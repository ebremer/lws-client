// SPDX-License-Identifier: MIT
// Authorization server (lws10-core "Authorization": RFC 8414 metadata + RFC 8693 token exchange)
// and access-token validation for the storage server.

import { generateKeyPairSync, randomUUID } from "node:crypto";
import { decodeJwt, didKeyToPublicJwk, publicKeyFromJwk, signJwt, verifyJwtSignature } from "./crypto.mjs";
import { asArray, HttpError, isObject, MEDIA, mediaTypeOf, readBody, REL_STORAGE, send } from "./util.mjs";

export const TOKEN_TYPES = Object.freeze({
  JWT: "urn:ietf:params:oauth:token-type:jwt",
  ID_TOKEN: "urn:ietf:params:oauth:token-type:id_token",
  SAML2: "urn:ietf:params:oauth:token-type:saml2",
  ACCESS_TOKEN: "urn:ietf:params:oauth:token-type:access_token",
});
export const GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

const ACCESS_TOKEN_LIFETIME = 300;
const CLOCK_SKEW = 60;
const AS_KID = "as-key-1";

class OAuthError extends Error {
  constructor(error, description, status = 400) {
    super(description);
    this.error = error;
    this.status = status;
  }
}

const now = () => Math.floor(Date.now() / 1000);

function checkTimes(claims, { requireExp, requireIat }) {
  const t = now();
  if (claims.exp === undefined) {
    if (requireExp) throw new OAuthError("invalid_request", "subject token has no exp claim");
  } else if (typeof claims.exp !== "number" || claims.exp + CLOCK_SKEW <= t) {
    throw new OAuthError("invalid_request", "subject token is expired");
  }
  if (claims.iat === undefined) {
    if (requireIat) throw new OAuthError("invalid_request", "subject token has no iat claim");
  } else if (typeof claims.iat !== "number" || claims.iat - CLOCK_SKEW > t) {
    throw new OAuthError("invalid_request", "subject token iat is in the future");
  }
  if (claims.nbf !== undefined && (typeof claims.nbf !== "number" || claims.nbf - CLOCK_SKEW > t)) {
    throw new OAuthError("invalid_request", "subject token is not yet valid");
  }
}

/** Selects the verification method a JWT `kid` refers to among the CID's authentication methods (CID 1.0 §3.3). */
export function findAuthenticationMethod(doc, kid) {
  const base = doc.id;
  const abs = (id) => {
    try {
      return new URL(id, base).href;
    } catch {
      return null;
    }
  };
  const methods = new Map();
  for (const vm of asArray(doc.verificationMethod)) if (isObject(vm) && typeof vm.id === "string") methods.set(abs(vm.id), vm);
  const candidates = [];
  for (const a of asArray(doc.authentication)) {
    if (typeof a === "string") {
      const vm = methods.get(abs(a));
      if (vm) candidates.push(vm);
    } else if (isObject(a) && typeof a.id === "string") {
      candidates.push(a);
    }
  }
  if (candidates.length === 0) throw new OAuthError("invalid_request", "controlled identifier document has no authentication verification methods");
  let selected;
  if (kid !== undefined) {
    if (typeof kid !== "string") throw new OAuthError("invalid_request", "kid must be a string");
    selected = candidates.find((vm) => {
      const id = abs(vm.id);
      if (id && id === abs(kid)) return true;
      if (id && new URL(id).hash === `#${kid}`) return true;
      return isObject(vm.publicKeyJwk) && vm.publicKeyJwk.kid === kid;
    });
  } else if (candidates.length === 1) {
    selected = candidates[0];
  }
  if (!selected) throw new OAuthError("invalid_request", `no authentication verification method matches kid ${kid ?? "(none)"}`);
  if (!isObject(selected.publicKeyJwk)) throw new OAuthError("invalid_request", "verification method has no publicKeyJwk");
  return selected;
}

export function createAuth(app) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const publicJwk = { ...publicKey.export({ format: "jwk" }), kid: AS_KID, alg: "ES256", use: "sig" };

  function metadata() {
    return {
      issuer: app.issuer,
      token_endpoint: `${app.base}/oauth/token`,
      jwks_uri: `${app.base}/oauth/jwks`,
      grant_types_supported: [GRANT_TOKEN_EXCHANGE],
      response_types_supported: ["token"],
      token_endpoint_auth_methods_supported: ["none"],
      claims_supported: ["sub", "iss", "client_id", "aud", "exp", "iat", "jti"],
      subject_token_types_supported: [TOKEN_TYPES.JWT, TOKEN_TYPES.ID_TOKEN, TOKEN_TYPES.SAML2],
      subject_identifier_types_supported: ["https", "http", "did:key"],
    };
  }

  function handleMetadata(req, res) {
    if (req.method !== "GET" && req.method !== "HEAD") throw new HttpError(405, undefined, { headers: { Allow: "GET, HEAD" } });
    send(req, res, 200, { "Content-Type": MEDIA.JSON, "Cache-Control": "public, max-age=60" }, metadata());
  }

  function handleJwks(req, res) {
    if (req.method !== "GET" && req.method !== "HEAD") throw new HttpError(405, undefined, { headers: { Allow: "GET, HEAD" } });
    send(req, res, 200, { "Content-Type": "application/jwk-set+json", "Cache-Control": "public, max-age=60" }, { keys: [publicJwk] });
  }

  async function fetchControlledIdentifier(subject) {
    const docUrl = subject.split("#")[0];
    let doc;
    if (docUrl.startsWith(`${app.base}/`)) {
      // Documents hosted in this storage are read directly (they would otherwise require a token).
      const resource = app.store.resolve(new URL(docUrl).pathname);
      if (!resource || resource.isContainer) throw new OAuthError("invalid_request", `cannot dereference subject ${subject}`);
      try {
        doc = JSON.parse(resource.body.toString("utf8"));
      } catch {
        throw new OAuthError("invalid_request", "subject document is not JSON");
      }
    } else {
      let response;
      try {
        response = await fetch(docUrl, {
          headers: { accept: "application/did+ld+json, application/ld+json, application/json;q=0.9, */*;q=0.1" },
          signal: AbortSignal.timeout(5000),
        });
      } catch (e) {
        throw new OAuthError("invalid_request", `cannot dereference subject ${subject}: ${e.message}`);
      }
      if (!response.ok) throw new OAuthError("invalid_request", `cannot dereference subject ${subject}: HTTP ${response.status}`);
      try {
        doc = await response.json();
      } catch {
        throw new OAuthError("invalid_request", "subject document is not JSON");
      }
    }
    if (!isObject(doc) || doc.id !== subject) {
      throw new OAuthError("invalid_request", "controlled identifier document id does not equal the subject identifier");
    }
    return doc;
  }

  // lws10-authn-ssi-cid (also covers did:key subjects, the subsumed lws10-authn-ssi-did-key suite)
  async function validateSelfSigned(token) {
    let jwt;
    try {
      jwt = decodeJwt(token);
    } catch {
      throw new OAuthError("invalid_request", "subject_token is not a well-formed JWT");
    }
    const { header, payload } = jwt;
    if (!header.alg || header.alg === "none") throw new OAuthError("invalid_request", 'subject token must not use alg "none"');
    if (!["ES256", "ES384", "EdDSA", "Ed25519"].includes(header.alg)) throw new OAuthError("invalid_request", `unsupported alg ${header.alg}`);
    const { sub, iss, client_id: clientId } = payload;
    if (typeof sub !== "string" || !sub) throw new OAuthError("invalid_request", "subject token has no sub claim");
    if (iss !== sub || clientId !== sub) throw new OAuthError("invalid_request", "sub, iss and client_id must all be the same URI");
    const aud = asArray(payload.aud);
    if (!aud.some((a) => a === app.issuer || a === `${app.issuer}/`)) {
      throw new OAuthError("invalid_request", `subject token audience must include ${app.issuer}`);
    }
    checkTimes(payload, { requireExp: true, requireIat: true });

    let key;
    if (sub.startsWith("did:key:")) {
      if (header.kid !== undefined && header.kid !== sub && !String(header.kid).startsWith(`${sub}#`)) {
        throw new OAuthError("invalid_request", "kid does not identify a key of the did:key subject");
      }
      try {
        key = publicKeyFromJwk(didKeyToPublicJwk(sub));
      } catch (e) {
        throw new OAuthError("invalid_request", `invalid did:key subject: ${e.message}`);
      }
    } else if (/^https?:\/\//i.test(sub)) {
      const doc = await fetchControlledIdentifier(sub);
      const vm = findAuthenticationMethod(doc, header.kid);
      try {
        key = publicKeyFromJwk(vm.publicKeyJwk);
      } catch (e) {
        throw new OAuthError("invalid_request", `invalid publicKeyJwk: ${e.message}`);
      }
    } else {
      throw new OAuthError("invalid_request", "unsupported subject identifier type");
    }
    let valid = false;
    try {
      valid = verifyJwtSignature(jwt, key);
    } catch {
      valid = false;
    }
    if (!valid) throw new OAuthError("invalid_request", "subject token signature verification failed");
    return { sub, clientId: sub };
  }

  // lws10-authn-openid — TEST MODE: the ID token signature is NOT verified.
  function validateIdToken(token) {
    let jwt;
    try {
      jwt = decodeJwt(token);
    } catch {
      throw new OAuthError("invalid_request", "subject_token is not a well-formed JWT");
    }
    if (!jwt.header.alg || jwt.header.alg === "none") throw new OAuthError("invalid_request", 'ID token must not use alg "none"');
    const { sub, iss } = jwt.payload;
    const clientId = jwt.payload.azp ?? jwt.payload.client_id;
    if (typeof sub !== "string" || typeof iss !== "string") throw new OAuthError("invalid_request", "ID token requires sub and iss");
    if (typeof clientId !== "string") throw new OAuthError("invalid_request", "ID token requires an azp claim");
    checkTimes(jwt.payload, { requireExp: false, requireIat: false });
    return { sub, clientId };
  }

  // lws10-authn-saml — TEST MODE: the assertion signature is NOT verified.
  function validateSaml(token) {
    let xml;
    try {
      xml = Buffer.from(token, /[+/=]/.test(token) ? "base64" : "base64url").toString("utf8");
    } catch {
      throw new OAuthError("invalid_request", "SAML subject_token must be base64url-encoded");
    }
    const nameId = /<(?:[\w-]+:)?NameID\b[^>]*>\s*([^<]+?)\s*<\/(?:[\w-]+:)?NameID>/.exec(xml)?.[1];
    if (!nameId) throw new OAuthError("invalid_request", "SAML assertion has no NameID");
    const recipient = /\bRecipient="([^"]+)"/.exec(xml)?.[1];
    const issuer = /<(?:[\w-]+:)?Issuer\b[^>]*>\s*([^<]+?)\s*<\/(?:[\w-]+:)?Issuer>/.exec(xml)?.[1];
    const notOnOrAfter = /<(?:[\w-]+:)?Conditions\b[^>]*\bNotOnOrAfter="([^"]+)"/.exec(xml)?.[1];
    if (notOnOrAfter && Date.parse(notOnOrAfter) + CLOCK_SKEW * 1000 <= Date.now()) {
      throw new OAuthError("invalid_request", "SAML assertion is expired");
    }
    return { sub: nameId, clientId: recipient ?? issuer ?? "urn:lws:mock:saml-client" };
  }

  async function handleToken(req, res) {
    if (req.method !== "POST") throw new HttpError(405, undefined, { headers: { Allow: "POST" } });
    const headers = { "Content-Type": MEDIA.JSON, "Cache-Control": "no-store", Pragma: "no-cache" };
    try {
      if (mediaTypeOf(req.headers["content-type"]) !== MEDIA.FORM) {
        throw new OAuthError("invalid_request", "Content-Type must be application/x-www-form-urlencoded");
      }
      const params = new URLSearchParams((await readBody(req, 256 * 1024)).toString("utf8"));
      for (const name of new Set(params.keys())) {
        if (params.getAll(name).length > 1) throw new OAuthError("invalid_request", `parameter ${name} is repeated`);
      }
      const grantType = params.get("grant_type");
      if (!grantType) throw new OAuthError("invalid_request", "grant_type is required");
      if (grantType !== GRANT_TOKEN_EXCHANGE) throw new OAuthError("unsupported_grant_type", `unsupported grant_type ${grantType}`);
      const resource = params.get("resource");
      if (!resource) throw new OAuthError("invalid_request", "resource is required");
      if (resource !== app.realm) throw new OAuthError("invalid_target", `resource ${resource} is not a storage known to this authorization server (expected ${app.realm})`);
      const subjectToken = params.get("subject_token");
      const subjectTokenType = params.get("subject_token_type");
      if (!subjectToken) throw new OAuthError("invalid_request", "subject_token is required");
      if (!subjectTokenType) throw new OAuthError("invalid_request", "subject_token_type is required");

      let subject;
      switch (subjectTokenType) {
        case TOKEN_TYPES.JWT:
          subject = await validateSelfSigned(subjectToken);
          break;
        case TOKEN_TYPES.ID_TOKEN:
          subject = validateIdToken(subjectToken);
          break;
        case TOKEN_TYPES.SAML2:
          subject = validateSaml(subjectToken);
          break;
        default:
          throw new OAuthError("invalid_request", `unsupported subject_token_type ${subjectTokenType}`);
      }
      const iat = now();
      const accessToken = signJwt(
        { alg: "ES256", typ: "at+jwt", kid: AS_KID },
        { iss: app.issuer, sub: subject.sub, client_id: subject.clientId, aud: resource, exp: iat + ACCESS_TOKEN_LIFETIME, iat, jti: randomUUID() },
        privateKey,
      );
      app.log?.(`issued access token for ${subject.sub}`);
      send(req, res, 200, headers, {
        access_token: accessToken,
        issued_token_type: TOKEN_TYPES.ACCESS_TOKEN,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_LIFETIME,
      });
    } catch (e) {
      if (!(e instanceof OAuthError)) throw e;
      app.log?.(`token exchange rejected: ${e.error}: ${e.message}`);
      send(req, res, e.status, headers, { error: e.error, error_description: e.message });
    }
  }

  function challengeHeaders() {
    return {
      "WWW-Authenticate": `Bearer as_uri="${app.issuer}", realm="${app.realm}", error="invalid_token"`,
      Link: `<${app.storageId}>; rel="${REL_STORAGE}"`,
    };
  }

  const unauthorized = (detail) => new HttpError(401, detail, { headers: challengeHeaders() });

  /** Validates the bearer access token of a storage request (lws10-core "Token Validation by a Storage Server"). */
  function authenticate(req) {
    const header = req.headers.authorization;
    if (!header) throw unauthorized("An access token is required");
    const m = /^Bearer[ \t]+([A-Za-z0-9\-._~+/]+=*)[ \t]*$/i.exec(header);
    if (!m) throw unauthorized("The Authorization header must use the Bearer scheme");
    let jwt;
    try {
      jwt = decodeJwt(m[1]);
    } catch {
      throw unauthorized("Malformed access token");
    }
    if (jwt.header.alg !== "ES256" || jwt.header.kid !== AS_KID) throw unauthorized("Access token was not issued by this authorization server");
    if (jwt.header.typ !== "at+jwt" && jwt.header.typ !== "application/at+jwt") throw unauthorized("Access token typ must be at+jwt");
    if (!verifyJwtSignature(jwt, publicKey)) throw unauthorized("Access token signature is invalid");
    const p = jwt.payload;
    if (p.iss !== app.issuer) throw unauthorized("Access token issuer is not trusted");
    const aud = asArray(p.aud);
    if (aud.length !== 1 || aud[0] !== app.realm) throw unauthorized("Access token audience does not identify this storage");
    const t = now();
    if (typeof p.exp !== "number" || p.exp + CLOCK_SKEW <= t) throw unauthorized("Access token is expired");
    if (p.nbf !== undefined && (typeof p.nbf !== "number" || p.nbf - CLOCK_SKEW > t)) throw unauthorized("Access token is not yet valid");
    if (typeof p.iat !== "number" || p.iat - CLOCK_SKEW > t) throw unauthorized("Access token iat is in the future");
    if (typeof p.sub !== "string") throw unauthorized("Access token has no subject");
    return { sub: p.sub, clientId: p.client_id ?? null };
  }

  return { handleMetadata, handleJwks, handleToken, authenticate, challengeHeaders, metadata, publicJwk };
}
