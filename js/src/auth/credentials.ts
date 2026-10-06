// SPDX-License-Identifier: MIT
// Credential providers implementing the LWS authentication suites.
import { TokenType } from "../constants.js";
import { signJwt } from "../crypto/jwt.js";
import { algorithmOfKey, didKeyFromJwk, type SigningAlgorithm, type SigningKeyPair } from "../crypto/keys.js";
import { base64UrlEncodeText } from "../util/base64.js";
import type { AuthorizationServerMetadata } from "./oauth.js";

/** What a credential provider learns about the token request. */
export interface CredentialContext {
  /** Authorization server issuer (`as_uri`); the audience of the credential. */
  readonly issuer: string;
  /** Realm (storage) the access token will be issued for. */
  readonly realm: string;
  readonly metadata: AuthorizationServerMetadata;
  readonly signal?: AbortSignal | undefined;
}

/** Produces authentication credentials (subject tokens) for token exchange. */
export interface CredentialProvider {
  /** The `subject_token_type` URI of the suite. */
  readonly tokenType: string;
  /** Return a subject token for the given authorization server. */
  getSubjectToken(context: CredentialContext): string | Promise<string>;
}

type Supplier = string | ((context: CredentialContext) => string | Promise<string>);

const supply = async (s: Supplier, context: CredentialContext): Promise<string> =>
  typeof s === "function" ? s(context) : s;

/**
 * OpenID Connect suite (lws10-authn-openid): presents an ID Token. Obtain the
 * token with your OIDC library; pass a callback to refresh it on demand.
 */
export class OpenIdCredentials implements CredentialProvider {
  readonly tokenType = TokenType.ID_TOKEN;
  readonly #idToken: Supplier;

  constructor(idToken: Supplier) {
    this.#idToken = idToken;
  }

  getSubjectToken(context: CredentialContext): Promise<string> {
    return supply(this.#idToken, context);
  }
}

/**
 * SAML 2.0 suite (lws10-authn-saml): presents a SAML assertion, base64url
 * encoded as required by RFC 8693. Raw XML (starting with `<`) is encoded
 * automatically.
 */
export class SamlCredentials implements CredentialProvider {
  readonly tokenType = TokenType.SAML2;
  readonly #assertion: Supplier;

  constructor(assertion: Supplier) {
    this.#assertion = assertion;
  }

  /** base64url-encode a SAML assertion XML document. */
  static encodeAssertion(xml: string): string {
    return base64UrlEncodeText(xml);
  }

  async getSubjectToken(context: CredentialContext): Promise<string> {
    const value = (await supply(this.#assertion, context)).trim();
    return value.startsWith("<") ? SamlCredentials.encodeAssertion(value) : value;
  }
}

/** Options of {@link SelfSignedCredentials}. */
export interface SelfSignedOptions {
  /** Token lifetime in seconds (default 300). */
  lifetimeSeconds?: number;
  /** Clock in epoch milliseconds (testing). */
  clock?: () => number;
}

function randomId(): string {
  const c = globalThis.crypto;
  if (typeof c.randomUUID === "function") return c.randomUUID();
  const b = c.getRandomValues(new Uint8Array(16));
  b[6] = (b[6]! & 0x0f) | 0x40;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/**
 * Self-signed identity suite (lws10-authn-ssi-cid, also covering did:key
 * subjects): signs a short-lived JWT with `sub = iss = client_id = agent` and
 * `aud = [authorization server]`.
 */
export class SelfSignedCredentials implements CredentialProvider {
  readonly tokenType = TokenType.JWT;
  /** The agent URI (`sub`, `iss`, `client_id`). */
  readonly agent: string;
  /** The JWT `kid` header. */
  readonly kid: string;
  /** `ES256` or `EdDSA`. */
  readonly algorithm: SigningAlgorithm;
  readonly #privateKey: CryptoKey;
  readonly #lifetime: number;
  readonly #clock: () => number;
  readonly #cache = new Map<string, { token: string; exp: number }>();

  private constructor(agent: string, kid: string, algorithm: SigningAlgorithm, privateKey: CryptoKey, options: SelfSignedOptions) {
    this.agent = agent;
    this.kid = kid;
    this.algorithm = algorithm;
    this.#privateKey = privateKey;
    this.#lifetime = options.lifetimeSeconds ?? 300;
    this.#clock = options.clock ?? Date.now;
  }

  /**
   * An agent identified by an HTTPS URI (or DID) whose controlled identifier
   * document lists the key under `kid`.
   */
  static forAgent(agent: string, key: SigningKeyPair | CryptoKey, kid: string, options: SelfSignedOptions = {}): SelfSignedCredentials {
    const privateKey = "privateKey" in key ? key.privateKey : key;
    const algorithm = "algorithm" in key && typeof key.algorithm === "string" ? key.algorithm : algorithmOfKey(privateKey);
    return new SelfSignedCredentials(agent, kid, algorithm, privateKey, options);
  }

  /** An agent identified by the did:key derived from the key pair (kid = `did:key:z…#z…`). */
  static didKey(key: SigningKeyPair, options: SelfSignedOptions = {}): SelfSignedCredentials {
    const { did, kid } = didKeyFromJwk(key.publicJwk);
    return new SelfSignedCredentials(did, kid, key.algorithm, key.privateKey, options);
  }

  /** Sign a fresh credential for `audience` (an authorization server issuer). */
  async createToken(audience: string): Promise<string> {
    const iat = Math.floor(this.#clock() / 1000);
    const claims = {
      sub: this.agent,
      iss: this.agent,
      client_id: this.agent,
      aud: [audience],
      iat,
      exp: iat + this.#lifetime,
      jti: randomId(),
    };
    return signJwt({ typ: "JWT", kid: this.kid }, claims, { algorithm: this.algorithm, privateKey: this.#privateKey });
  }

  async getSubjectToken(context: CredentialContext): Promise<string> {
    const now = Math.floor(this.#clock() / 1000);
    const cached = this.#cache.get(context.issuer);
    if (cached && cached.exp - 60 > now) return cached.token;
    const token = await this.createToken(context.issuer);
    this.#cache.set(context.issuer, { token, exp: now + this.#lifetime });
    return token;
  }
}
