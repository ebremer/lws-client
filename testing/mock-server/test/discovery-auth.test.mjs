// SPDX-License-Identifier: MIT
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import http from "node:http";
import { after, before, describe, test } from "node:test";
import { signJwt } from "../lib/crypto.mjs";
import { authed, decodePayload, didKeyAgent, exchange, JWT_TYPE, launch, login } from "./helpers.mjs";

let server;
let base;

before(async () => {
  server = await launch();
  base = server.url;
});
after(() => server.close());

describe("storage description", () => {
  test("GET / returns an application/lws+cid storage description", async () => {
    const r = await fetch(`${base}/`);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("content-type"), "application/lws+cid");
    assert.ok(r.headers.get("etag"));
    const d = await r.json();
    assert.deepEqual(d["@context"], ["https://www.w3.org/ns/cid/v1", "https://www.w3.org/ns/lws/v1"]);
    assert.equal(d.id, `${base}/`);
    assert.equal(d.type, "Storage");
    const byType = Object.fromEntries(d.service.map((s) => [s.type, s]));
    assert.equal(byType.StorageRoot.serviceEndpoint, `${base}/root/`);
    assert.equal(byType.NotificationService.serviceEndpoint, `${base}/notifications/`);
    assert.deepEqual(byType.NotificationService.subscriptionType, ["WebhookSubscription"]);
    assert.equal(byType.AccessRequestService.serviceEndpoint, `${base}/access/requests/`);
    assert.deepEqual(byType.AccessGrantService.conformsTo, ["https://www.w3.org/ns/lws#AccessProfile"]);
    assert.equal(byType.TypeIndexService.serviceEndpoint, `${base}/types/index`);
    assert.equal(byType.TypeSearchService.serviceEndpoint, `${base}/types/search`);
    assert.equal(d.verificationMethod[0].id, `${base}/#webhook-key`);
    assert.equal(d.verificationMethod[0].publicKeyJwk.crv, "P-256");
    assert.deepEqual(d.authentication, [`${base}/#webhook-key`]);
  });

  test("HEAD, conditional GET and content negotiation", async () => {
    const head = await fetch(`${base}/`, { method: "HEAD" });
    assert.equal(head.status, 200);
    assert.ok(Number(head.headers.get("content-length")) > 0);
    assert.equal((await head.arrayBuffer()).byteLength, 0);
    const etag = head.headers.get("etag");
    assert.equal((await fetch(`${base}/`, { headers: { "if-none-match": etag } })).status, 304);
    const ld = await fetch(`${base}/`, { headers: { accept: "application/ld+json" } });
    assert.equal(ld.headers.get("content-type"), "application/ld+json");
    const any = await fetch(`${base}/`, { headers: { accept: "*/*" } });
    assert.equal(any.headers.get("content-type"), "application/lws+cid");
  });

  test("authorization server metadata and JWKS", async () => {
    const m = await (await fetch(`${base}/.well-known/lws-configuration`)).json();
    assert.equal(m.issuer, base);
    assert.equal(m.token_endpoint, `${base}/oauth/token`);
    assert.deepEqual(m.grant_types_supported, ["urn:ietf:params:oauth:grant-type:token-exchange"]);
    assert.ok(m.subject_token_types_supported.includes(JWT_TYPE));
    assert.ok(m.subject_token_types_supported.includes("urn:ietf:params:oauth:token-type:id_token"));
    assert.ok(m.subject_token_types_supported.includes("urn:ietf:params:oauth:token-type:saml2"));
    assert.ok(m.subject_identifier_types_supported.includes("did:key"));
    const jwks = await (await fetch(m.jwks_uri)).json();
    assert.equal(jwks.keys[0].kty, "EC");
    assert.equal(jwks.keys[0].alg, "ES256");
  });
});

describe("401 challenge", () => {
  for (const path of ["/root/", "/notifications/", "/access/requests/", "/types/index"]) {
    test(`unauthenticated ${path} gets the LWS Bearer challenge`, async () => {
      const r = await fetch(`${base}${path}`);
      assert.equal(r.status, 401);
      assert.equal(r.headers.get("www-authenticate"), `Bearer as_uri="${base}", realm="${base}/", error="invalid_token"`);
      assert.equal(r.headers.get("link"), `<${base}/>; rel="https://www.w3.org/ns/lws#storage"`);
      assert.equal(r.headers.get("content-type"), "application/problem+json");
      assert.equal((await r.json()).status, 401);
    });
  }

  test("invalid tokens are rejected", async () => {
    for (const token of ["garbage", "a.b.c", `${signJwt({ alg: "ES256", typ: "at+jwt", kid: "as-key-1" }, { sub: "x" }, generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey)}`]) {
      const r = await authed(token)(`${base}/root/`);
      assert.equal(r.status, 401, token);
    }
    const { token } = await login(base);
    const [h, p, s] = token.split(".");
    const tampered = Buffer.from(JSON.stringify({ ...decodePayload(token), sub: "https://evil.example/" })).toString("base64url");
    assert.equal((await authed(`${h}.${tampered}.${s}`)(`${base}/root/`)).status, 401);
    const basic = await fetch(`${base}/root/`, { headers: { authorization: "Basic dXNlcjpwYXNz" } });
    assert.equal(basic.status, 401);
  });
});

describe("token exchange", () => {
  test("did:key (P-256) self-signed credential yields an RFC 9068 access token", async () => {
    const agent = didKeyAgent("P-256");
    const { status, body, headers } = await exchange(base, agent.credential(base));
    assert.equal(status, 200, JSON.stringify(body));
    assert.equal(headers.get("cache-control"), "no-store");
    assert.equal(body.token_type, "Bearer");
    assert.equal(body.expires_in, 300);
    assert.equal(body.issued_token_type, "urn:ietf:params:oauth:token-type:access_token");
    const [header] = body.access_token.split(".");
    assert.equal(JSON.parse(Buffer.from(header, "base64url")).typ, "at+jwt");
    const claims = decodePayload(body.access_token);
    assert.equal(claims.iss, base);
    assert.equal(claims.sub, agent.did);
    assert.equal(claims.client_id, agent.did);
    assert.equal(claims.aud, `${base}/`);
    assert.equal(claims.exp - claims.iat, 300);
    assert.ok(claims.jti);
    const r = await authed(body.access_token)(`${base}/root/`);
    assert.equal(r.status, 200);
  });

  test("did:key (Ed25519) self-signed credential is accepted", async () => {
    const agent = didKeyAgent("Ed25519");
    assert.ok(agent.did.startsWith("did:key:z6Mk"));
    const { status, body } = await exchange(base, agent.credential(base));
    assert.equal(status, 200, JSON.stringify(body));
  });

  test("audience may be the issuer with a trailing slash and kid may be omitted", async () => {
    const agent = didKeyAgent();
    const iat = Math.floor(Date.now() / 1000);
    const token = signJwt({ alg: "ES256", typ: "JWT" }, { sub: agent.did, iss: agent.did, client_id: agent.did, aud: `${base}/`, iat, exp: iat + 60 }, agent.privateKey);
    assert.equal((await exchange(base, token)).status, 200);
  });

  const rejections = [
    ["alg none", (a) => `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${Buffer.from(JSON.stringify({ sub: a.did, iss: a.did, client_id: a.did, aud: [base] })).toString("base64url")}.`],
    ["sub differs from iss", (a) => a.credential(base, { iss: "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169" })],
    ["client_id differs", (a) => a.credential(base, { client_id: "https://app.example/" })],
    ["wrong audience", (a) => a.credential("https://other.example")],
    ["expired", (a) => a.credential(base, { iat: 1000, exp: 2000 })],
    ["missing iat", (a) => a.credential(base, { iat: undefined })],
    ["kid of another did", (a) => a.credential(base, {}, { kid: "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169#x" })],
    ["signed with another key", (a) => didKeyAgent().credential(base, { sub: a.did, iss: a.did, client_id: a.did }, { kid: a.kid })],
    ["not a JWT", () => "not-a-jwt"],
  ];
  for (const [name, make] of rejections) {
    test(`rejects self-signed credential: ${name}`, async () => {
      const { status, body } = await exchange(base, make(didKeyAgent()));
      assert.equal(status, 400);
      assert.equal(body.error, "invalid_request", JSON.stringify(body));
    });
  }

  test("request validation follows RFC 6749 / RFC 8693 error codes", async () => {
    const token = didKeyAgent().credential(base);
    assert.equal((await exchange(base, token, { resource: null })).body.error, "invalid_request");
    assert.equal((await exchange(base, token, { resource: "https://storage.example/" })).body.error, "invalid_target");
    assert.equal((await exchange(base, token, { resource: base })).body.error, "invalid_target");
    assert.equal((await exchange(base, token, { extra: { grant_type: "client_credentials" } })).body.error, "unsupported_grant_type");
    assert.equal((await exchange(base, token, { type: "urn:example:unknown" })).body.error, "invalid_request");
    assert.equal((await exchange(base, null)).body.error, "invalid_request");
    const json = await fetch(`${base}/oauth/token`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    assert.equal(json.status, 400);
    assert.equal((await json.json()).error, "invalid_request");
    const repeated = await fetch(`${base}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&resource=${encodeURIComponent(`${base}/`)}&resource=x&subject_token=${token}&subject_token_type=${encodeURIComponent(JWT_TYPE)}`,
    });
    assert.equal((await repeated.json()).error, "invalid_request");
    assert.equal((await fetch(`${base}/oauth/token`)).status, 405);
  });

  test("OpenID Connect ID tokens are accepted in test mode (azp required)", async () => {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const idToken = (claims) => signJwt({ alg: "ES256", typ: "JWT", kid: "op-key" }, { iss: "https://openid.example", aud: ["https://client.example/17da1b", base], iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300, ...claims }, privateKey);
    const ok = await exchange(base, idToken({ sub: "https://id.example/end-user", azp: "https://client.example/17da1b" }), { type: "urn:ietf:params:oauth:token-type:id_token" });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    const claims = decodePayload(ok.body.access_token);
    assert.equal(claims.sub, "https://id.example/end-user");
    assert.equal(claims.client_id, "https://client.example/17da1b");
    const noAzp = await exchange(base, idToken({ sub: "https://id.example/end-user" }), { type: "urn:ietf:params:oauth:token-type:id_token" });
    assert.equal(noAzp.status, 400);
  });

  test("SAML 2.0 assertions are accepted in test mode (base64url)", async () => {
    const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion><saml:Issuer>https://idp.example</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">https://id.example/end-user</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="https://app.example/SAML"/></saml:SubjectConfirmation></saml:Subject></saml:Assertion></samlp:Response>`;
    const r = await exchange(base, Buffer.from(xml).toString("base64url"), { type: "urn:ietf:params:oauth:token-type:saml2" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const claims = decodePayload(r.body.access_token);
    assert.equal(claims.sub, "https://id.example/end-user");
    assert.equal(claims.client_id, "https://app.example/SAML");
    const bad = await exchange(base, Buffer.from("<x/>").toString("base64url"), { type: "urn:ietf:params:oauth:token-type:saml2" });
    assert.equal(bad.status, 400);
  });

  test("HTTP(S) subjects are verified against their controlled identifier document", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    let docServer;
    await new Promise((resolve) => {
      docServer = http.createServer((req, res) => {
        const id = `http://127.0.0.1:${docServer.address().port}/agent`;
        if (req.url !== "/agent") return res.writeHead(404).end();
        res.writeHead(200, { "content-type": "application/ld+json" }).end(
          JSON.stringify({
            "@context": ["https://www.w3.org/ns/cid/v1"],
            id,
            authentication: [{ id: `${id}#c1f52577`, type: "JsonWebKey", controller: id, publicKeyJwk: { ...publicKey.export({ format: "jwk" }), kid: "c1f52577", alg: "ES256" } }],
          }),
        );
      });
      docServer.listen(0, "127.0.0.1", resolve);
    });
    try {
      const agentId = `http://127.0.0.1:${docServer.address().port}/agent`;
      const mint = (kid, key = privateKey) => {
        const iat = Math.floor(Date.now() / 1000);
        return signJwt({ alg: "ES256", typ: "JWT", kid }, { sub: agentId, iss: agentId, client_id: agentId, aud: [base], iat, exp: iat + 300 }, key);
      };
      for (const kid of ["c1f52577", `${agentId}#c1f52577`, "#c1f52577"]) {
        const r = await exchange(base, mint(kid));
        assert.equal(r.status, 200, `${kid}: ${JSON.stringify(r.body)}`);
        assert.equal(decodePayload(r.body.access_token).sub, agentId);
      }
      assert.equal((await exchange(base, mint("unknown-kid"))).status, 400);
      assert.equal((await exchange(base, mint("c1f52577", generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey))).status, 400);
    } finally {
      await new Promise((resolve) => docServer.close(resolve));
    }
  });

  test("controlled identifier documents hosted in this storage can be used", async () => {
    const { token } = await login(base);
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const created = await authed(token)(`${base}/root/`, { method: "POST", headers: { "content-type": "application/ld+json", slug: `agent-${randomUUID()}` }, body: "{}" });
    const agentId = created.headers.get("location");
    const doc = {
      "@context": ["https://www.w3.org/ns/cid/v1"],
      id: agentId,
      verificationMethod: [{ id: `${agentId}#k1`, type: "JsonWebKey", controller: agentId, publicKeyJwk: publicKey.export({ format: "jwk" }) }],
      authentication: ["#k1"],
    };
    const put = await authed(token)(agentId, { method: "PUT", headers: { "content-type": "application/ld+json" }, body: JSON.stringify(doc) });
    assert.equal(put.status, 204);
    const iat = Math.floor(Date.now() / 1000);
    const credential = signJwt({ alg: "EdDSA", typ: "JWT", kid: `${agentId}#k1` }, { sub: agentId, iss: agentId, client_id: agentId, aud: [base], iat, exp: iat + 300 }, privateKey);
    const r = await exchange(base, credential);
    assert.equal(r.status, 200, JSON.stringify(r.body));
  });
});

describe("--no-auth", () => {
  test("everything is accessible anonymously", async () => {
    const open = await launch({ auth: false });
    try {
      const r = await fetch(`${open.url}/root/`);
      assert.equal(r.status, 200);
      const created = await fetch(`${open.url}/root/`, { method: "POST", headers: { "content-type": "text/plain" }, body: "hi" });
      assert.equal(created.status, 201);
    } finally {
      await open.close();
    }
  });
});
