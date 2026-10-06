// SPDX-License-Identifier: MIT
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  didKeyFromJwk,
  jwkFromDidKey,
  verifyJwt,
  decodeJwt,
  generateKeyPair,
  importKeyPair,
  exportPrivateJwk,
  SelfSignedCredentials,
  OpenIdCredentials,
  SamlCredentials,
  controlledIdentifierDocument,
  base58btcDecode,
  base58btcEncode,
  TokenType,
  type CredentialContext,
} from "../src/index.js";
import { fixture } from "./support/fixtures.js";

const ctx = (issuer: string): CredentialContext => ({
  issuer,
  realm: "https://storage.example/",
  metadata: { issuer, token_endpoint: `${issuer}/token` },
});

describe("did:key — conformance/fixtures/did-key.json", () => {
  const { vectors } = fixture("did-key.json");
  for (const v of vectors) {
    test(v.name, () => {
      const { did, kid } = didKeyFromJwk(v.publicJwk);
      assert.equal(did, v.did);
      assert.equal(kid, v.kid);
      const jwk = jwkFromDidKey(v.did);
      assert.equal(jwk.x, v.publicJwk.x);
      if (v.publicJwk.y) assert.equal(jwk.y, v.publicJwk.y);
    });
  }

  test("base58btc round trip with leading zeros", () => {
    const bytes = new Uint8Array([0, 0, 1, 2, 255]);
    assert.deepEqual(base58btcDecode(base58btcEncode(bytes)), bytes);
  });
});

describe("JWT — conformance/fixtures/jwt.json", () => {
  const { vectors } = fixture("jwt.json");
  for (const v of vectors) {
    test(v.name, async () => {
      const decoded = await verifyJwt(v.jwt, v.publicJwk);
      assert.deepEqual(decoded.payload, v.claims);
      assert.deepEqual(decoded.header, v.header);
      // the kid of the did:key vectors identifies the same key
      assert.deepEqual(jwkFromDidKey(v.header.kid).x, v.publicJwk.x);
    });
  }

  test("tampered tokens are rejected", async () => {
    const v = vectors[0];
    const [h, p, s] = v.jwt.split(".");
    const forged = `${h}.${Buffer.from(JSON.stringify({ ...v.claims, sub: "did:key:evil" })).toString("base64url")}.${s}`;
    await assert.rejects(verifyJwt(forged, v.publicJwk));
    const none = `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${p}.`;
    await assert.rejects(verifyJwt(none, v.publicJwk));
  });
});

describe("SelfSignedCredentials", () => {
  for (const alg of ["ES256", "EdDSA"] as const) {
    test(`did:key with ${alg}`, async () => {
      const pair = await generateKeyPair(alg);
      const creds = SelfSignedCredentials.didKey(pair, { clock: () => 1_790_000_000_000 });
      assert.equal(creds.tokenType, TokenType.JWT);
      assert.ok(creds.agent.startsWith(alg === "ES256" ? "did:key:zDn" : "did:key:z6Mk"));
      const token = await creds.getSubjectToken(ctx("https://as.example"));
      const { header, payload } = await verifyJwt(token, pair.publicJwk);
      assert.equal(header["alg"], alg);
      assert.equal(header["typ"], "JWT");
      assert.equal(header["kid"], creds.kid);
      assert.equal(payload["sub"], creds.agent);
      assert.equal(payload["iss"], creds.agent);
      assert.equal(payload["client_id"], creds.agent);
      assert.deepEqual(payload["aud"], ["https://as.example"]);
      assert.equal(payload["iat"], 1_790_000_000);
      assert.equal(payload["exp"], 1_790_000_300);
      assert.match(String(payload["jti"]), /^[0-9a-f-]{36}$/);
      // cached per audience
      assert.equal(await creds.getSubjectToken(ctx("https://as.example")), token);
      assert.notEqual(await creds.getSubjectToken(ctx("https://other.example")), token);
    });
  }

  test("forAgent with an imported fixture key and CID document", async () => {
    const keys = fixture("keys/p256.json");
    const pair = await importKeyPair(keys.privateJwk);
    const creds = SelfSignedCredentials.forAgent("https://id.example/agent", pair, "key-1");
    const token = await creds.createToken("https://as.example");
    const { header, payload } = await verifyJwt(token, keys.publicJwk);
    assert.equal(header["kid"], "key-1");
    assert.equal(payload["sub"], "https://id.example/agent");
    const doc = controlledIdentifierDocument("https://id.example/agent", pair.publicJwk, "key-1") as any;
    assert.equal(doc.id, "https://id.example/agent");
    assert.equal(doc.authentication[0].id, "https://id.example/agent#key-1");
    assert.equal(doc.authentication[0].publicKeyJwk.kid, "key-1");
    assert.equal(doc.authentication[0].publicKeyJwk.d, undefined);
  });

  test("extractable keys export as JWK", async () => {
    const pair = await generateKeyPair("ES256", { extractable: true });
    const jwk = await exportPrivateJwk(pair);
    assert.ok(jwk.d);
    const again = await importKeyPair(jwk);
    assert.deepEqual(didKeyFromJwk(again.publicJwk), didKeyFromJwk(pair.publicJwk));
  });
});

describe("OpenID / SAML credentials", () => {
  test("OpenID passes the ID token (static or supplier)", async () => {
    assert.equal(await new OpenIdCredentials("id.tok.en").getSubjectToken(ctx("https://as")), "id.tok.en");
    const supplied = new OpenIdCredentials((c) => `for-${c.issuer}`);
    assert.equal(await supplied.getSubjectToken(ctx("https://as")), "for-https://as");
    assert.equal(supplied.tokenType, TokenType.ID_TOKEN);
  });

  test("SAML encodes raw XML as base64url", async () => {
    const xml = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">?</saml:Assertion>';
    const creds = new SamlCredentials(xml);
    const token = await creds.getSubjectToken(ctx("https://as"));
    assert.equal(Buffer.from(token, "base64url").toString(), xml);
    assert.doesNotMatch(token, /[+/=]/);
    assert.equal(await new SamlCredentials("already-encoded").getSubjectToken(ctx("https://as")), "already-encoded");
    assert.equal(creds.tokenType, TokenType.SAML2);
  });

  test("decodeJwt without verification", () => {
    const fx = fixture("responses/oauth.json");
    assert.equal(decodeJwt(fx.tokenResponseNoExpiry.body.access_token).payload["exp"], fx.tokenResponseNoExpiry.expectedExp);
  });
});
