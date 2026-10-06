#!/usr/bin/env node
// SPDX-License-Identifier: MIT
//
// Generates the cryptographic conformance fixtures shared by every client:
//   - fixtures/keys/*.json            test-only key pairs (JWK, includes private "d")
//   - fixtures/did-key.json           did:key encoding vectors
//   - fixtures/jwt.json               self-signed JWTs (ES256, EdDSA) for signature interop checks
//   - fixtures/webhook/*.json         RFC 9421 signed webhook deliveries (valid and invalid)
//
// Keys are created once and then reused, so regenerating only changes ECDSA signatures
// (which are randomized) — every regenerated vector is still valid.
//
// Usage: node conformance/tools/generate-fixtures.mjs

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "fixtures");
mkdirSync(join(fixtures, "keys"), { recursive: true });
mkdirSync(join(fixtures, "webhook"), { recursive: true });

const write = (rel, value) =>
  writeFileSync(join(fixtures, rel), JSON.stringify(value, null, 2) + "\n");

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

function loadOrCreateKey(name, type, options) {
  const file = join(fixtures, "keys", `${name}.json`);
  if (existsSync(file)) return JSON.parse(readFileSync(file, "utf8"));
  const { privateKey } = generateKeyPairSync(type, options);
  const jwk = privateKey.export({ format: "jwk" });
  const doc = {
    description: "TEST KEY ONLY - never use outside the conformance fixtures",
    privateJwk: jwk,
    publicJwk: Object.fromEntries(Object.entries(jwk).filter(([k]) => k !== "d")),
  };
  writeFileSync(file, JSON.stringify(doc, null, 2) + "\n");
  return doc;
}

const p256 = loadOrCreateKey("p256", "ec", { namedCurve: "P-256" });
const ed25519 = loadOrCreateKey("ed25519", "ed25519");
const unlisted = loadOrCreateKey("p256-unlisted", "ec", { namedCurve: "P-256" });

const privateKey = (doc) => createPrivateKey({ key: doc.privateJwk, format: "jwk" });
const publicKey = (doc) => createPublicKey({ key: doc.publicJwk, format: "jwk" });

// ---------------------------------------------------------------------------
// did:key
// ---------------------------------------------------------------------------

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58btc(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out;
}

const b64u = (s) => Buffer.from(s, "base64url");

function didKeyFromJwk(jwk) {
  let prefix;
  let raw;
  if (jwk.kty === "EC" && jwk.crv === "P-256") {
    const x = b64u(jwk.x);
    const y = b64u(jwk.y);
    raw = Buffer.concat([Buffer.from([(y[y.length - 1] & 1) === 1 ? 0x03 : 0x02]), x]);
    prefix = Buffer.from([0x80, 0x24]); // multicodec p256-pub (0x1200) as unsigned varint
  } else if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
    raw = b64u(jwk.x);
    prefix = Buffer.from([0xed, 0x01]); // multicodec ed25519-pub (0xed) as unsigned varint
  } else {
    throw new Error("unsupported key");
  }
  const multibase = "z" + base58btc(Buffer.concat([prefix, raw]));
  return { did: `did:key:${multibase}`, kid: `did:key:${multibase}#${multibase}` };
}

// Known vector from the did:key method specification (P-256 test vectors).
const specVector = {
  publicJwk: {
    kty: "EC",
    crv: "P-256",
    x: "fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI",
    y: "hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU",
  },
  expectedDid: "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
};
const specComputed = didKeyFromJwk(specVector.publicJwk).did;
if (specComputed !== specVector.expectedDid) {
  throw new Error(`did:key spec vector mismatch: ${specComputed}`);
}

const didVectors = [
  { name: "did-key-spec-p256", source: "did:key method specification test vector", publicJwk: specVector.publicJwk, ...didKeyFromJwk(specVector.publicJwk) },
  { name: "fixture-p256", publicJwk: p256.publicJwk, ...didKeyFromJwk(p256.publicJwk) },
  { name: "fixture-ed25519", publicJwk: ed25519.publicJwk, ...didKeyFromJwk(ed25519.publicJwk) },
];
write("did-key.json", {
  description:
    "did:key encoding vectors. did = 'did:key:' + multibase(base58btc, multicodec-varint-prefix + public key); P-256 uses the 33-byte compressed point. kid = did + '#' + multibase.",
  vectors: didVectors,
});

// ---------------------------------------------------------------------------
// JWTs (self-signed LWS authentication credentials)
// ---------------------------------------------------------------------------

const enc = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

function jwt(header, claims, keyDoc) {
  const input = `${enc(header)}.${enc(claims)}`;
  const algo = header.alg === "ES256" ? "sha256" : null;
  const sig = sign(algo, Buffer.from(input), {
    key: privateKey(keyDoc),
    dsaEncoding: "ieee-p1363",
  });
  return `${input}.${sig.toString("base64url")}`;
}

const iat = 1790000000;
const jwtVectors = [];
for (const [name, keyDoc, alg] of [
  ["es256-did-key", p256, "ES256"],
  ["eddsa-did-key", ed25519, "EdDSA"],
]) {
  const { did, kid } = didKeyFromJwk(keyDoc.publicJwk);
  const header = { alg, typ: "JWT", kid };
  const claims = {
    sub: did,
    iss: did,
    client_id: did,
    aud: ["https://as.example"],
    iat,
    exp: iat + 300,
    jti: "7f6c3e2a-1b9d-4c47-9d8e-2f0a5b6c7d8e",
  };
  jwtVectors.push({ name, publicJwk: keyDoc.publicJwk, jwt: jwt(header, claims, keyDoc), header, claims });
}
write("jwt.json", {
  description:
    "Self-signed LWS authentication credentials (lws10-authn-ssi-cid). Each JWT must verify with publicJwk; ECDSA signatures are JOSE raw r||s.",
  vectors: jwtVectors,
});

// ---------------------------------------------------------------------------
// RFC 9421 webhook deliveries
// ---------------------------------------------------------------------------

const STORAGE = "https://storage.example/";
const INBOX = "https://receiver.example/hooks/lws?subscription=9e8d7c6b5a4f";

const storageDescription = {
  "@context": ["https://www.w3.org/ns/cid/v1", "https://www.w3.org/ns/lws/v1"],
  id: STORAGE,
  type: "Storage",
  verificationMethod: [
    {
      id: "https://storage.example/#key-p256",
      type: "JsonWebKey",
      controller: STORAGE,
      publicKeyJwk: { ...p256.publicJwk, kid: "key-p256", alg: "ES256" },
    },
    {
      id: "#key-ed25519",
      type: "JsonWebKey",
      controller: STORAGE,
      publicKeyJwk: { ...ed25519.publicJwk, kid: "key-ed25519", alg: "EdDSA" },
    },
    {
      id: "https://storage.example/#key-unlisted",
      type: "JsonWebKey",
      controller: STORAGE,
      publicKeyJwk: { ...unlisted.publicJwk, kid: "key-unlisted", alg: "ES256" },
    },
  ],
  authentication: ["https://storage.example/#key-p256", "#key-ed25519"],
  service: [
    { type: "StorageRoot", serviceEndpoint: "https://storage.example/root/" },
    {
      type: "NotificationService",
      serviceEndpoint: "https://storage.example/notifications/",
      subscriptionType: ["WebhookSubscription"],
    },
  ],
};
write("webhook/storage-description.json", storageDescription);

const notification = (storage) => ({
  "@context": ["https://www.w3.org/ns/lws/v1", "https://www.w3.org/ns/activitystreams"],
  type: "Notification",
  storage,
  activity: [
    {
      id: "urn:uuid:a1b2c3d4-5678-4abc-8ef0-1234567890ab",
      type: ["Create"],
      object: { id: "https://storage.example/root/notes/meeting.txt", type: ["DataResource"] },
      target: "https://storage.example/root/notes/",
      published: "2026-09-21T11:33:20Z",
    },
    {
      id: "urn:uuid:b2c3d4e5-6789-4bcd-9f01-234567890abc",
      type: ["Update"],
      object: { id: "https://storage.example/root/profile", type: ["DataResource"] },
      published: "2026-09-21T11:33:21Z",
    },
  ],
});

const digestHeader = (body, algs) =>
  algs
    .map((a) => `${a}=:${createHash(a.replace("-", "")).update(body).digest("base64")}:`)
    .join(", ");

const sfString = (s) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

function signatureParams(components, params) {
  const list = `(${components.map(sfString).join(" ")})`;
  const p = Object.entries(params)
    .map(([k, v]) => (typeof v === "number" ? `;${k}=${v}` : `;${k}=${sfString(v)}`))
    .join("");
  return list + p;
}

function componentValue(name, method, url, headers) {
  const u = new URL(url);
  switch (name) {
    case "@method":
      return method.toUpperCase();
    case "@scheme":
      return u.protocol.slice(0, -1).toLowerCase();
    case "@authority":
      return u.host.toLowerCase(); // URL.host omits default ports
    case "@path":
      return u.pathname || "/";
    case "@query":
      return u.search || "?";
    case "@target-uri":
      return u.href;
    default: {
      const v = headers[name];
      if (v === undefined) throw new Error(`missing header ${name}`);
      return v.trim();
    }
  }
}

function signatureBase(components, params, method, url, headers) {
  const lines = components.map((c) => `${sfString(c)}: ${componentValue(c, method, url, headers)}`);
  lines.push(`"@signature-params": ${signatureParams(components, params)}`);
  return lines.join("\n");
}

const REQUIRED = ["@method", "@scheme", "@authority", "@path", "content-type", "content-digest"];

function signedDelivery({
  keyDoc,
  keyid,
  alg,
  body,
  digestAlgs = ["sha-256"],
  components = REQUIRED,
  created = iat,
  url = INBOX,
  label = "sig1",
}) {
  const headers = {
    "content-type": "application/lws+json",
    "content-digest": digestHeader(body, digestAlgs),
  };
  const params = { created, keyid, alg };
  const base = signatureBase(components, params, "POST", url, headers);
  const sig = sign(alg === "ecdsa-p256-sha256" ? "sha256" : null, Buffer.from(base), {
    key: privateKey(keyDoc),
    dsaEncoding: "ieee-p1363",
  });
  headers["signature-input"] = `${label}=${signatureParams(components, params)}`;
  headers["signature"] = `${label}=:${sig.toString("base64")}:`;
  return { headers, signatureBase: base };
}

const body = JSON.stringify(notification(STORAGE));
const expectedNotification = {
  storage: STORAGE,
  activities: [
    { types: ["Create"], objectId: "https://storage.example/root/notes/meeting.txt", target: "https://storage.example/root/notes/" },
    { types: ["Update"], objectId: "https://storage.example/root/profile" },
  ],
};

const vectors = [];
const add = (v) => vectors.push({ method: "POST", url: INBOX, now: iat + 30, ...v });

{
  const d = signedDelivery({ keyDoc: p256, keyid: "https://storage.example/#key-p256", alg: "ecdsa-p256-sha256", body });
  add({ name: "p256-valid", description: "ECDSA P-256 signature, sha-256 digest", headers: d.headers, body, signatureBase: d.signatureBase, expected: { valid: true, keyid: "https://storage.example/#key-p256", notification: expectedNotification } });
}
{
  const d = signedDelivery({ keyDoc: ed25519, keyid: "https://storage.example/#key-ed25519", alg: "ed25519", body, digestAlgs: ["sha-512"] });
  add({ name: "ed25519-valid", description: "Ed25519 signature, sha-512 digest; verification method id is the bare fragment form '#key-ed25519'", headers: d.headers, body, signatureBase: d.signatureBase, expected: { valid: true, keyid: "https://storage.example/#key-ed25519", notification: expectedNotification } });
}
{
  const d = signedDelivery({ keyDoc: p256, keyid: "https://storage.example/#key-p256", alg: "ecdsa-p256-sha256", body, digestAlgs: ["sha-256", "sha-512"] });
  add({ name: "p256-two-digests-valid", description: "Content-Digest carries sha-256 and sha-512; both must match", headers: d.headers, body, signatureBase: d.signatureBase, expected: { valid: true, keyid: "https://storage.example/#key-p256", notification: expectedNotification } });
}
{
  const d = signedDelivery({ keyDoc: p256, keyid: "https://storage.example/#key-p256", alg: "ecdsa-p256-sha256", body });
  add({ name: "body-tampered", description: "Body modified after signing; Content-Digest no longer matches", headers: d.headers, body: body.replace("meeting.txt", "evil.txt"), expected: { valid: false, reason: "content-digest mismatch" } });
}
{
  const d = signedDelivery({ keyDoc: p256, keyid: "https://storage.example/#key-p256", alg: "ecdsa-p256-sha256", body });
  const tampered = body.replace("meeting.txt", "evil.txt");
  add({ name: "digest-recomputed", description: "Attacker modified body and recomputed Content-Digest; signature no longer verifies", headers: { ...d.headers, "content-digest": digestHeader(tampered, ["sha-256"]) }, body: tampered, expected: { valid: false, reason: "signature mismatch" } });
}
{
  const d = signedDelivery({ keyDoc: p256, keyid: "https://storage.example/#key-p256", alg: "ecdsa-p256-sha256", body });
  add({ name: "wrong-authority", description: "Delivered to a different host than the one signed (@authority mismatch)", url: "https://evil.example/hooks/lws?subscription=9e8d7c6b5a4f", headers: d.headers, body, expected: { valid: false, reason: "signature mismatch" } });
}
{
  const d = signedDelivery({ keyDoc: p256, keyid: "https://storage.example/#key-p256", alg: "ecdsa-p256-sha256", body });
  add({ name: "too-old", description: "created is one hour before now (outside the default 300 s window)", now: iat + 3600, headers: d.headers, body, expected: { valid: false, reason: "signature too old" } });
}
{
  const d = signedDelivery({ keyDoc: p256, keyid: "https://storage.example/#key-p256", alg: "ecdsa-p256-sha256", body, created: iat + 3600 });
  add({ name: "from-the-future", description: "created is one hour after now", headers: d.headers, body, expected: { valid: false, reason: "signature created in the future" } });
}
{
  const d = signedDelivery({ keyDoc: p256, keyid: "https://storage.example/#key-p256", alg: "ecdsa-p256-sha256", body, components: ["@method", "@path", "content-digest"] });
  add({ name: "missing-required-components", description: "Signature does not cover @scheme, @authority and content-type", headers: d.headers, body, expected: { valid: false, reason: "required component not covered" } });
}
{
  const d = signedDelivery({ keyDoc: unlisted, keyid: "https://storage.example/#key-unlisted", alg: "ecdsa-p256-sha256", body });
  add({ name: "key-not-in-authentication", description: "Key is in verificationMethod but not referenced from authentication", headers: d.headers, body, expected: { valid: false, reason: "key not authorized for authentication" } });
}
{
  const otherBody = JSON.stringify(notification("https://other.example/"));
  const d = signedDelivery({ keyDoc: p256, keyid: "https://storage.example/#key-p256", alg: "ecdsa-p256-sha256", body: otherBody });
  add({ name: "storage-mismatch", description: "Notification claims a different storage than the signing key's storage", headers: d.headers, body: otherBody, expected: { valid: false, reason: "notification storage does not match keyid storage" } });
}
{
  const d = signedDelivery({ keyDoc: p256, keyid: "https://storage.example/#key-missing", alg: "ecdsa-p256-sha256", body });
  add({ name: "unknown-key", description: "keyid fragment not present in the storage description", headers: d.headers, body, expected: { valid: false, reason: "verification method not found" } });
}
{
  const d = signedDelivery({ keyDoc: p256, keyid: "https://storage.example/#key-p256", alg: "ed25519", body });
  // Signed with P-256 but advertising alg=ed25519: rejected because alg does not match the key.
  add({ name: "alg-mismatch", description: "alg parameter (ed25519) does not match the P-256 key", headers: d.headers, body, expected: { valid: false, reason: "alg does not match key" } });
}

for (const v of vectors) write(`webhook/${v.name}.json`, v);
write("webhook/index.json", {
  description:
    "RFC 9421 signed webhook deliveries. Verify each with storage-description.json as the dereferenced storage description, the given 'url' as the inbox URL, and 'now' (unix seconds) as the current time, using a 300 s max age / clock skew.",
  storageDescription: "storage-description.json",
  vectors: vectors.map((v) => `${v.name}.json`),
});

// Sanity: verify the valid vectors with node:crypto.
import { verify } from "node:crypto";
for (const v of vectors.filter((x) => x.expected.valid)) {
  const keyDoc = v.name.startsWith("ed25519") ? ed25519 : p256;
  const sig = Buffer.from(v.headers.signature.split("=:")[1].slice(0, -1), "base64");
  const ok = verify(keyDoc === p256 ? "sha256" : null, Buffer.from(v.signatureBase), { key: publicKey(keyDoc), dsaEncoding: "ieee-p1363" }, sig);
  if (!ok) throw new Error(`self-check failed for ${v.name}`);
}
console.log(`wrote ${vectors.length} webhook vectors, ${didVectors.length} did:key vectors, ${jwtVectors.length} JWT vectors`);
