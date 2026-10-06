// SPDX-License-Identifier: MIT
// Cryptography for the mock server: base58btc / did:key, compact JWS (ES256, EdDSA),
// RFC 9421 HTTP Message Signatures and RFC 9530 Content-Digest.

import { createHash, createPublicKey, ECDH, sign, verify } from "node:crypto";

export const b64u = {
  encode: (buf) => Buffer.from(buf).toString("base64url"),
  decode: (s) => Buffer.from(s, "base64url"),
};

// ---------------------------------------------------------------------------
// base58btc and did:key
// ---------------------------------------------------------------------------

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Encode(bytes) {
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

export function base58Decode(str) {
  let n = 0n;
  for (const c of str) {
    const v = B58.indexOf(c);
    if (v < 0) throw new Error("invalid base58 character");
    n = n * 58n + BigInt(v);
  }
  const out = [];
  while (n > 0n) {
    out.unshift(Number(n & 255n));
    n >>= 8n;
  }
  for (const c of str) {
    if (c !== "1") break;
    out.unshift(0);
  }
  return Buffer.from(out);
}

/** Decodes the public key embedded in a did:key identifier (P-256 or Ed25519) to a JWK. */
export function didKeyToPublicJwk(did) {
  const m = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)(?:#.*)?$/.exec(did);
  if (!m) throw new Error("not a base58btc did:key identifier");
  const bytes = base58Decode(m[1]);
  if (bytes.length === 35 && bytes[0] === 0x80 && bytes[1] === 0x24) {
    const point = ECDH.convertKey(bytes.subarray(2), "prime256v1", undefined, undefined, "uncompressed");
    return { kty: "EC", crv: "P-256", x: b64u.encode(point.subarray(1, 33)), y: b64u.encode(point.subarray(33, 65)) };
  }
  if (bytes.length === 34 && bytes[0] === 0xed && bytes[1] === 0x01) {
    return { kty: "OKP", crv: "Ed25519", x: b64u.encode(bytes.subarray(2)) };
  }
  throw new Error("unsupported did:key multicodec (P-256 and Ed25519 are supported)");
}

/** Encodes a P-256 or Ed25519 public JWK as a did:key identifier and key id. */
export function publicJwkToDidKey(jwk) {
  let prefix;
  let raw;
  if (jwk.kty === "EC" && jwk.crv === "P-256") {
    const x = b64u.decode(jwk.x);
    const y = b64u.decode(jwk.y);
    raw = Buffer.concat([Buffer.from([(y[y.length - 1] & 1) === 1 ? 0x03 : 0x02]), x]);
    prefix = Buffer.from([0x80, 0x24]);
  } else if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
    raw = b64u.decode(jwk.x);
    prefix = Buffer.from([0xed, 0x01]);
  } else {
    throw new Error("unsupported key type for did:key");
  }
  const multibase = `z${base58Encode(Buffer.concat([prefix, raw]))}`;
  return { did: `did:key:${multibase}`, kid: `did:key:${multibase}#${multibase}` };
}

/** Imports a public JWK, keeping only the members that define the key. */
export function publicKeyFromJwk(jwk) {
  if (!jwk || typeof jwk !== "object") throw new Error("missing publicKeyJwk");
  const { kty, crv, x, y, n, e } = jwk;
  const key = Object.fromEntries(Object.entries({ kty, crv, x, y, n, e }).filter(([, v]) => v !== undefined));
  return createPublicKey({ key, format: "jwk" });
}

// ---------------------------------------------------------------------------
// Compact JWS / JWT
// ---------------------------------------------------------------------------

function hashFor(alg) {
  switch (alg) {
    case "ES256":
      return "sha256";
    case "ES384":
      return "sha384";
    case "EdDSA":
    case "Ed25519":
      return null;
    default:
      throw new Error(`unsupported JWS algorithm: ${alg}`);
  }
}

export function signJwt(header, payload, privateKey) {
  const input = `${b64u.encode(JSON.stringify(header))}.${b64u.encode(JSON.stringify(payload))}`;
  const sig = sign(hashFor(header.alg), Buffer.from(input), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return `${input}.${b64u.encode(sig)}`;
}

export function decodeJwt(token) {
  if (typeof token !== "string") throw new Error("token is not a string");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("not a compact JWS");
  const header = JSON.parse(b64u.decode(parts[0]).toString("utf8"));
  const payload = JSON.parse(b64u.decode(parts[1]).toString("utf8"));
  if (!header || typeof header !== "object" || !payload || typeof payload !== "object") {
    throw new Error("JWT header and payload must be JSON objects");
  }
  return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: b64u.decode(parts[2]) };
}

/** Verifies a decoded JWT against a KeyObject, checking that the algorithm fits the key type. */
export function verifyJwtSignature(jwt, publicKey) {
  const { alg } = jwt.header;
  const type = publicKey.asymmetricKeyType;
  const curve = publicKey.asymmetricKeyDetails?.namedCurve;
  if (alg === "ES256" && !(type === "ec" && curve === "prime256v1")) return false;
  if (alg === "ES384" && !(type === "ec" && curve === "secp384r1")) return false;
  if ((alg === "EdDSA" || alg === "Ed25519") && type !== "ed25519") return false;
  if (alg.startsWith("ES") && jwt.signature.length !== (alg === "ES256" ? 64 : 96)) return false;
  return verify(hashFor(alg), Buffer.from(jwt.signingInput), { key: publicKey, dsaEncoding: "ieee-p1363" }, jwt.signature);
}

// ---------------------------------------------------------------------------
// RFC 9421 HTTP Message Signatures / RFC 9530 Content-Digest
// ---------------------------------------------------------------------------

export const WEBHOOK_COMPONENTS = ["@method", "@scheme", "@authority", "@path", "content-type", "content-digest"];

export function sfString(s) {
  return `"${String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export function serializeSignatureParams(components, params) {
  let out = `(${components.map(sfString).join(" ")})`;
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined) continue;
    out += typeof v === "number" ? `;${k}=${v}` : `;${k}=${sfString(v)}`;
  }
  return out;
}

export function componentValue(name, { method, url, headers }) {
  const u = new URL(url);
  switch (name) {
    case "@method":
      return method.toUpperCase();
    case "@scheme":
      return u.protocol.slice(0, -1).toLowerCase();
    case "@authority":
      return u.host.toLowerCase();
    case "@path":
      return u.pathname || "/";
    case "@query":
      return u.search || "?";
    case "@target-uri":
      return u.href;
    default: {
      const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
      if (key === undefined) throw new Error(`header ${name} is not present`);
      const v = headers[key];
      return (Array.isArray(v) ? v.map((x) => String(x).trim()).join(", ") : String(v)).trim();
    }
  }
}

export function signatureBase(components, serializedParams, message) {
  const lines = components.map((c) => `${sfString(c)}: ${componentValue(c, message)}`);
  lines.push(`"@signature-params": ${serializedParams}`);
  return lines.join("\n");
}

export function contentDigest(body, algorithms = ["sha-256"]) {
  return algorithms
    .map((a) => `${a}=:${createHash(a.replace("-", "")).update(body).digest("base64")}:`)
    .join(", ");
}

/**
 * Signs an outgoing request per lws10-notifications-webhook. `headers` must already contain
 * content-type and content-digest. Returns the Signature-Input and Signature header values.
 */
export function signRequest({ method, url, headers, privateKey, keyid, alg = "ecdsa-p256-sha256", created, label = "sig1", components = WEBHOOK_COMPONENTS }) {
  const params = serializeSignatureParams(components, {
    created: created ?? Math.floor(Date.now() / 1000),
    keyid,
    alg,
  });
  const base = signatureBase(components, params, { method, url, headers });
  const sig = sign(alg === "ed25519" ? null : "sha256", Buffer.from(base), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return {
    "Signature-Input": `${label}=${params}`,
    Signature: `${label}=:${sig.toString("base64")}:`,
    signatureBase: base,
  };
}
