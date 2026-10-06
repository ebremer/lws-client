// SPDX-License-Identifier: MIT
// WebCrypto key helpers: generation, JWK import/export, did:key, CID documents.
import { CID_CONTEXT } from "../constants.js";
import { base64UrlToBytes, bytesToBase64Url, concatBytes } from "../util/base64.js";

/** JOSE signing algorithms supported for self-signed credentials. */
export type SigningAlgorithm = "ES256" | "EdDSA";

/** A key pair usable for signing LWS authentication credentials. */
export interface SigningKeyPair {
  readonly algorithm: SigningAlgorithm;
  readonly privateKey: CryptoKey;
  readonly publicKey: CryptoKey;
  /** Public JWK (kty/crv/x[/y] only). */
  readonly publicJwk: JsonWebKey;
}

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error("WebCrypto (crypto.subtle) is not available in this environment");
  return s;
}

/** WebCrypto import/generation parameters for an algorithm. */
export function keyParams(alg: SigningAlgorithm): EcKeyImportParams | Algorithm {
  return alg === "ES256" ? { name: "ECDSA", namedCurve: "P-256" } : { name: "Ed25519" };
}

/** WebCrypto signing parameters for an algorithm. */
export function signParams(alg: SigningAlgorithm): EcdsaParams | Algorithm {
  return alg === "ES256" ? { name: "ECDSA", hash: "SHA-256" } : { name: "Ed25519" };
}

/** Determine the JOSE algorithm of a JWK. */
export function algorithmOfJwk(jwk: JsonWebKey): SigningAlgorithm {
  if (jwk.kty === "EC" && jwk.crv === "P-256") return "ES256";
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") return "EdDSA";
  throw new TypeError(`unsupported key type ${jwk.kty}/${jwk.crv} (supported: EC P-256, OKP Ed25519)`);
}

/** Determine the JOSE algorithm of a CryptoKey. */
export function algorithmOfKey(key: CryptoKey): SigningAlgorithm {
  const a = key.algorithm as EcKeyAlgorithm;
  if (a.name === "ECDSA" && a.namedCurve === "P-256") return "ES256";
  if (a.name === "Ed25519") return "EdDSA";
  throw new TypeError(`unsupported key algorithm ${a.name}${a.namedCurve ? "/" + a.namedCurve : ""}`);
}

/** Keep only the public members of a JWK. */
export function publicJwkOf(jwk: JsonWebKey): JsonWebKey {
  const out: JsonWebKey = { kty: jwk.kty };
  if (jwk.crv !== undefined) out.crv = jwk.crv;
  if (jwk.x !== undefined) out.x = jwk.x;
  if (jwk.y !== undefined) out.y = jwk.y;
  if (jwk.n !== undefined) out.n = jwk.n;
  if (jwk.e !== undefined) out.e = jwk.e;
  return out;
}

/**
 * Generate a signing key pair (ES256 = P-256 by default, or EdDSA = Ed25519).
 * Set `extractable` to export the private key later (e.g. to persist it as a JWK).
 */
export async function generateKeyPair(
  algorithm: SigningAlgorithm = "ES256",
  options: { extractable?: boolean } = {},
): Promise<SigningKeyPair> {
  const pair = (await subtle().generateKey(keyParams(algorithm), options.extractable ?? false, ["sign", "verify"])) as CryptoKeyPair;
  const publicJwk = publicJwkOf(await subtle().exportKey("jwk", pair.publicKey));
  return { algorithm, privateKey: pair.privateKey, publicKey: pair.publicKey, publicJwk };
}

/** Import a key pair from a private JWK (must contain `d`, plus the public members). */
export async function importKeyPair(privateJwk: JsonWebKey, options: { extractable?: boolean } = {}): Promise<SigningKeyPair> {
  if (!privateJwk.d) throw new TypeError("private JWK must contain 'd'");
  const algorithm = algorithmOfJwk(privateJwk);
  const { key_ops: _ops, ext: _ext, alg: _alg, use: _use, ...clean } = privateJwk;
  const privateKey = await subtle().importKey("jwk", clean, keyParams(algorithm), options.extractable ?? false, ["sign"]);
  const publicJwk = publicJwkOf(privateJwk);
  const publicKey = await subtle().importKey("jwk", publicJwk, keyParams(algorithm), true, ["verify"]);
  return { algorithm, privateKey, publicKey, publicJwk };
}

/** Import a public JWK for signature verification. */
export async function importPublicJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  const algorithm = algorithmOfJwk(jwk);
  return subtle().importKey("jwk", publicJwkOf(jwk), keyParams(algorithm), true, ["verify"]);
}

/** Export the private key of an extractable key pair as a JWK. */
export async function exportPrivateJwk(pair: SigningKeyPair): Promise<JsonWebKey> {
  const { key_ops: _ops, ext: _ext, ...jwk } = await subtle().exportKey("jwk", pair.privateKey);
  return jwk;
}

/** Sign bytes with a key pair; ECDSA signatures are raw r‖s (JOSE / RFC 9421 form). */
export async function signBytes(pair: Pick<SigningKeyPair, "algorithm" | "privateKey">, data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await subtle().sign(signParams(pair.algorithm), pair.privateKey, data));
}

/** Verify a signature (raw r‖s for ECDSA) with a public JWK. */
export async function verifyBytes(publicJwk: JsonWebKey, signature: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>): Promise<boolean> {
  const algorithm = algorithmOfJwk(publicJwk);
  const key = await importPublicJwk(publicJwk);
  return subtle().verify(signParams(algorithm), key, signature, data);
}

// ---------------------------------------------------------------------------
// did:key
// ---------------------------------------------------------------------------

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** base58btc encoding (Bitcoin alphabet). */
export function base58btcEncode(bytes: Uint8Array): string {
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

/** base58btc decoding. */
export function base58btcDecode(text: string): Uint8Array<ArrayBuffer> {
  let n = 0n;
  for (const c of text) {
    const v = B58.indexOf(c);
    if (v < 0) throw new SyntaxError(`invalid base58 character '${c}'`);
    n = n * 58n + BigInt(v);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n % 256n));
    n /= 256n;
  }
  for (const c of text) {
    if (c !== "1") break;
    bytes.unshift(0);
  }
  return new Uint8Array(bytes);
}

const P256_PREFIX = new Uint8Array([0x80, 0x24]); // multicodec p256-pub (0x1200)
const ED25519_PREFIX = new Uint8Array([0xed, 0x01]); // multicodec ed25519-pub (0xed)

/** A did:key identifier and its verification method id. */
export interface DidKey {
  /** `did:key:z…` */
  did: string;
  /** `did:key:z…#z…` (use as JWT `kid`). */
  kid: string;
}

/** Derive the did:key identifier of a public JWK (P-256 or Ed25519). */
export function didKeyFromJwk(publicJwk: JsonWebKey): DidKey {
  const alg = algorithmOfJwk(publicJwk);
  let bytes: Uint8Array;
  if (alg === "ES256") {
    if (!publicJwk.x || !publicJwk.y) throw new TypeError("P-256 JWK requires x and y");
    const x = base64UrlToBytes(publicJwk.x);
    const y = base64UrlToBytes(publicJwk.y);
    const prefix = (y[y.length - 1]! & 1) === 1 ? 0x03 : 0x02;
    bytes = concatBytes(P256_PREFIX, new Uint8Array([prefix]), x);
  } else {
    if (!publicJwk.x) throw new TypeError("Ed25519 JWK requires x");
    bytes = concatBytes(ED25519_PREFIX, base64UrlToBytes(publicJwk.x));
  }
  const multibase = "z" + base58btcEncode(bytes);
  return { did: `did:key:${multibase}`, kid: `did:key:${multibase}#${multibase}` };
}

/** Derive the did:key identifier of a public CryptoKey. */
export async function didKeyFromPublicKey(publicKey: CryptoKey): Promise<DidKey> {
  return didKeyFromJwk(await subtle().exportKey("jwk", publicKey));
}

// P-256 curve parameters for point decompression.
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

const toBigInt = (bytes: Uint8Array): bigint => bytes.reduce((n, b) => (n << 8n) | BigInt(b), 0n);
function toBytes32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

/** Resolve a did:key identifier (or DID URL) to its public JWK (P-256 or Ed25519). */
export function jwkFromDidKey(didOrKid: string): JsonWebKey {
  const did = didOrKid.split("#")[0]!;
  if (!did.startsWith("did:key:z")) throw new TypeError("not a base58btc did:key identifier");
  const bytes = base58btcDecode(did.slice("did:key:z".length));
  if (bytes[0] === 0xed && bytes[1] === 0x01 && bytes.length === 34) {
    return { kty: "OKP", crv: "Ed25519", x: bytesToBase64Url(bytes.subarray(2)) };
  }
  if (bytes[0] === 0x80 && bytes[1] === 0x24 && bytes.length === 35) {
    const sign = bytes[2]!;
    const x = toBigInt(bytes.subarray(3));
    const rhs = (((x * x * x - 3n * x + B) % P) + P) % P;
    let y = modPow(rhs, (P + 1n) / 4n, P);
    if ((y & 1n) !== BigInt(sign & 1)) y = P - y;
    return { kty: "EC", crv: "P-256", x: bytesToBase64Url(toBytes32(x)), y: bytesToBase64Url(toBytes32(y)) };
  }
  throw new TypeError("unsupported did:key multicodec (supported: p256-pub, ed25519-pub)");
}

/**
 * Build the controlled identifier document an agent must publish at its URI
 * so verifiers can validate its self-signed credentials (lws10-authn-ssi-cid).
 */
export function controlledIdentifierDocument(agent: string, publicJwk: JsonWebKey, kid: string): Record<string, unknown> {
  const vmId = kid.includes(":") ? kid : `${agent}#${kid.replace(/^#/, "")}`;
  const bareKid = vmId.includes("#") ? vmId.slice(vmId.indexOf("#") + 1) : kid;
  return {
    "@context": [CID_CONTEXT],
    id: agent,
    authentication: [
      {
        id: vmId,
        type: "JsonWebKey",
        controller: agent,
        publicKeyJwk: { ...publicJwkOf(publicJwk), kid: bareKid, alg: algorithmOfJwk(publicJwk) },
      },
    ],
  };
}
