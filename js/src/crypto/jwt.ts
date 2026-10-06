// SPDX-License-Identifier: MIT
// Minimal compact JWS/JWT helpers (sign, decode, verify) on WebCrypto.
import { base64UrlEncodeText, base64UrlToBytes, bytesToBase64Url, utf8Decode, utf8Encode } from "../util/base64.js";
import { isObject } from "../util/types.js";
import { algorithmOfJwk, signBytes, verifyBytes, type SigningKeyPair } from "./keys.js";

/** Decoded (unverified) JWT. */
export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: Uint8Array<ArrayBuffer>;
  signingInput: string;
}

/** Create a signed compact JWT. The `alg` header is set from the key pair. */
export async function signJwt(
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
  key: Pick<SigningKeyPair, "algorithm" | "privateKey">,
): Promise<string> {
  const input = `${base64UrlEncodeText(JSON.stringify({ ...header, alg: key.algorithm }))}.${base64UrlEncodeText(JSON.stringify(claims))}`;
  const sig = await signBytes(key, utf8Encode(input));
  return `${input}.${bytesToBase64Url(sig)}`;
}

/** Decode a compact JWT without verifying it. */
export function decodeJwt(token: string): DecodedJwt {
  const parts = token.split(".");
  if (parts.length !== 3) throw new SyntaxError("JWT must have three parts");
  const header = JSON.parse(utf8Decode(base64UrlToBytes(parts[0]!))) as unknown;
  const payload = JSON.parse(utf8Decode(base64UrlToBytes(parts[1]!))) as unknown;
  if (!isObject(header) || !isObject(payload)) throw new SyntaxError("JWT header and payload must be JSON objects");
  return { header, payload, signature: base64UrlToBytes(parts[2]!), signingInput: `${parts[0]}.${parts[1]}` };
}

/**
 * Verify a compact JWT signature with a public JWK (ES256 or EdDSA) and return
 * the decoded token. Rejects `alg: none` and algorithm/key mismatches. Claims
 * (exp, aud, …) are not validated.
 */
export async function verifyJwt(token: string, publicJwk: JsonWebKey): Promise<DecodedJwt> {
  const decoded = decodeJwt(token);
  const alg = decoded.header["alg"];
  if (alg === "none" || typeof alg !== "string") throw new Error("JWT alg must not be 'none'");
  if (alg !== algorithmOfJwk(publicJwk)) throw new Error(`JWT alg ${alg} does not match the key`);
  const ok = await verifyBytes(publicJwk, decoded.signature, utf8Encode(decoded.signingInput));
  if (!ok) throw new Error("JWT signature is invalid");
  return decoded;
}
