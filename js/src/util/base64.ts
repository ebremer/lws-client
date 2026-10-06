// SPDX-License-Identifier: MIT
// Universal (browser / Node / Deno / Bun) base64 helpers built on btoa/atob.

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** UTF-8 encode a string. */
export function utf8Encode(text: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(text) as Uint8Array<ArrayBuffer>;
}

/** UTF-8 decode bytes. */
export function utf8Decode(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** Standard base64 (with padding). */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

/** Decode standard base64 (padding optional). Throws on invalid input. */
export function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) throw new SyntaxError("invalid base64");
  let padded = b64;
  while (padded.length % 4 !== 0) padded += "=";
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** base64url without padding (RFC 4648 §5), as used by JOSE. */
export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode base64url (padding optional). */
export function base64UrlToBytes(s: string): Uint8Array<ArrayBuffer> {
  return base64ToBytes(s.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, ""));
}

/** base64url-encode the UTF-8 bytes of a string. */
export function base64UrlEncodeText(text: string): string {
  return bytesToBase64Url(utf8Encode(text));
}

/** Concatenate byte arrays. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Length-independent comparison of two byte arrays. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
