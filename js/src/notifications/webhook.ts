// SPDX-License-Identifier: MIT
// Verification of signed webhook deliveries (lws10-notifications-webhook):
// RFC 9530 Content-Digest + RFC 9421 HTTP Message Signatures.
import { SignatureVerificationError } from "../errors.js";
import {
  parseDictionary,
  serializeMember,
  type SfDictionary,
  type SfInnerList,
} from "../http/structured-fields.js";
import { StorageDescription } from "../models/storage.js";
import { parseNotification, type Notification } from "../models/notification.js";
import { bytesEqual, bytesToBase64, utf8Encode } from "../util/base64.js";

/** A webhook request in transport-neutral form. */
export interface WebhookRequestLike {
  method: string;
  /** The URL the request was delivered to (normally the registered inbox URL). */
  url: string;
  headers: Headers | Record<string, string | readonly string[] | undefined> | Iterable<[string, string]>;
  body: Uint8Array | ArrayBuffer | string;
}

/** Fetches a storage description by storage identifier (e.g. `client.getStorageDescription`). */
export type StorageDescriptionResolver = (storageId: string) => Promise<StorageDescription | object>;

/** Options of {@link WebhookVerifier}. */
export interface WebhookVerifierOptions {
  /** How to dereference a storage identifier. Pass `(id) => client.getStorageDescription(id)`. */
  resolveStorageDescription: StorageDescriptionResolver;
  /** Only accept deliveries signed by these storages. */
  trustedStorages?: readonly string[];
  /** Maximum age of the `created` parameter in seconds (default 300). */
  maxAgeSeconds?: number;
  /** Tolerated clock skew for `created` in the future, in seconds (default 300). */
  clockSkewSeconds?: number;
  /** Storage description cache TTL in seconds (default 600). */
  keyCacheTtlSeconds?: number;
  /** Clock in epoch milliseconds. */
  clock?: () => number;
}

/** Per-call options of {@link WebhookVerifier.verify}. */
export interface VerifyOptions {
  /** The registered inbox URL; overrides the request URL (useful behind proxies). */
  inboxUrl?: string;
}

/** A successfully verified delivery. */
export interface VerifiedNotification {
  notification: Notification;
  /** The `keyid` that signed the delivery. */
  keyid: string;
  /** The storage identifier derived from the keyid. */
  storage: string;
  /** The signature label used (e.g. `sig1`). */
  label: string;
}

const REQUIRED_COMPONENTS = ["@method", "@scheme", "@authority", "@path", "content-type", "content-digest"];
const DIGESTS: Record<string, "SHA-256" | "SHA-512"> = { "sha-256": "SHA-256", "sha-512": "SHA-512" };

function fail(message: string, cause?: unknown): never {
  throw new SignatureVerificationError(message, cause === undefined ? undefined : { cause });
}

function toHeaders(h: WebhookRequestLike["headers"]): Headers {
  if (h instanceof Headers) return h;
  const out = new Headers();
  if (Symbol.iterator in h) {
    for (const [k, v] of h as Iterable<[string, string]>) out.append(k, v);
    return out;
  }
  for (const [k, v] of Object.entries(h as Record<string, string | readonly string[] | undefined>)) {
    if (v === undefined) continue;
    if (typeof v === "string") out.append(k, v);
    else for (const item of v) out.append(k, item);
  }
  return out;
}

function toBytes(body: WebhookRequestLike["body"]): Uint8Array<ArrayBuffer> {
  if (typeof body === "string") return utf8Encode(body);
  if (body instanceof Uint8Array) return new Uint8Array(body);
  return new Uint8Array(body);
}

function sfDict(headers: Headers, name: string): SfDictionary {
  const value = headers.get(name);
  if (value === null) fail(`missing ${name} header`);
  try {
    return parseDictionary(value);
  } catch (e) {
    return fail(`malformed ${name} header`, e);
  }
}

async function digest(alg: "SHA-256" | "SHA-512", body: Uint8Array<ArrayBuffer>): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest(alg, body));
}

/** Verify an RFC 9530 `Content-Digest` header against a body. */
export async function verifyContentDigest(headers: Headers, body: Uint8Array<ArrayBuffer>): Promise<void> {
  const dict = sfDict(headers, "content-digest");
  let recognised = 0;
  for (const [alg, member] of dict) {
    const algorithm = DIGESTS[alg];
    if (!algorithm) continue;
    recognised++;
    if (member.kind !== "item" || member.value.type !== "bytes") fail(`content-digest ${alg} is not a byte sequence`);
    if (!bytesEqual(await digest(algorithm, body), member.value.value)) fail("content-digest mismatch");
  }
  if (recognised === 0) fail("content-digest has no supported algorithm (sha-256, sha-512)");
}

/** Compute an RFC 9530 `Content-Digest` header value for a body. */
export async function contentDigest(body: Uint8Array<ArrayBuffer> | string, algorithm: "sha-256" | "sha-512" = "sha-256"): Promise<string> {
  const bytes = typeof body === "string" ? utf8Encode(body) : body;
  return `${algorithm}=:${bytesToBase64(await digest(DIGESTS[algorithm]!, bytes))}:`;
}

/** The value of one covered component (RFC 9421 §2). */
export function componentValue(name: string, method: string, url: URL, headers: Headers): string {
  switch (name) {
    case "@method":
      return method.toUpperCase();
    case "@scheme":
      return url.protocol.slice(0, -1).toLowerCase();
    case "@authority":
      return url.host.toLowerCase();
    case "@path":
      return url.pathname || "/";
    case "@query":
      return url.search || "?";
    case "@target-uri":
      return url.href;
    case "@request-target":
      return (url.pathname || "/") + url.search;
    default: {
      if (name.startsWith("@")) fail(`unsupported derived component ${name}`);
      const v = headers.get(name);
      if (v === null) fail(`covered header ${name} is missing`);
      return v.trim();
    }
  }
}

/** Build the RFC 9421 signature base for a signature's inner list. */
export function signatureBase(params: SfInnerList, method: string, url: URL, headers: Headers): string {
  const lines: string[] = [];
  for (const item of params.items) {
    if (item.value.type !== "string") fail("covered component identifiers must be strings");
    if (item.params.size > 0) fail(`component parameters are not supported (${item.value.value})`);
    lines.push(`"${item.value.value}": ${componentValue(item.value.value, method, url, headers)}`);
  }
  lines.push(`"@signature-params": ${serializeMember(params)}`);
  return lines.join("\n");
}

interface KeyMaterial {
  jwk: JsonWebKey;
  algorithm: "ecdsa-p256-sha256" | "ecdsa-p384-sha384" | "ed25519";
}

function keyMaterial(jwk: JsonWebKey): KeyMaterial {
  if (jwk.kty === "EC" && jwk.crv === "P-256") return { jwk, algorithm: "ecdsa-p256-sha256" };
  if (jwk.kty === "EC" && jwk.crv === "P-384") return { jwk, algorithm: "ecdsa-p384-sha384" };
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") return { jwk, algorithm: "ed25519" };
  return fail(`unsupported verification key ${jwk.kty}/${jwk.crv}`);
}

async function verifySignature(key: KeyMaterial, signature: Uint8Array, base: string): Promise<boolean> {
  const subtle = globalThis.crypto.subtle;
  const { kty, crv, x, y } = key.jwk;
  const jwk: JsonWebKey = y === undefined ? { kty, crv, x } : { kty, crv, x, y };
  const data = utf8Encode(base);
  const sig = new Uint8Array(signature);
  if (key.algorithm === "ed25519") {
    const k = await subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["verify"]);
    return subtle.verify({ name: "Ed25519" }, k, sig, data);
  }
  const curve = key.algorithm === "ecdsa-p256-sha256" ? "P-256" : "P-384";
  const hash = key.algorithm === "ecdsa-p256-sha256" ? "SHA-256" : "SHA-384";
  const k = await subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: curve }, false, ["verify"]);
  return subtle.verify({ name: "ECDSA", hash }, k, sig, data);
}

/**
 * Verifies signed webhook deliveries: Content-Digest, RFC 9421 signature with
 * the storage's published key (which must be an `authentication` key), the
 * freshness window, and that the notification's storage matches the signer.
 */
export class WebhookVerifier {
  readonly #options: WebhookVerifierOptions;
  readonly #cache = new Map<string, { description: StorageDescription; expires: number }>();

  constructor(options: WebhookVerifierOptions) {
    this.#options = options;
  }

  #now(): number {
    return (this.#options.clock ?? Date.now)();
  }

  async #description(storageId: string, refresh: boolean): Promise<{ description: StorageDescription; cached: boolean }> {
    const hit = this.#cache.get(storageId);
    if (!refresh && hit && hit.expires > this.#now()) return { description: hit.description, cached: true };
    let resolved: StorageDescription | object;
    try {
      resolved = await this.#options.resolveStorageDescription(storageId);
    } catch (e) {
      return fail(`could not retrieve storage description ${storageId}`, e);
    }
    let description: StorageDescription;
    try {
      description = resolved instanceof StorageDescription ? resolved : new StorageDescription(resolved, storageId);
    } catch (e) {
      return fail(`invalid storage description ${storageId}`, e);
    }
    if (description.id !== storageId) fail(`storage description id ${description.id} does not match ${storageId}`);
    this.#cache.set(storageId, { description, expires: this.#now() + (this.#options.keyCacheTtlSeconds ?? 600) * 1000 });
    return { description, cached: false };
  }

  /** Verify a delivery given as a Fetch API `Request` or a {@link WebhookRequestLike}. */
  async verify(request: Request | WebhookRequestLike, options: VerifyOptions = {}): Promise<VerifiedNotification> {
    let method: string;
    let url: string;
    let headers: Headers;
    let body: Uint8Array<ArrayBuffer>;
    if (typeof Request !== "undefined" && request instanceof Request) {
      method = request.method;
      url = request.url;
      headers = request.headers;
      body = new Uint8Array(await request.arrayBuffer());
    } else {
      const r = request as WebhookRequestLike;
      method = r.method;
      url = r.url;
      headers = toHeaders(r.headers);
      body = toBytes(r.body);
    }
    const target = new URL(options.inboxUrl ?? url);

    // 1. Content-Digest
    await verifyContentDigest(headers, body);

    // 2. Signature-Input / Signature
    const inputs = sfDict(headers, "signature-input");
    const signatures = sfDict(headers, "signature");
    let label: string | undefined;
    let params: SfInnerList | undefined;
    for (const [l, member] of inputs) {
      if (member.kind === "innerList" && member.params.get("keyid")?.type === "string" && signatures.has(l)) {
        label = l;
        params = member;
        break;
      }
    }
    if (!label || !params) fail("no signature with a keyid present in both Signature-Input and Signature");
    const sigMember = signatures.get(label)!;
    if (sigMember.kind !== "item" || sigMember.value.type !== "bytes") fail("signature value is not a byte sequence");
    const signature = sigMember.value.value;

    // 3. Required components and parameters
    const covered = params.items.map((i) => (i.value.type === "string" ? i.value.value : ""));
    for (const c of REQUIRED_COMPONENTS) if (!covered.includes(c)) fail(`required component ${c} not covered by the signature`);
    const created = params.params.get("created");
    if (created?.type !== "integer") fail("signature parameter 'created' is missing");
    const keyidItem = params.params.get("keyid");
    if (keyidItem?.type !== "string") fail("signature parameter 'keyid' is missing");
    const keyid = keyidItem.value;
    const now = Math.floor(this.#now() / 1000);
    if (created.value < now - (this.#options.maxAgeSeconds ?? 300)) fail("signature too old");
    if (created.value > now + (this.#options.clockSkewSeconds ?? 300)) fail("signature created in the future");
    const expires = params.params.get("expires");
    if (expires && (expires.type !== "integer" || expires.value < now)) fail("signature expired");
    const algParam = params.params.get("alg");
    if (algParam && algParam.type !== "string") fail("signature parameter 'alg' must be a string");

    // 4. keyid → storage identifier
    let keyUrl: URL;
    try {
      keyUrl = new URL(keyid);
    } catch {
      return fail(`keyid ${keyid} is not a URL`);
    }
    if (!keyUrl.hash || keyUrl.hash === "#") fail(`keyid ${keyid} has no fragment`);
    const storageId = keyUrl.href.slice(0, keyUrl.href.length - keyUrl.hash.length);
    const trusted = this.#options.trustedStorages;
    if (trusted && !trusted.some((t) => new URL(t).href === storageId)) fail(`storage ${storageId} is not trusted`);

    const base = signatureBase(params, method, target, headers);
    let { description, cached } = await this.#description(storageId, false);
    for (;;) {
      // 6. Verification method referenced from authentication
      const vm = description.verificationMethod(keyUrl.href);
      if (!vm) {
        if (cached) {
          ({ description, cached } = await this.#description(storageId, true));
          continue;
        }
        fail(`verification method ${keyid} not found in the storage description`);
      }
      if (!description.isAuthenticationKey(keyUrl.href)) fail(`key ${keyid} is not authorized for authentication`);
      if (!vm.publicKeyJwk) fail(`verification method ${keyid} has no publicKeyJwk`);
      const key = keyMaterial(vm.publicKeyJwk);
      if (algParam && algParam.type === "string" && algParam.value !== key.algorithm) {
        fail(`alg ${algParam.value} does not match the ${key.algorithm} key`);
      }
      // 8. Signature
      let ok: boolean;
      try {
        ok = await verifySignature(key, signature, base);
      } catch (e) {
        ok = false;
        if (!cached) fail("signature verification failed", e);
      }
      if (!ok) {
        if (cached) {
          ({ description, cached } = await this.#description(storageId, true));
          continue;
        }
        fail("signature mismatch");
      }
      break;
    }

    // 9. Notification storage must match the signer
    let notification: Notification;
    try {
      notification = parseNotification(body);
    } catch (e) {
      return fail("body is not a valid notification", e);
    }
    let notifiedStorage = notification.storage;
    try {
      notifiedStorage = new URL(notification.storage).href;
    } catch {
      // compared verbatim below
    }
    if (notifiedStorage !== storageId) {
      fail(`notification storage ${notification.storage} does not match keyid storage ${storageId}`);
    }
    return { notification, keyid, storage: storageId, label };
  }
}
