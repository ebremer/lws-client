// SPDX-License-Identifier: MIT
// Small HTTP helpers shared by the client and the models.

/** URL inputs accepted by the client. */
export type UrlLike = string | URL;

/** Resolve `ref` against `base`; returns `ref` unchanged when it cannot be resolved. */
export function resolveUrl(ref: string, base?: UrlLike): string {
  try {
    return new URL(ref, base).href;
  } catch {
    return ref;
  }
}

/** Convert a URL-like value to its string href. */
export function href(url: UrlLike): string {
  return typeof url === "string" ? new URL(url).href : url.href;
}

/** Lower-cased media type essence (`type/subtype`, parameters removed). */
export function mediaTypeEssence(contentType: string | null | undefined): string | undefined {
  if (!contentType) return undefined;
  const essence = contentType.split(";")[0]?.trim().toLowerCase();
  return essence ? essence : undefined;
}

/** Media type parameter value (e.g. `charset`). */
export function mediaTypeParam(contentType: string | null | undefined, name: string): string | undefined {
  if (!contentType) return undefined;
  for (const part of contentType.split(";").slice(1)) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim().toLowerCase() === name.toLowerCase()) {
      return part.slice(eq + 1).trim().replace(/^"(.*)"$/, "$1");
    }
  }
  return undefined;
}

/** True for `application/json` and any `+json` structured syntax suffix. */
export function isJsonMediaType(contentType: string | null | undefined): boolean {
  const e = mediaTypeEssence(contentType);
  return e !== undefined && (e === "application/json" || e.endsWith("+json"));
}

/**
 * Split a comma-separated header list (Allow, Accept-Patch, Accept-Query, …),
 * respecting quoted strings, trimming members and dropping empty ones.
 */
export function splitHeaderList(value: string | null | undefined): string[] {
  if (!value) return [];
  const out: string[] = [];
  let current = "";
  let quoted = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === '"' && value[i - 1] !== "\\") quoted = !quoted;
    if (c === "," && !quoted) {
      if (current.trim()) out.push(current.trim());
      current = "";
    } else {
      current += c;
    }
  }
  if (current.trim()) out.push(current.trim());
  return out;
}

/** Format a date-time as RFC 3339 without fractional seconds when they are zero. */
export function formatDateTime(value: Date | string): string {
  if (typeof value === "string") return value;
  return value.toISOString().replace(".000Z", "Z");
}

/** Parse an RFC 3339 / ISO 8601 date-time; `undefined` when absent or unparseable. */
export function parseDateTime(value: unknown): Date | undefined {
  if (typeof value !== "string" || value.trim() === "") return undefined;
  if (!/^\d{4}-\d{2}-\d{2}/.test(value)) return undefined;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? undefined : d;
}

/** Hosts for which plain `http` is acceptable (loopback). */
export function isLoopbackHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  return h === "localhost" || h === "127.0.0.1" || h === "[::1]" || h === "::1" || h.endsWith(".localhost");
}

/** Percent-encode a `Slug` value (RFC 5023 §9.7): non-ASCII, control characters and `%`. */
export function encodeSlug(slug: string): string {
  let out = "";
  for (const byte of new TextEncoder().encode(slug)) {
    if (byte < 0x20 || byte > 0x7e || byte === 0x25) out += "%" + byte.toString(16).toUpperCase().padStart(2, "0");
    else out += String.fromCharCode(byte);
  }
  return out;
}
