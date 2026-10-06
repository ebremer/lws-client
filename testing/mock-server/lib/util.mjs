// SPDX-License-Identifier: MIT
// Shared HTTP helpers for the LWS mock server: constants, errors, content negotiation,
// Link / ETag / Prefer header handling and response writing.

import { createHash } from "node:crypto";
import { STATUS_CODES } from "node:http";

export const LWS_NS = "https://www.w3.org/ns/lws#";
export const LWS_CONTEXT = "https://www.w3.org/ns/lws/v1";
export const CID_CONTEXT = "https://www.w3.org/ns/cid/v1";
export const AS_CONTEXT = "https://www.w3.org/ns/activitystreams";
export const TYPE_CONTAINER = `${LWS_NS}Container`;
export const TYPE_DATA_RESOURCE = `${LWS_NS}DataResource`;
export const REL_STORAGE = `${LWS_NS}storage`;

export const MEDIA = Object.freeze({
  LWS_JSON: "application/lws+json",
  LWS_CID: "application/lws+cid",
  LD_JSON: "application/ld+json",
  JSON: "application/json",
  LINKSET_JSON: "application/linkset+json",
  JSON_PATCH: "application/json-patch+json",
  LWS_QUERY_JSON: "application/lws-query+json",
  PROBLEM_JSON: "application/problem+json",
  FORM: "application/x-www-form-urlencoded",
});

/** Media types that are equivalent for container representations (lws10-core "Media Type Equivalence"). */
export const CONTAINER_MEDIA = [MEDIA.LWS_JSON, MEDIA.LD_JSON, MEDIA.JSON];

/** Relations managed by the server that clients can neither set nor have indexed. */
export const STRUCTURAL_RELS = new Set(["up", "linkset", REL_STORAGE, "first", "last", "next", "prev", "items", "anchor"]);

export class HttpError extends Error {
  /**
   * @param {number} status
   * @param {string} [detail]
   * @param {{headers?: Record<string, string|string[]>, title?: string, type?: string, extra?: object}} [options]
   */
  constructor(status, detail, { headers = {}, title, type, extra } = {}) {
    super(detail ?? STATUS_CODES[status] ?? "Error");
    this.status = status;
    this.detail = detail;
    this.headers = headers;
    this.title = title;
    this.type = type;
    this.extra = extra;
  }
}

export const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
export const asArray = (v) => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);
export const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

export function makeEtag(...parts) {
  const h = createHash("sha256");
  for (const p of parts) {
    h.update(typeof p === "string" ? p : Buffer.from(p));
    h.update("\0");
  }
  return `"${h.digest("base64url").slice(0, 22)}"`;
}

export function mediaTypeOf(contentType) {
  return String(contentType ?? "").split(";")[0].trim().toLowerCase();
}

export function isJsonMedia(contentType) {
  const m = mediaTypeOf(contentType);
  return m === "application/json" || m.endsWith("+json");
}

/** RFC 3987 absolute IRI (scheme ":" hier-part), optionally with a fragment. */
export function isAbsoluteIri(value) {
  return (
    typeof value === "string" &&
    /^[A-Za-z][A-Za-z0-9+.-]*:[^\s<>"{}|\\^`\u0000-\u001f\u007f]*$/u.test(value) &&
    value.indexOf(":") < value.length - 1
  );
}

export function isHttpUrl(value) {
  if (typeof value !== "string") return false;
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

export function isoNow() {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// Generic header list splitting (respects quoted strings)
// ---------------------------------------------------------------------------

function splitOutsideQuotes(s, sep) {
  const out = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quoted) {
      cur += c;
      if (c === "\\" && i + 1 < s.length) cur += s[++i];
      else if (c === '"') quoted = false;
    } else if (c === '"') {
      quoted = true;
      cur += c;
    } else if (c === sep) {
      out.push(cur);
      cur = "";
    } else {
      cur += c;
    }
  }
  out.push(cur);
  return out;
}

function unquote(v) {
  v = v.trim();
  if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) {
    return v.slice(1, -1).replace(/\\(.)/g, "$1");
  }
  return v;
}

export function splitHeaderList(value) {
  if (value === undefined || value === null) return [];
  return splitOutsideQuotes(String(value), ",")
    .map((s) => s.trim())
    .filter(Boolean);
}

// ---------------------------------------------------------------------------
// Content negotiation
// ---------------------------------------------------------------------------

export function parseAccept(header) {
  const entries = [];
  splitHeaderList(header).forEach((part, index) => {
    const [range, ...rawParams] = splitOutsideQuotes(part, ";");
    const [type, subtype] = range.trim().toLowerCase().split("/");
    if (!type || !subtype) return;
    const params = {};
    let q = 1;
    for (const p of rawParams) {
      const eq = p.indexOf("=");
      if (eq < 0) continue;
      const k = p.slice(0, eq).trim().toLowerCase();
      const v = unquote(p.slice(eq + 1));
      if (k === "q") {
        q = Number(v);
        if (!Number.isFinite(q)) q = 0;
      } else {
        params[k] = v;
      }
    }
    entries.push({ type, subtype, params, q, index });
  });
  return entries;
}

/**
 * Picks the best of `available` (server preference order) for an Accept header.
 * Returns the chosen media type string (echoing an ld+json profile parameter when requested),
 * or null when nothing is acceptable. A missing/empty Accept yields the first available type.
 */
export function negotiate(acceptHeader, available) {
  const entries = parseAccept(acceptHeader);
  if (entries.length === 0) return available[0];
  let best = null;
  for (const media of available) {
    const [t, s] = media.split("/");
    let match = null;
    let spec = -1;
    for (const e of entries) {
      let sp;
      if (e.type === t && e.subtype === s) sp = 2;
      else if (e.type === t && e.subtype === "*") sp = 1;
      else if (e.type === "*" && e.subtype === "*") sp = 0;
      else continue;
      if (sp > spec) {
        spec = sp;
        match = e;
      }
    }
    if (!match || match.q <= 0) continue;
    if (!best || match.q > best.q || (match.q === best.q && spec > best.spec)) {
      best = { media, q: match.q, spec, entry: match };
    }
  }
  if (!best) return null;
  if (best.media === MEDIA.LD_JSON && best.spec === 2 && best.entry.params.profile) {
    return `${MEDIA.LD_JSON}; profile="${best.entry.params.profile}"`;
  }
  return best.media;
}

// ---------------------------------------------------------------------------
// Link header (RFC 8288)
// ---------------------------------------------------------------------------

/**
 * Parses Link header field value(s). Relative targets are resolved against `base`.
 * Returns [{href, rel, params}] with one entry per relation type.
 */
export function parseLinkHeader(header, base) {
  const links = [];
  if (header === undefined || header === null) return links;
  const s = Array.isArray(header) ? header.join(", ") : String(header);
  const n = s.length;
  let i = 0;
  const isWs = (c) => c === " " || c === "\t" || c === "\r" || c === "\n";
  const ws = () => {
    while (i < n && isWs(s[i])) i++;
  };
  const skipToComma = () => {
    let quoted = false;
    while (i < n) {
      const c = s[i];
      if (quoted) {
        if (c === "\\") i++;
        else if (c === '"') quoted = false;
      } else if (c === '"') quoted = true;
      else if (c === ",") break;
      i++;
    }
  };
  while (i < n) {
    ws();
    if (i >= n) break;
    if (s[i] === ",") {
      i++;
      continue;
    }
    if (s[i] !== "<") {
      skipToComma();
      continue;
    }
    const end = s.indexOf(">", i + 1);
    if (end < 0) break;
    const target = s.slice(i + 1, end).trim();
    i = end + 1;
    const params = {};
    for (;;) {
      ws();
      if (s[i] !== ";") break;
      i++;
      ws();
      let name = "";
      while (i < n && !isWs(s[i]) && s[i] !== "=" && s[i] !== ";" && s[i] !== ",") name += s[i++];
      name = name.toLowerCase();
      ws();
      let value = "";
      if (s[i] === "=") {
        i++;
        ws();
        if (s[i] === '"') {
          i++;
          while (i < n && s[i] !== '"') {
            if (s[i] === "\\" && i + 1 < n) i++;
            value += s[i++];
          }
          i++;
        } else {
          while (i < n && !isWs(s[i]) && s[i] !== ";" && s[i] !== ",") value += s[i++];
        }
      }
      if (name && !hasOwn(params, name)) params[name] = value;
    }
    ws();
    if (i < n && s[i] !== ",") skipToComma();
    let href;
    try {
      href = new URL(target, base).href;
    } catch {
      continue;
    }
    const rels = (params.rel ?? "").split(/\s+/).filter(Boolean);
    delete params.rel;
    for (const r of rels) links.push({ href, rel: normalizeRel(r), params: { ...params } });
  }
  return links;
}

/** Registered relation types are case-insensitive; extension relation URIs are kept verbatim. */
export function normalizeRel(rel) {
  return rel.includes(":") ? rel : rel.toLowerCase();
}

function quote(v) {
  return `"${String(v).replace(/[\\"]/g, "\\$&")}"`;
}

export function serializeLink(href, rel, params = {}) {
  let out = `<${href}>; rel=${quote(rel)}`;
  for (const [k, v] of Object.entries(params)) out += `; ${k}=${quote(v)}`;
  return out;
}

// ---------------------------------------------------------------------------
// Prefer (RFC 7240)
// ---------------------------------------------------------------------------

export function preferences(header) {
  const prefs = new Set();
  for (const part of splitHeaderList(header)) {
    const name = splitOutsideQuotes(part, ";")[0].split("=")[0].trim().toLowerCase();
    if (name) prefs.add(name);
  }
  return prefs;
}

// ---------------------------------------------------------------------------
// Conditional requests (RFC 9110 section 13)
// ---------------------------------------------------------------------------

export function parseEtagList(header) {
  if (header === undefined || header === null) return null;
  const v = String(header).trim();
  if (v === "*") return "*";
  const out = [];
  const re = /(W\/)?("[^"]*")/g;
  let m;
  while ((m = re.exec(v))) out.push({ weak: Boolean(m[1]), tag: m[2] });
  return out;
}

const opaque = (etag) => (etag ?? "").replace(/^W\//, "");

/** Returns true when a GET/HEAD should be answered with 304 Not Modified. */
export function isNotModified(req, etag, lastModified) {
  const inm = parseEtagList(req.headers["if-none-match"]);
  if (inm !== null) {
    if (inm === "*") return Boolean(etag);
    return inm.some((e) => e.tag === opaque(etag));
  }
  const ims = req.headers["if-modified-since"];
  if (ims && lastModified) {
    const since = Date.parse(ims);
    if (!Number.isNaN(since)) return Math.floor(lastModified.getTime() / 1000) <= Math.floor(since / 1000);
  }
  return false;
}

/** Evaluates If-Match / If-Unmodified-Since / If-None-Match for state-changing requests. */
export function checkPreconditions(req, { etag, lastModified, exists = true }) {
  const im = parseEtagList(req.headers["if-match"]);
  if (im !== null) {
    const ok =
      exists &&
      (im === "*" || im.some((e) => !e.weak && etag && !etag.startsWith("W/") && e.tag === etag));
    if (!ok) throw new HttpError(412, "If-Match precondition failed");
  } else if (req.headers["if-unmodified-since"] && lastModified) {
    const d = Date.parse(req.headers["if-unmodified-since"]);
    if (!Number.isNaN(d) && Math.floor(lastModified.getTime() / 1000) > Math.floor(d / 1000)) {
      throw new HttpError(412, "If-Unmodified-Since precondition failed");
    }
  }
  const inm = parseEtagList(req.headers["if-none-match"]);
  if (inm !== null && exists) {
    if (inm === "*" || inm.some((e) => e.tag === opaque(etag))) {
      throw new HttpError(412, "If-None-Match precondition failed");
    }
  }
}

// ---------------------------------------------------------------------------
// Request / response plumbing
// ---------------------------------------------------------------------------

export const MAX_BODY = 10 * 1024 * 1024;

export function readBody(req, limit = MAX_BODY) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers["content-length"]);
    if (Number.isFinite(declared) && declared > limit) {
      reject(new HttpError(413, `Request body exceeds ${limit} bytes`));
      req.resume();
      return;
    }
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new HttpError(413, `Request body exceeds ${limit} bytes`));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export function parseJsonBody(buffer, what = "request body") {
  try {
    return JSON.parse(buffer.toString("utf8"));
  } catch {
    throw new HttpError(400, `The ${what} is not valid JSON`);
  }
}

/**
 * Writes a response. `body` may be a Buffer, string, plain object (serialised as JSON) or null.
 * HEAD responses carry the Content-Length of the representation but no body.
 */
export function send(req, res, status, headers = {}, body = null) {
  let buf = null;
  if (body !== null && body !== undefined) {
    buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
  }
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined || v === null || (Array.isArray(v) && v.length === 0)) continue;
    if (k.toLowerCase() === "vary" && res.hasHeader("vary")) {
      const merged = new Set([...splitHeaderList(res.getHeader("vary")), ...splitHeaderList(v)]);
      res.setHeader("Vary", [...merged].join(", "));
      continue;
    }
    res.setHeader(k, v);
  }
  if (status === 204 || status === 304) {
    res.removeHeader("Content-Length");
    res.removeHeader("Content-Type");
    res.writeHead(status);
    res.end();
    return;
  }
  res.setHeader("Content-Length", buf ? buf.length : 0);
  res.writeHead(status);
  if (req.method === "HEAD" || !buf) res.end();
  else res.end(buf);
}

export function sendProblem(req, res, err) {
  const status = err.status ?? 500;
  const problem = {
    type: err.type ?? "about:blank",
    title: err.title ?? STATUS_CODES[status] ?? "Error",
    status,
    ...(err.detail ? { detail: err.detail } : {}),
    instance: req.url,
    ...(err.extra ?? {}),
  };
  send(req, res, status, { ...err.headers, "Content-Type": MEDIA.PROBLEM_JSON }, problem);
}
