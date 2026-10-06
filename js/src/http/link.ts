// SPDX-License-Identifier: MIT
// RFC 8288 Web Linking: Link header parsing and serialisation.
import { isAbsoluteIri } from "../util/types.js";
import { resolveUrl, type UrlLike } from "../util/http.js";

/** A link to use in a request (e.g. user-managed metadata on create/update). */
export interface LinkInit {
  /** Link target. */
  href: string | URL;
  /** Relation type. */
  rel: string;
  /** Additional target attributes (`type`, `title`, `anchor`, …). */
  params?: Record<string, string>;
}

/** A parsed link: one relation type, an absolute target and its parameters. */
export class Link {
  /** Absolute target URI (resolved against the request URL). */
  readonly href: string;
  /** Relation type (registered types lower-cased; extension URIs verbatim). */
  readonly rel: string;
  /** Target attributes with lower-cased names (excluding `rel`); valueless parameters are `""`. */
  readonly params: Readonly<Record<string, string>>;
  readonly #base: string | undefined;

  constructor(href: string, rel: string, params: Record<string, string> = {}, base?: string) {
    this.href = href;
    this.rel = rel;
    this.params = params;
    this.#base = base;
  }

  /** The `type` target attribute (a media type hint), if present. */
  get type(): string | undefined {
    return this.params["type"];
  }

  /** The link context: the `anchor` parameter resolved against the request URL, if present. */
  get anchor(): string | undefined {
    const a = this.params["anchor"];
    return a === undefined ? undefined : resolveUrl(a, this.#base);
  }

  /** Serialise as a Link header value. */
  toString(): string {
    return formatLink(this);
  }
}

const WS = /[ \t\r\n]/;

/** Normalise a relation type: lower-case registered names, keep extension URIs. */
export function normalizeRel(rel: string): string {
  return isAbsoluteIri(rel) ? rel : rel.toLowerCase();
}

/**
 * Parse one or more `Link` header field values. Commas inside `<…>` or quoted
 * strings do not split; a `rel` with several values yields one link per value.
 * Relative targets are resolved against `base`.
 */
export function parseLinkHeader(values: string | readonly string[] | null | undefined, base?: UrlLike): Link[] {
  if (values === null || values === undefined) return [];
  const list = typeof values === "string" ? [values] : values;
  const baseHref = base === undefined ? undefined : typeof base === "string" ? base : base.href;
  const links: Link[] = [];
  for (const value of list) parseInto(value, baseHref, links);
  return links;
}

function parseInto(s: string, base: string | undefined, out: Link[]): void {
  let i = 0;
  const n = s.length;
  const skipWs = (): void => {
    while (i < n && WS.test(s[i]!)) i++;
  };
  while (i < n) {
    while (i < n && (WS.test(s[i]!) || s[i] === ",")) i++;
    if (i >= n) break;
    if (s[i] !== "<") {
      // Malformed link-value: skip to the next top-level comma.
      skipToComma();
      continue;
    }
    const end = s.indexOf(">", i + 1);
    if (end < 0) break;
    const target = s.slice(i + 1, end).trim();
    i = end + 1;
    const params: Record<string, string> = {};
    let rel: string | undefined;
    for (;;) {
      skipWs();
      if (i >= n) break;
      if (s[i] === ",") {
        i++;
        break;
      }
      if (s[i] !== ";") {
        skipToComma();
        break;
      }
      i++;
      skipWs();
      let name = "";
      while (i < n && !WS.test(s[i]!) && s[i] !== "=" && s[i] !== ";" && s[i] !== ",") name += s[i++];
      name = name.toLowerCase();
      skipWs();
      let value = "";
      if (s[i] === "=") {
        i++;
        skipWs();
        if (s[i] === '"') value = readQuoted();
        else while (i < n && !WS.test(s[i]!) && s[i] !== ";" && s[i] !== ",") value += s[i++];
      }
      if (!name) continue;
      if (name === "rel") {
        if (rel === undefined) rel = value;
      } else if (!(name in params)) {
        params[name] = value;
      }
    }
    if (rel === undefined) continue;
    const resolved = resolveUrl(target, base);
    for (const r of rel.split(/[ \t]+/).filter(Boolean)) {
      out.push(new Link(resolved, normalizeRel(r), { ...params }, base));
    }
  }

  function readQuoted(): string {
    let value = "";
    i++; // opening quote
    while (i < n && s[i] !== '"') {
      if (s[i] === "\\" && i + 1 < n) i++;
      value += s[i++];
    }
    i++; // closing quote
    return value;
  }

  function skipToComma(): void {
    let quoted = false;
    let angle = false;
    while (i < n) {
      const c = s[i];
      if (c === "\\" && quoted) i++;
      else if (c === '"') quoted = !quoted;
      else if (c === "<" && !quoted) angle = true;
      else if (c === ">" && !quoted) angle = false;
      else if (c === "," && !quoted && !angle) return;
      i++;
    }
  }
}

function quote(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** Serialise a link as a Link header value: `<href>; rel="rel"; name="value"`. */
export function formatLink(link: LinkInit | Link): string {
  const target = typeof link.href === "string" ? link.href : link.href.href;
  let out = `<${target}>; rel=${quote(link.rel)}`;
  for (const [name, value] of Object.entries(link.params ?? {})) {
    if (name.toLowerCase() === "rel") continue;
    out += value === "" ? `; ${name}` : `; ${name}=${quote(value)}`;
  }
  return out;
}

/** Find the first link with the given relation type. */
export function findLink(links: readonly Link[], rel: string): Link | undefined {
  const r = normalizeRel(rel);
  return links.find((l) => l.rel === r);
}
