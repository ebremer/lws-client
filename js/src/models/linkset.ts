// SPDX-License-Identifier: MIT
// RFC 9264 linkset documents (application/linkset+json).
import { ProtocolError } from "../errors.js";
import { normalizeRel } from "../http/link.js";
import { isObject } from "../util/types.js";
import type { ResourceMetadata } from "./resource.js";

/** A link target object: `href` plus target attributes (`type`, `title`, `hreflang`, `title*`, …). */
export interface LinkTarget {
  href: string;
  /** Target attributes other than `href`, kept as raw JSON values. */
  attributes: Record<string, unknown>;
}

/** One link context object: an anchor and its relations. */
export interface LinkContext {
  anchor: string | undefined;
  /** Ordered relation type → targets. */
  relations: Map<string, LinkTarget[]>;
}

/** A flattened linkset link. */
export interface LinksetLink {
  anchor: string | undefined;
  rel: string;
  href: string;
  attributes: Record<string, unknown>;
}

/** A mutable, lossless model of an `application/linkset+json` document. */
export class Linkset {
  readonly contexts: LinkContext[];

  constructor(contexts: LinkContext[] = []) {
    this.contexts = contexts;
  }

  /** Parse a linkset JSON document. */
  static parse(json: unknown): Linkset {
    const doc = typeof json === "string" ? (JSON.parse(json) as unknown) : json;
    if (!isObject(doc) || !Array.isArray(doc["linkset"])) {
      throw new ProtocolError("linkset document must be an object with a 'linkset' array");
    }
    const contexts = doc["linkset"].filter(isObject).map((ctx): LinkContext => {
      const relations = new Map<string, LinkTarget[]>();
      for (const [key, value] of Object.entries(ctx)) {
        if (key === "anchor" || !Array.isArray(value)) continue;
        relations.set(
          key,
          value.filter(isObject).map((t) => {
            const { href, ...attributes } = t;
            return { href: typeof href === "string" ? href : "", attributes };
          }),
        );
      }
      return { anchor: typeof ctx["anchor"] === "string" ? ctx["anchor"] : undefined, relations };
    });
    return new Linkset(contexts);
  }

  /** The JSON representation (round-trips everything that was parsed). */
  toJSON(): { linkset: Record<string, unknown>[] } {
    return {
      linkset: this.contexts.map((ctx) => {
        const out: Record<string, unknown> = {};
        if (ctx.anchor !== undefined) out["anchor"] = ctx.anchor;
        for (const [rel, targets] of ctx.relations) {
          out[rel] = targets.map((t) => ({ href: t.href, ...t.attributes }));
        }
        return out;
      }),
    };
  }

  /** A deep copy. */
  clone(): Linkset {
    return Linkset.parse(JSON.parse(JSON.stringify(this.toJSON())));
  }

  /** The context object for an anchor (the first context when `anchor` is omitted). */
  context(anchor?: string): LinkContext | undefined {
    return anchor === undefined ? this.contexts[0] : this.contexts.find((c) => c.anchor === anchor);
  }

  /** All links flattened (optionally only those with relation `rel`). */
  links(rel?: string): LinksetLink[] {
    const out: LinksetLink[] = [];
    for (const ctx of this.contexts) {
      for (const [r, targets] of ctx.relations) {
        if (rel !== undefined && !sameRel(r, rel)) continue;
        for (const t of targets) out.push({ anchor: ctx.anchor, rel: r, href: t.href, attributes: t.attributes });
      }
    }
    return out;
  }

  /** Targets of relation `rel` (optionally restricted to one anchor). */
  targets(rel: string, anchor?: string): LinkTarget[] {
    return this.contexts
      .filter((c) => anchor === undefined || c.anchor === anchor)
      .flatMap((c) => [...c.relations].filter(([r]) => sameRel(r, rel)).flatMap(([, t]) => t));
  }

  /** Add a link (creating the context if needed). Returns `this`. */
  add(anchor: string, rel: string, href: string, attributes: Record<string, unknown> = {}): this {
    let ctx = this.contexts.find((c) => c.anchor === anchor);
    if (!ctx) {
      ctx = { anchor, relations: new Map() };
      this.contexts.push(ctx);
    }
    const key = [...ctx.relations.keys()].find((r) => sameRel(r, rel)) ?? rel;
    const targets = ctx.relations.get(key) ?? [];
    targets.push({ href, attributes });
    ctx.relations.set(key, targets);
    return this;
  }

  /** Remove links of `rel` for `anchor` (only targets equal to `href` when given). Returns the number removed. */
  remove(anchor: string, rel: string, href?: string): number {
    let removed = 0;
    for (const ctx of this.contexts.filter((c) => c.anchor === anchor)) {
      for (const [r, targets] of [...ctx.relations]) {
        if (!sameRel(r, rel)) continue;
        const kept = targets.filter((t) => href !== undefined && t.href !== href);
        removed += targets.length - kept.length;
        if (kept.length) ctx.relations.set(r, kept);
        else ctx.relations.delete(r);
      }
    }
    return removed;
  }
}

function sameRel(a: string, b: string): boolean {
  return normalizeRel(a) === normalizeRel(b);
}

/** A retrieved linkset resource. */
export interface LinksetDocument {
  /** URL of the linkset resource (use it with `updateLinkset` / `patchLinkset`). */
  url: string;
  /** ETag of the linkset resource (use it for `ifMatch`). */
  etag: string | undefined;
  linkset: Linkset;
  /** Methods allowed on the linkset resource. */
  allow: string[];
  /** Patch formats accepted by the linkset resource. */
  acceptPatch: string[];
  metadata: ResourceMetadata;
}
