// SPDX-License-Identifier: MIT
// In-memory containment hierarchy for the storage root. Container names end with "/".

import { randomUUID } from "node:crypto";
import { makeEtag, mediaTypeOf, normalizeRel, STRUCTURAL_RELS, TYPE_CONTAINER, TYPE_DATA_RESOURCE } from "./util.mjs";

export const ROOT_PATH = "/root/";
const INTRINSIC = new Set([TYPE_CONTAINER, TYPE_DATA_RESOURCE]);

export class Resource {
  constructor({ name, isContainer, parent = null, contentType = null, body = Buffer.alloc(0) }) {
    this.name = name;
    this.isContainer = isContainer;
    this.parent = parent;
    this.children = isContainer ? new Map() : null;
    this.contentType = isContainer ? null : contentType || "application/octet-stream";
    this.body = isContainer ? Buffer.alloc(0) : body;
    /** User-managed metadata: relation -> array of RFC 9264 target objects. */
    this.links = {};
    this.modified = new Date();
    this.linksetModified = this.modified;
    this.refreshEtag();
    this.refreshLinksetEtag();
  }

  get path() {
    return this.parent ? this.parent.path + this.name : ROOT_PATH;
  }

  get linksetPath() {
    return `${this.path}.meta`;
  }

  refreshEtag() {
    this.etag = this.isContainer ? null : makeEtag(this.contentType, this.body);
  }

  refreshLinksetEtag() {
    this.linksetEtag = makeEtag(JSON.stringify(this.links));
  }

  setContent(contentType, body) {
    this.contentType = contentType || this.contentType;
    this.body = body;
    this.modified = new Date();
    this.refreshEtag();
  }

  setLinks(links) {
    this.links = links;
    this.linksetModified = new Date();
    this.refreshLinksetEtag();
  }

  /** User-declared types (rel="type" metadata), resolved to absolute IRIs, intrinsic classes excluded. */
  userTypes(base) {
    const out = [];
    for (const t of this.links.type ?? []) {
      try {
        const iri = new URL(t.href, base + this.path).href;
        if (!INTRINSIC.has(iri) && !out.includes(iri)) out.push(iri);
      } catch {
        // ignore unresolvable targets
      }
    }
    return out;
  }

  /** All types used for indexing and notifications: the intrinsic LWS class plus user types. */
  allTypes(base) {
    return [this.isContainer ? TYPE_CONTAINER : TYPE_DATA_RESOURCE, ...this.userTypes(base)];
  }

  /** Absolute targets of a descriptive (indexable) relation. */
  relationTargets(rel, base) {
    const key = normalizeRel(rel);
    const out = new Set();
    if (key === "type" || STRUCTURAL_RELS.has(key)) return out;
    for (const [r, targets] of Object.entries(this.links)) {
      if (normalizeRel(r) !== key) continue;
      for (const t of targets) {
        try {
          out.add(new URL(t.href, base + this.path).href);
        } catch {
          // ignore
        }
      }
    }
    return out;
  }

  /** Contained-resource description used in container listings and search results. */
  describe(base, { absolute = false } = {}) {
    const intrinsic = this.isContainer ? "Container" : "DataResource";
    const user = this.userTypes(base);
    const item = { type: user.length ? [intrinsic, ...user] : intrinsic, id: absolute ? base + this.path : this.path };
    if (!this.isContainer) {
      item.format = mediaTypeOf(this.contentType);
      item.size = this.body.length;
    }
    item.modified = this.modified.toISOString();
    return item;
  }
}

/** Sanitises an RFC 5023 Slug (percent-encoded UTF-8) into a safe path segment. */
export function sanitizeSlug(raw) {
  if (raw === undefined || raw === null) return null;
  let s = String(raw).trim();
  try {
    s = decodeURIComponent(s);
  } catch {
    // keep the raw value
  }
  s = s
    .normalize("NFKC")
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^[.-]+/, "")
    .replace(/-+$/, "");
  if (s.toLowerCase().endsWith(".meta")) s = `${s.slice(0, -5)}-meta`;
  s = s.slice(0, 100);
  return s || null;
}

export class Store {
  constructor() {
    this.root = new Resource({ name: "root/", isContainer: true });
  }

  /** Finds the resource for a URL path, or null. */
  resolve(path) {
    if (!path.startsWith(ROOT_PATH)) return null;
    let node = this.root;
    let rest = path.slice(ROOT_PATH.length);
    while (rest.length) {
      if (!node.isContainer) return null;
      const slash = rest.indexOf("/");
      const name = slash >= 0 ? rest.slice(0, slash + 1) : rest;
      rest = slash >= 0 ? rest.slice(slash + 1) : "";
      if (name === "/") return null;
      node = node.children.get(name);
      if (!node) return null;
    }
    return node;
  }

  *walk(node = this.root) {
    yield node;
    if (node.isContainer) for (const child of node.children.values()) yield* this.walk(child);
  }

  #taken(container, base) {
    return container.children.has(base) || container.children.has(`${base}/`);
  }

  uniqueName(container, slug, isContainer) {
    let base = slug ?? randomUUID();
    if (this.#taken(container, base)) {
      const dot = isContainer ? -1 : base.lastIndexOf(".");
      const stem = dot > 0 ? base.slice(0, dot) : base;
      const ext = dot > 0 ? base.slice(dot) : "";
      let i = 1;
      while (this.#taken(container, `${stem}-${i}${ext}`)) i++;
      base = `${stem}-${i}${ext}`;
    }
    return isContainer ? `${base}/` : base;
  }

  create(container, { slug, isContainer, contentType, body, links }) {
    const name = this.uniqueName(container, slug, isContainer);
    const resource = new Resource({ name, isContainer, parent: container, contentType, body });
    if (links) resource.setLinks(links);
    container.children.set(name, resource);
    container.modified = new Date();
    return resource;
  }

  /** Removes a resource (and, for containers, everything below it). Returns removed resources, deepest first. */
  remove(resource) {
    const removed = [];
    const collect = (node) => {
      if (node.isContainer) for (const child of node.children.values()) collect(child);
      removed.push(node);
    };
    collect(resource);
    resource.parent.children.delete(resource.name);
    resource.parent.modified = new Date();
    return removed;
  }
}
