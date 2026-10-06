// SPDX-License-Identifier: MIT
import { LwsType, Rel } from "../constants.js";
import { ProtocolError } from "../errors.js";
import { parseDateTime, resolveUrl } from "../util/http.js";
import { hasType, isObject, toStringList } from "../util/types.js";
import type { ResourceMetadata } from "./resource.js";

/** A member of a container listing (or of a search result page). */
export class ContainedResource {
  /** Absolute resource URL. */
  readonly id: string;
  /** Types as received (`DataResource`, `Container`, user-defined type IRIs…). */
  readonly types: string[];
  /** Media type (present for data resources). */
  readonly format: string | undefined;
  /** Size in bytes. */
  readonly size: number | undefined;
  /** Last modification time, when present and parseable. */
  readonly modified: Date | undefined;
  /** Last modification time exactly as received. */
  readonly modifiedRaw: string | undefined;
  /** The raw JSON object. */
  readonly raw: Readonly<Record<string, unknown>>;

  constructor(raw: Record<string, unknown>, base: string) {
    if (typeof raw["id"] !== "string") throw new ProtocolError("contained resource without an id");
    this.raw = raw;
    this.id = resolveUrl(raw["id"], base);
    this.types = toStringList(raw["type"]);
    this.format = typeof raw["format"] === "string" ? raw["format"] : undefined;
    this.size = typeof raw["size"] === "number" ? raw["size"] : undefined;
    this.modifiedRaw = typeof raw["modified"] === "string" ? raw["modified"] : undefined;
    this.modified = parseDateTime(raw["modified"]);
  }

  isContainer(): boolean {
    return hasType(this.types, LwsType.CONTAINER);
  }
  isDataResource(): boolean {
    return hasType(this.types, LwsType.DATA_RESOURCE);
  }
  hasType(type: string): boolean {
    return hasType(this.types, type);
  }
}

/** Pagination links of a page (absolute URLs). */
export interface PageLinks {
  readonly first: string | undefined;
  readonly next: string | undefined;
  readonly prev: string | undefined;
  readonly last: string | undefined;
}

/** One page of a container listing (`application/lws+json`). */
export class ContainerPage implements PageLinks {
  /** Absolute container URL (the page URL when the body has no `id`). */
  readonly id: string;
  /** Types as received (`Container`, or `ContainerPage` for search results). */
  readonly types: string[];
  /** Total number of members visible to the client (may be approximate). */
  readonly totalItems: number | undefined;
  /** Members on this page. */
  readonly items: readonly ContainedResource[];
  readonly first: string | undefined;
  readonly next: string | undefined;
  readonly prev: string | undefined;
  readonly last: string | undefined;
  /** Response metadata (ETag, links…). */
  readonly metadata: ResourceMetadata;
  /** The raw JSON document. */
  readonly raw: Readonly<Record<string, unknown>>;

  constructor(json: unknown, metadata: ResourceMetadata) {
    if (!isObject(json)) throw new ProtocolError("container representation is not a JSON object");
    const base = metadata.url;
    this.raw = json;
    this.metadata = metadata;
    this.id = typeof json["id"] === "string" ? resolveUrl(json["id"], base) : base;
    this.types = toStringList(json["type"]);
    this.totalItems = typeof json["totalItems"] === "number" ? json["totalItems"] : undefined;
    const items = json["items"] ?? [];
    if (!Array.isArray(items)) throw new ProtocolError("container 'items' is not an array");
    this.items = items.filter(isObject).map((i) => new ContainedResource(i, base));
    this.first = metadata.link(Rel.FIRST)?.href;
    this.next = metadata.link(Rel.NEXT)?.href;
    this.prev = metadata.link(Rel.PREV)?.href;
    this.last = metadata.link(Rel.LAST)?.href;
  }

  /** True when the body or the `rel="type"` links identify a Container. */
  isContainer(): boolean {
    return hasType(this.types, LwsType.CONTAINER) || this.metadata.isContainer();
  }

  /** The container's ETag. */
  get etag(): string | undefined {
    return this.metadata.etag;
  }

  /** The container's linkset URL. */
  get linkset(): string | undefined {
    return this.metadata.linkset;
  }

  /** The parent container URL. */
  get parent(): string | undefined {
    return this.metadata.parent;
  }

  /** The storage URL. */
  get storage(): string | undefined {
    return this.metadata.storage;
  }
}

/** A Type Search result page (same shape as a container page, type `ContainerPage`). */
export type SearchPage = ContainerPage;
