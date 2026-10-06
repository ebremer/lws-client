// SPDX-License-Identifier: MIT
import { LwsType, Rel } from "../constants.js";
import { Link, normalizeRel, parseLinkHeader } from "../http/link.js";
import { mediaTypeEssence, mediaTypeParam, splitHeaderList } from "../util/http.js";
import { hasType } from "../util/types.js";

/** Read a header that may be repeated (fetch joins repeats with ", "). */
function linkHeaderValues(headers: Headers): string[] {
  const value = headers.get("link");
  return value === null ? [] : [value];
}

/**
 * Metadata of a Storage Resource, parsed from response headers
 * (ETag, Last-Modified, Content-Type, Link, Allow, Accept-Patch).
 */
export class ResourceMetadata {
  /** Final (absolute) URL of the resource. */
  readonly url: string;
  /** HTTP status of the response. */
  readonly status: number;
  /** Raw response headers. */
  readonly headers: Headers;
  readonly #links: Link[];

  constructor(url: string, status: number, headers: Headers) {
    this.url = url;
    this.status = status;
    this.headers = headers;
    this.#links = parseLinkHeader(linkHeaderValues(headers), url);
  }

  /** Build from a fetch Response (falls back to `requestUrl` for constructed responses). */
  static fromResponse(response: Response, requestUrl: string): ResourceMetadata {
    return new ResourceMetadata(response.url || requestUrl, response.status, response.headers);
  }

  /** Entity tag exactly as sent (including quotes and `W/`); echo it verbatim in `If-Match`. */
  get etag(): string | undefined {
    return this.headers.get("etag") ?? undefined;
  }

  /** `Last-Modified` as a Date. */
  get lastModified(): Date | undefined {
    const v = this.headers.get("last-modified");
    if (!v) return undefined;
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? undefined : d;
  }

  /** Full `Content-Type` header value. */
  get contentType(): string | undefined {
    return this.headers.get("content-type") ?? undefined;
  }

  /** Media type essence of `Content-Type` (lower-case, no parameters). */
  get mediaType(): string | undefined {
    return mediaTypeEssence(this.headers.get("content-type"));
  }

  /** `Content-Length`, if present. */
  get contentLength(): number | undefined {
    const v = this.headers.get("content-length");
    if (v === null) return undefined;
    const n = Number.parseInt(v, 10);
    return Number.isNaN(n) ? undefined : n;
  }

  /** All links, or only those with relation type `rel`. */
  links(rel?: string): Link[] {
    if (rel === undefined) return [...this.#links];
    const r = normalizeRel(rel);
    return this.#links.filter((l) => l.rel === r);
  }

  /** The first link with relation type `rel`. */
  link(rel: string): Link | undefined {
    const r = normalizeRel(rel);
    return this.#links.find((l) => l.rel === r);
  }

  /** The linkset (metadata) resource URL (`rel="linkset"`). */
  get linkset(): string | undefined {
    return this.link(Rel.LINKSET)?.href;
  }

  /** The parent container URL (`rel="up"`). */
  get parent(): string | undefined {
    return this.link(Rel.UP)?.href;
  }

  /** The storage URL (`rel="https://www.w3.org/ns/lws#storage"`). */
  get storage(): string | undefined {
    return this.link(Rel.STORAGE)?.href;
  }

  /** Targets of `rel="type"` links. */
  get types(): string[] {
    return this.links(Rel.TYPE).map((l) => l.href);
  }

  /** True when a `rel="type"` link identifies an LWS Container. */
  isContainer(): boolean {
    return hasType(this.types, LwsType.CONTAINER);
  }

  /** True when a `rel="type"` link identifies an LWS DataResource. */
  isDataResource(): boolean {
    return hasType(this.types, LwsType.DATA_RESOURCE);
  }

  /** True when the resource declares `type` (LWS term aware). */
  hasType(type: string): boolean {
    return hasType(this.types, type);
  }

  /** Methods listed in `Allow`. */
  get allow(): string[] {
    return splitHeaderList(this.headers.get("allow")).map((m) => m.toUpperCase());
  }

  /** Patch media types listed in `Accept-Patch`. */
  get acceptPatch(): string[] {
    return splitHeaderList(this.headers.get("accept-patch")).map((m) => mediaTypeEssence(m) ?? m);
  }
}

/** A read resource: metadata plus its representation. */
export class Resource extends ResourceMetadata {
  /** True for a `304 Not Modified` answer to a conditional read (the body is empty). */
  readonly notModified: boolean;
  readonly #response: Response;
  #buffer: Promise<Uint8Array<ArrayBuffer>> | undefined;

  constructor(url: string, response: Response) {
    super(url, response.status, response.headers);
    this.#response = response;
    this.notModified = response.status === 304;
  }

  /** `Content-Range` of a `206 Partial Content` response. */
  get contentRange(): string | undefined {
    return this.headers.get("content-range") ?? undefined;
  }

  /** True for a `206 Partial Content` response. */
  get partial(): boolean {
    return this.status === 206;
  }

  /**
   * The raw body stream, for streaming large representations. Do not combine
   * with {@link bytes}, {@link text}, {@link json} or {@link blob}.
   */
  get body(): ReadableStream<Uint8Array> | null {
    return this.#response.body;
  }

  /** The body as bytes (buffered once; may be called repeatedly). */
  bytes(): Promise<Uint8Array<ArrayBuffer>> {
    this.#buffer ??= this.#response.arrayBuffer().then((b) => new Uint8Array(b));
    return this.#buffer;
  }

  /** The body decoded as text using the Content-Type charset (default UTF-8). */
  async text(): Promise<string> {
    const bytes = await this.bytes();
    const charset = mediaTypeParam(this.contentType, "charset") ?? "utf-8";
    let decoder: TextDecoder;
    try {
      decoder = new TextDecoder(charset);
    } catch {
      decoder = new TextDecoder();
    }
    return decoder.decode(bytes);
  }

  /** The body parsed as JSON. */
  async json<T = unknown>(): Promise<T> {
    return JSON.parse(await this.text()) as T;
  }

  /** The body as a Blob typed with the response media type. */
  async blob(): Promise<Blob> {
    return new Blob([await this.bytes()], { type: this.contentType ?? "" });
  }
}
