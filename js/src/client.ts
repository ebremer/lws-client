// SPDX-License-Identifier: MIT
// LwsClient: the entry point of the library.
import type { AuthContext, Authenticator, AuthRequest } from "./auth/authenticator.js";
import { LWS_CONTEXT, LwsType, MediaType, Prefer, Rel, SUBSCRIPTION_WEBHOOK, VERSION } from "./constants.js";
import {
  errorFromResponse,
  HttpError,
  MethodNotAllowedError,
  NotImplementedError,
  ProtocolError,
} from "./errors.js";
import { formatLink, type LinkInit } from "./http/link.js";
import { JsonPatch, type JsonPatchOperation } from "./json-patch.js";
import { AccessGrant, AccessRequest, type AccessDocumentInit } from "./models/access.js";
import { ContainedResource, ContainerPage, type SearchPage } from "./models/container.js";
import { Linkset, type LinksetDocument } from "./models/linkset.js";
import { Subscription, type WebhookSubscriptionRequest } from "./models/notification.js";
import { Resource, ResourceMetadata } from "./models/resource.js";
import { Service, StorageDescription } from "./models/storage.js";
import { TypeIndexPage, TypeQuery } from "./models/type-index.js";
import {
  encodeSlug,
  formatDateTime,
  mediaTypeEssence,
  resolveUrl,
  splitHeaderList,
  type UrlLike,
} from "./util/http.js";
import { isObject } from "./util/types.js";

/** Options of {@link LwsClient}. */
export interface LwsClientOptions {
  /** fetch implementation (defaults to `globalThis.fetch`). Inject for testing, proxies or custom agents. */
  fetch?: typeof fetch;
  /** Authentication strategy (e.g. `TokenExchangeAuthenticator`). Anonymous when omitted. */
  authenticator?: Authenticator;
  /**
   * `User-Agent` header. Defaults to `lws-client-js/<version>` outside browsers;
   * browsers send their own (setting it would force CORS preflights). `null` disables it.
   */
  userAgent?: string | null;
  /** Headers added to every request. */
  headers?: HeadersInit;
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
}

/** Options accepted by every operation. */
export interface RequestOptions {
  /** Extra request headers. */
  headers?: HeadersInit;
  /** Abort the operation. */
  signal?: AbortSignal;
}

/** Byte ranges for {@link ReadOptions.range}. */
export type RangeSpec = string | { start: number; end?: number } | { suffix: number };

/** Options of {@link LwsClient.read}. */
export interface ReadOptions extends RequestOptions {
  /** `Accept` header (content negotiation). */
  accept?: string;
  /** Range request: `"bytes=0-99"`, `{ start, end? }` (inclusive) or `{ suffix }`. */
  range?: RangeSpec;
  /** Conditional read: answer 304 (`notModified`) when the ETag still matches. */
  ifNoneMatch?: string;
  /** Conditional read by date. */
  ifModifiedSince?: Date | string;
  /** `Prefer` header (e.g. link relation preferences). */
  prefer?: string;
}

/** Options of {@link LwsClient.create} and {@link LwsClient.createContainer}. */
export interface CreateOptions extends RequestOptions {
  /** Identity hint for the new resource name (sent as `Slug`). */
  slug?: string;
  /** User-managed metadata links. */
  links?: LinkInit[];
  /** Additional type IRIs (sent as `Link: <type>; rel="type"`). */
  types?: string[];
}

/** Options of {@link LwsClient.update} and {@link LwsClient.patch}. */
export interface UpdateOptions extends RequestOptions {
  /** Only update when the current ETag matches (optimistic concurrency). */
  ifMatch?: string;
  /** `If-None-Match` (e.g. `"*"`). */
  ifNoneMatch?: string;
  /** Links to send with the update (applied to the linkset only with `setLinkset`). */
  links?: LinkInit[];
  /** Update content and linkset atomically (`Prefer: set-linkset`). */
  setLinkset?: boolean;
}

/** Options of conditional metadata updates. */
export interface ConditionalOptions extends RequestOptions {
  ifMatch?: string;
}

/** Options of {@link LwsClient.delete}. */
export interface DeleteOptions extends RequestOptions {
  ifMatch?: string;
  /** Delete a container and everything in it (`Depth: infinity`). */
  recursive?: boolean;
}

/** A raw patch document in a format other than JSON Patch. */
export interface RawPatch {
  body: BodyInit;
  contentType: string;
}

/** Result of a create operation. */
export interface CreateResult {
  /** Absolute URL of the new resource. */
  location: string;
  /** Metadata from the `201` response (linkset, up, type links…). */
  metadata: ResourceMetadata;
}

/** Result of an update operation. */
export interface UpdateResult {
  status: number;
  /** New ETag, when the server returned one. */
  etag: string | undefined;
  metadata: ResourceMetadata;
}

/** A service given as its endpoint URL or as a {@link Service} from a storage description. */
export type ServiceRef = UrlLike | Service;

interface SendInit {
  method: string;
  url: string;
  headers?: Headers;
  body?: BodyInit | null;
}

const isBrowser = (): boolean => typeof (globalThis as { document?: unknown }).document !== "undefined";

function isReplayable(body: BodyInit | null | undefined): boolean {
  return !(typeof ReadableStream !== "undefined" && body instanceof ReadableStream);
}

function rangeHeader(range: RangeSpec): string {
  if (typeof range === "string") return range;
  if ("suffix" in range) return `bytes=-${range.suffix}`;
  return `bytes=${range.start}-${range.end ?? ""}`;
}

const endpointOf = (service: ServiceRef): string =>
  service instanceof Service ? service.serviceEndpoint : typeof service === "string" ? new URL(service).href : service.href;

const CONTAINER_MEDIA_TYPES = new Set([MediaType.LWS_JSON, MediaType.LD_JSON, MediaType.JSON]);

/**
 * A client for W3C Linked Web Storage servers.
 *
 * ```ts
 * const client = new LwsClient({ authenticator });
 * const storage = await client.discoverStorage("https://storage.example/alice/");
 * for await (const item of client.listContainer(storage.storageRoot())) console.log(item.id);
 * ```
 */
export class LwsClient {
  readonly #fetch: typeof fetch;
  readonly #authenticator: Authenticator | undefined;
  readonly #defaultHeaders: Headers;
  readonly #timeoutMs: number | undefined;

  constructor(options: LwsClientOptions = {}) {
    const f = options.fetch ?? globalThis.fetch;
    if (typeof f !== "function") throw new TypeError("no fetch implementation available; pass options.fetch");
    this.#fetch = options.fetch ? f : f.bind(globalThis);
    this.#authenticator = options.authenticator;
    this.#defaultHeaders = new Headers(options.headers);
    const ua = options.userAgent === undefined ? (isBrowser() ? null : `lws-client-js/${VERSION}`) : options.userAgent;
    if (ua) this.#defaultHeaders.set("user-agent", ua);
    this.#timeoutMs = options.timeoutMs;
  }

  /** The configured authenticator. */
  get authenticator(): Authenticator | undefined {
    return this.#authenticator;
  }

  // -------------------------------------------------------------------------
  // Transport
  // -------------------------------------------------------------------------

  #signal(opts: RequestOptions | undefined): AbortSignal | undefined {
    const signals: AbortSignal[] = [];
    if (opts?.signal) signals.push(opts.signal);
    if (this.#timeoutMs !== undefined && typeof AbortSignal.timeout === "function") {
      signals.push(AbortSignal.timeout(this.#timeoutMs));
    }
    if (signals.length <= 1) return signals[0];
    const any = (AbortSignal as unknown as { any?: (s: AbortSignal[]) => AbortSignal }).any;
    return any ? any(signals) : signals[0];
  }

  async #send(init: SendInit, opts: RequestOptions | undefined): Promise<Response> {
    const signal = this.#signal(opts);
    const auth = this.#authenticator;
    const ctx: AuthContext = { fetch: this.#fetch, signal };
    const replayable = isReplayable(init.body);
    if (auth && !replayable && auth.hasCredentials && !auth.hasCredentials(init.url)) {
      // Establish credentials before streaming a body that cannot be replayed.
      try {
        const pre = await this.#send({ method: "HEAD", url: init.url }, { signal } as RequestOptions);
        await pre.body?.cancel();
      } catch (e) {
        if (!(e instanceof HttpError)) throw e;
      }
    }
    for (let attempt = 0; ; attempt++) {
      const headers = new Headers(this.#defaultHeaders);
      init.headers?.forEach((v, k) => headers.set(k, v));
      new Headers(opts?.headers).forEach((v, k) => headers.set(k, v));
      const request: AuthRequest = { url: init.url, method: init.method, headers };
      if (auth) await auth.authorize(request, ctx);
      const requestInit: RequestInit & { duplex?: "half" } = {
        method: init.method,
        headers,
        body: init.body ?? null,
        redirect: "follow",
        signal: signal ?? null,
      };
      if (!replayable) requestInit.duplex = "half";
      const response = await this.#fetch(init.url, requestInit);
      if (response.status === 401 && auth && attempt === 0 && replayable) {
        let retry: boolean;
        try {
          retry = await auth.handleChallenge(request, response, ctx);
        } catch (e) {
          await response.body?.cancel().catch(() => undefined);
          throw e;
        }
        if (retry) {
          await response.body?.cancel().catch(() => undefined);
          continue;
        }
      }
      return response;
    }
  }

  async #ok(init: SendInit, opts: RequestOptions | undefined, extraOk: readonly number[] = []): Promise<Response> {
    const response = await this.#send(init, opts);
    if (!response.ok && !extraOk.includes(response.status)) {
      throw await errorFromResponse(response, init.method, init.url);
    }
    return response;
  }

  async #json(response: Response, url: string): Promise<unknown> {
    const text = await response.text();
    try {
      return JSON.parse(text) as unknown;
    } catch (e) {
      throw new ProtocolError(`response from ${url} is not valid JSON`, { cause: e });
    }
  }

  /**
   * Authenticated `fetch`: sends any request through the client's authenticator
   * (including the 401 → token → retry flow) and returns the raw Response
   * without throwing on error statuses.
   */
  async fetch(url: UrlLike, init: RequestInit = {}): Promise<Response> {
    const opts: RequestOptions = {};
    if (init.headers) opts.headers = init.headers;
    if (init.signal) opts.signal = init.signal;
    return this.#send({ method: (init.method ?? "GET").toUpperCase(), url: new URL(url).href, body: init.body ?? null }, opts);
  }

  // -------------------------------------------------------------------------
  // Discovery
  // -------------------------------------------------------------------------

  /**
   * Discover the storage that contains `resourceUrl` (via its
   * `rel="https://www.w3.org/ns/lws#storage"` link) and fetch its description.
   */
  async discoverStorage(resourceUrl: UrlLike, opts?: RequestOptions): Promise<StorageDescription> {
    const url = new URL(resourceUrl).href;
    let metadata: ResourceMetadata;
    try {
      metadata = await this.head(url, opts);
    } catch (e) {
      if (e instanceof MethodNotAllowedError || e instanceof NotImplementedError) {
        const res = await this.#ok({ method: "GET", url }, opts);
        await res.body?.cancel().catch(() => undefined);
        metadata = ResourceMetadata.fromResponse(res, url);
      } else if (e instanceof HttpError && new ResourceMetadata(url, e.status, e.headers).storage) {
        metadata = new ResourceMetadata(url, e.status, e.headers);
      } else throw e;
    }
    const storage = metadata.storage;
    if (!storage) throw new ProtocolError(`${url} has no rel="${Rel.STORAGE}" link`);
    return this.getStorageDescription(storage, opts);
  }

  /** Fetch and parse a storage description resource. */
  async getStorageDescription(storageUrl: UrlLike, opts?: RequestOptions): Promise<StorageDescription> {
    const url = new URL(storageUrl).href;
    const headers = new Headers({ accept: `${MediaType.LWS_CID}, ${MediaType.LD_JSON};q=0.9, ${MediaType.JSON};q=0.8` });
    const res = await this.#ok({ method: "GET", url, headers }, opts);
    return new StorageDescription(await this.#json(res, url), res.url || url);
  }

  // -------------------------------------------------------------------------
  // Reading
  // -------------------------------------------------------------------------

  /** `HEAD`: resource metadata without the body. */
  async head(url: UrlLike, opts?: RequestOptions): Promise<ResourceMetadata> {
    const u = new URL(url).href;
    const res = await this.#ok({ method: "HEAD", url: u }, opts);
    await res.body?.cancel().catch(() => undefined);
    return ResourceMetadata.fromResponse(res, u);
  }

  /**
   * `GET` a resource. A `304` answer to a conditional read is returned with
   * `notModified === true`; `206` partial content is a normal result.
   */
  async read(url: UrlLike, opts: ReadOptions = {}): Promise<Resource> {
    const u = new URL(url).href;
    const headers = new Headers();
    if (opts.accept) headers.set("accept", opts.accept);
    if (opts.range !== undefined) headers.set("range", rangeHeader(opts.range));
    if (opts.ifNoneMatch) headers.set("if-none-match", opts.ifNoneMatch);
    if (opts.ifModifiedSince) {
      headers.set(
        "if-modified-since",
        typeof opts.ifModifiedSince === "string" ? opts.ifModifiedSince : opts.ifModifiedSince.toUTCString(),
      );
    }
    if (opts.prefer) headers.set("prefer", opts.prefer);
    const res = await this.#ok({ method: "GET", url: u, headers }, opts, [304]);
    return new Resource(res.url || u, res);
  }

  /** Read one page of a container listing. */
  async readContainer(url: UrlLike, opts?: RequestOptions): Promise<ContainerPage> {
    const page = await this.#readPage(new URL(url).href, opts);
    if (!page.isContainer()) {
      throw new ProtocolError(`${page.metadata.url} is not a container (type ${JSON.stringify(page.types)})`);
    }
    return page;
  }

  async #readPage(u: string, opts: RequestOptions | undefined): Promise<ContainerPage> {
    const headers = new Headers({ accept: MediaType.LWS_JSON });
    const res = await this.#ok({ method: "GET", url: u, headers }, opts);
    const mediaType = mediaTypeEssence(res.headers.get("content-type"));
    if (!mediaType || !CONTAINER_MEDIA_TYPES.has(mediaType as never)) {
      await res.body?.cancel().catch(() => undefined);
      throw new ProtocolError(`expected an application/lws+json listing from ${u}, got ${mediaType ?? "no content type"}`);
    }
    return new ContainerPage(await this.#json(res, u), ResourceMetadata.fromResponse(res, u));
  }

  async *#paginate<T, P extends { next: string | undefined }>(
    first: string,
    load: (url: string) => Promise<P>,
    items: (page: P) => Iterable<T>,
  ): AsyncGenerator<T, void, undefined> {
    const seen = new Set<string>();
    let next: string | undefined = first;
    while (next !== undefined && !seen.has(next)) {
      seen.add(next);
      const page: P = await load(next);
      yield* items(page);
      next = page.next;
    }
  }

  /** Lazily iterate every member of a container, following `rel="next"` pages. */
  listContainer(url: UrlLike, opts?: RequestOptions): AsyncGenerator<ContainedResource, void, undefined> {
    return this.#paginate(new URL(url).href, (u) => this.readContainer(u, opts), (p) => p.items);
  }

  // -------------------------------------------------------------------------
  // Creating
  // -------------------------------------------------------------------------

  #createHeaders(opts: CreateOptions): Headers {
    const headers = new Headers();
    if (opts.slug) headers.set("slug", encodeSlug(opts.slug));
    for (const link of opts.links ?? []) headers.append("link", formatLink(link));
    for (const type of opts.types ?? []) headers.append("link", formatLink({ href: type, rel: Rel.TYPE }));
    return headers;
  }

  async #created(res: Response, url: string): Promise<CreateResult> {
    await res.body?.cancel().catch(() => undefined);
    const location = res.headers.get("location");
    if (!location) throw new ProtocolError(`create in ${url} returned ${res.status} without a Location header`);
    return { location: resolveUrl(location, res.url || url), metadata: ResourceMetadata.fromResponse(res, url) };
  }

  /** `POST` a new data resource into a container. */
  async create(containerUrl: UrlLike, body: BodyInit, contentType: string, opts: CreateOptions = {}): Promise<CreateResult> {
    const url = new URL(containerUrl).href;
    const headers = this.#createHeaders(opts);
    headers.set("content-type", contentType);
    return this.#created(await this.#ok({ method: "POST", url, headers, body }, opts), url);
  }

  /** Create a JSON data resource (`application/json` unless `contentType` is given). */
  createJson(containerUrl: UrlLike, value: unknown, opts: CreateOptions & { contentType?: string } = {}): Promise<CreateResult> {
    return this.create(containerUrl, JSON.stringify(value), opts.contentType ?? MediaType.JSON, opts);
  }

  /** Create a text data resource (`text/plain` unless `contentType` is given). */
  createText(containerUrl: UrlLike, text: string, opts: CreateOptions & { contentType?: string } = {}): Promise<CreateResult> {
    return this.create(containerUrl, text, opts.contentType ?? "text/plain", opts);
  }

  /** `POST` a new (empty) container into a parent container. */
  async createContainer(parentUrl: UrlLike, opts: CreateOptions = {}): Promise<CreateResult> {
    const url = new URL(parentUrl).href;
    const headers = this.#createHeaders(opts);
    headers.append("link", formatLink({ href: LwsType.CONTAINER, rel: Rel.TYPE }));
    return this.#created(await this.#ok({ method: "POST", url, headers, body: new Uint8Array(0) }, opts), url);
  }

  // -------------------------------------------------------------------------
  // Updating
  // -------------------------------------------------------------------------

  #updateHeaders(opts: UpdateOptions): Headers {
    const headers = new Headers();
    if (opts.ifMatch) headers.set("if-match", opts.ifMatch);
    if (opts.ifNoneMatch) headers.set("if-none-match", opts.ifNoneMatch);
    for (const link of opts.links ?? []) headers.append("link", formatLink(link));
    if (opts.setLinkset) headers.set("prefer", Prefer.SET_LINKSET);
    return headers;
  }

  async #updated(res: Response, url: string): Promise<UpdateResult> {
    await res.body?.cancel().catch(() => undefined);
    const metadata = ResourceMetadata.fromResponse(res, url);
    return { status: res.status, etag: metadata.etag, metadata };
  }

  /** `PUT`: replace the content of an existing resource. */
  async update(url: UrlLike, body: BodyInit, contentType: string, opts: UpdateOptions = {}): Promise<UpdateResult> {
    const u = new URL(url).href;
    const headers = this.#updateHeaders(opts);
    headers.set("content-type", contentType);
    return this.#updated(await this.#ok({ method: "PUT", url: u, headers, body }, opts), u);
  }

  /** Replace a resource with a JSON value. */
  updateJson(url: UrlLike, value: unknown, opts: UpdateOptions & { contentType?: string } = {}): Promise<UpdateResult> {
    return this.update(url, JSON.stringify(value), opts.contentType ?? MediaType.JSON, opts);
  }

  /**
   * `PATCH` a resource with a JSON Patch (`application/json-patch+json`, the
   * LWS baseline) or a raw patch in another advertised format.
   */
  async patch(url: UrlLike, patch: JsonPatch | readonly JsonPatchOperation[] | RawPatch, opts: UpdateOptions = {}): Promise<UpdateResult> {
    const u = new URL(url).href;
    const headers = this.#updateHeaders(opts);
    let body: BodyInit;
    if (patch instanceof JsonPatch || Array.isArray(patch)) {
      body = JSON.stringify(patch instanceof JsonPatch ? patch.toJSON() : patch);
      headers.set("content-type", MediaType.JSON_PATCH);
    } else {
      const raw = patch as RawPatch;
      body = raw.body;
      headers.set("content-type", raw.contentType);
    }
    return this.#updated(await this.#ok({ method: "PATCH", url: u, headers, body }, opts), u);
  }

  // -------------------------------------------------------------------------
  // Deleting
  // -------------------------------------------------------------------------

  /** `DELETE` a resource; containers must be empty unless `recursive` is set. */
  async delete(url: UrlLike, opts: DeleteOptions = {}): Promise<void> {
    const u = new URL(url).href;
    const headers = new Headers();
    if (opts.ifMatch) headers.set("if-match", opts.ifMatch);
    if (opts.recursive) headers.set("depth", "infinity");
    const res = await this.#ok({ method: "DELETE", url: u, headers }, opts);
    await res.body?.cancel().catch(() => undefined);
  }

  // -------------------------------------------------------------------------
  // Metadata (linksets)
  // -------------------------------------------------------------------------

  /** The URL of a resource's linkset (metadata) resource. */
  async linksetUrl(resourceUrl: UrlLike, opts?: RequestOptions): Promise<string> {
    const metadata = await this.head(resourceUrl, opts);
    const linkset = metadata.linkset;
    if (!linkset) throw new ProtocolError(`${metadata.url} has no rel="linkset" link`);
    return linkset;
  }

  /** Discover and read the linkset of a resource. */
  async readLinkset(resourceUrl: UrlLike, opts?: RequestOptions): Promise<LinksetDocument> {
    const url = await this.linksetUrl(resourceUrl, opts);
    const headers = new Headers({ accept: MediaType.LINKSET_JSON });
    const res = await this.#ok({ method: "GET", url, headers }, opts);
    const metadata = ResourceMetadata.fromResponse(res, url);
    const json = await this.#json(res, url);
    return {
      url: metadata.url,
      etag: metadata.etag,
      linkset: Linkset.parse(json),
      allow: metadata.allow,
      acceptPatch: metadata.acceptPatch,
      metadata,
    };
  }

  /** `PUT` a complete linkset (only when the server allows PUT on the linkset). */
  async updateLinkset(linksetUrl: UrlLike, linkset: Linkset | object, opts: ConditionalOptions = {}): Promise<UpdateResult> {
    const u = new URL(linksetUrl).href;
    const headers = new Headers({ "content-type": MediaType.LINKSET_JSON });
    if (opts.ifMatch) headers.set("if-match", opts.ifMatch);
    const body = JSON.stringify(linkset instanceof Linkset ? linkset.toJSON() : linkset);
    return this.#updated(await this.#ok({ method: "PUT", url: u, headers, body }, opts), u);
  }

  /** `PATCH` a linkset with a JSON Patch. */
  patchLinkset(linksetUrl: UrlLike, patch: JsonPatch | readonly JsonPatchOperation[], opts: ConditionalOptions = {}): Promise<UpdateResult> {
    return this.patch(linksetUrl, patch, opts);
  }

  // -------------------------------------------------------------------------
  // Notifications
  // -------------------------------------------------------------------------

  /** Create a webhook subscription at a NotificationService. */
  async subscribe(service: ServiceRef, request: WebhookSubscriptionRequest, opts?: RequestOptions): Promise<Subscription> {
    if (service instanceof Service && !service.supportsWebhooks()) {
      throw new ProtocolError(`notification service ${service.serviceEndpoint} does not support ${SUBSCRIPTION_WEBHOOK}`);
    }
    const url = endpointOf(service);
    const body: Record<string, unknown> = {
      "@context": [LWS_CONTEXT],
      type: SUBSCRIPTION_WEBHOOK,
      topic: request.topics.map((t) => (typeof t === "string" ? t : t.href)),
      inbox: typeof request.inbox === "string" ? request.inbox : request.inbox.href,
    };
    if (request.expires !== undefined) body["expires"] = formatDateTime(request.expires);
    const headers = new Headers({ "content-type": MediaType.LWS_JSON, accept: MediaType.LWS_JSON });
    const res = await this.#ok({ method: "POST", url, headers, body: JSON.stringify(body) }, opts);
    const base = res.url || url;
    const text = await res.text();
    let json: unknown = {};
    if (text.trim()) {
      try {
        json = JSON.parse(text);
      } catch (e) {
        throw new ProtocolError("subscription response is not valid JSON", { cause: e });
      }
    }
    const raw = isObject(json) ? json : {};
    const location = res.headers.get("location");
    const subscription =
      typeof raw["subscription"] === "string" ? resolveUrl(raw["subscription"], base) : location ? resolveUrl(location, base) : undefined;
    if (!subscription) throw new ProtocolError("subscription response has neither 'subscription' nor Location");
    return new Subscription(raw, subscription);
  }

  /** Iterate the caller's subscriptions at a NotificationService. */
  listSubscriptions(service: ServiceRef, opts?: RequestOptions): AsyncGenerator<ContainedResource, void, undefined> {
    return this.listContainer(endpointOf(service), opts);
  }

  /** Read a subscription. */
  async getSubscription(url: UrlLike, opts?: RequestOptions): Promise<Subscription> {
    const u = new URL(url).href;
    const res = await this.#ok({ method: "GET", url: u, headers: new Headers({ accept: MediaType.LWS_JSON }) }, opts);
    const json = await this.#json(res, u);
    if (!isObject(json)) throw new ProtocolError("subscription is not a JSON object");
    const id = typeof json["subscription"] === "string" ? resolveUrl(json["subscription"], u) : u;
    return new Subscription(json, id);
  }

  /** Cancel a subscription. */
  unsubscribe(url: UrlLike, opts?: RequestOptions): Promise<void> {
    return this.delete(url, opts ?? {});
  }

  // -------------------------------------------------------------------------
  // Access requests and grants
  // -------------------------------------------------------------------------

  async #postAccess(service: ServiceRef, doc: AccessRequest | AccessGrant, opts?: RequestOptions): Promise<string> {
    const url = endpointOf(service);
    const headers = new Headers({ "content-type": MediaType.LWS_JSON, accept: MediaType.LWS_JSON });
    const res = await this.#ok({ method: "POST", url, headers, body: JSON.stringify(doc.toJSON()) }, opts);
    return (await this.#created(res, url)).location;
  }

  async #getJson(url: UrlLike, opts?: RequestOptions): Promise<unknown> {
    const u = new URL(url).href;
    const res = await this.#ok({ method: "GET", url: u, headers: new Headers({ accept: MediaType.LWS_JSON }) }, opts);
    return this.#json(res, u);
  }

  /** Submit an access request; returns its URL. */
  requestAccess(service: ServiceRef, request: AccessRequest | AccessDocumentInit, opts?: RequestOptions): Promise<string> {
    return this.#postAccess(service, request instanceof AccessRequest ? request : new AccessRequest(request), opts);
  }
  /** Iterate access requests. */
  listAccessRequests(service: ServiceRef, opts?: RequestOptions): AsyncGenerator<ContainedResource, void, undefined> {
    return this.listContainer(endpointOf(service), opts);
  }
  /** Read an access request. */
  async getAccessRequest(url: UrlLike, opts?: RequestOptions): Promise<AccessRequest> {
    return AccessRequest.parse(await this.#getJson(url, opts));
  }
  /** Cancel an access request. */
  cancelAccessRequest(url: UrlLike, opts?: RequestOptions): Promise<void> {
    return this.delete(url, opts ?? {});
  }
  /** Create an access grant (storage controllers); returns its URL. */
  grantAccess(service: ServiceRef, grant: AccessGrant | AccessDocumentInit, opts?: RequestOptions): Promise<string> {
    return this.#postAccess(service, grant instanceof AccessGrant ? grant : new AccessGrant(grant), opts);
  }
  /** Iterate access grants. */
  listAccessGrants(service: ServiceRef, opts?: RequestOptions): AsyncGenerator<ContainedResource, void, undefined> {
    return this.listContainer(endpointOf(service), opts);
  }
  /** Read an access grant. */
  async getAccessGrant(url: UrlLike, opts?: RequestOptions): Promise<AccessGrant> {
    return AccessGrant.parse(await this.#getJson(url, opts));
  }
  /** Revoke an access grant. */
  revokeAccessGrant(url: UrlLike, opts?: RequestOptions): Promise<void> {
    return this.delete(url, opts ?? {});
  }

  // -------------------------------------------------------------------------
  // Type index and type search
  // -------------------------------------------------------------------------

  /** Read one page of a Type Index (the service endpoint or a page URL). */
  async readTypeIndex(url: ServiceRef, opts?: RequestOptions): Promise<TypeIndexPage> {
    const u = endpointOf(url);
    const res = await this.#ok({ method: "GET", url: u, headers: new Headers({ accept: MediaType.LWS_JSON }) }, opts);
    return new TypeIndexPage(await this.#json(res, u), ResourceMetadata.fromResponse(res, u));
  }

  /** Iterate every type IRI of a Type Index. */
  listTypes(service: ServiceRef, opts?: RequestOptions): AsyncGenerator<string, void, undefined> {
    return this.#paginate(endpointOf(service), (u) => this.readTypeIndex(u, opts), (p) => p.types);
  }

  /** Run a type search (HTTP `QUERY` with an `application/lws-query+json` filter); returns the first page. */
  async searchTypes(service: ServiceRef, query: TypeQuery | object, opts?: RequestOptions): Promise<SearchPage> {
    const u = endpointOf(service);
    const headers = new Headers({ "content-type": MediaType.LWS_QUERY_JSON, accept: MediaType.LWS_JSON });
    const body = JSON.stringify(query instanceof TypeQuery ? query.toJSON() : query);
    const res = await this.#ok({ method: "QUERY", url: u, headers, body }, opts);
    return new ContainerPage(await this.#json(res, u), ResourceMetadata.fromResponse(res, u));
  }

  /** Iterate every search result, following the opaque `next` page links. */
  async *searchAll(service: ServiceRef, query: TypeQuery | object, opts?: RequestOptions): AsyncGenerator<ContainedResource, void, undefined> {
    const first = await this.searchTypes(service, query, opts);
    yield* first.items;
    if (first.next) yield* this.#paginate(first.next, (u) => this.#readPage(u, opts), (p) => p.items);
  }

  /** Query formats a search service accepts (`OPTIONS` → `Accept-Query`). */
  async acceptedQueryFormats(service: ServiceRef, opts?: RequestOptions): Promise<string[]> {
    const u = endpointOf(service);
    const res = await this.#ok({ method: "OPTIONS", url: u }, opts);
    await res.body?.cancel().catch(() => undefined);
    return splitHeaderList(res.headers.get("accept-query")).map((m) => mediaTypeEssence(m.replace(/"/g, "")) ?? m);
  }
}
