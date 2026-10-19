// SPDX-License-Identifier: MIT
// The LWS authorization flow: 401 challenge → protected resource metadata → discovery checks →
// AS metadata → token exchange → retry.
import { Rel, ServiceType } from "../constants.js";
import { AuthenticationError } from "../errors.js";
import { parseLinkHeader } from "../http/link.js";
import { parseWwwAuthenticate } from "../http/www-authenticate.js";
import { STORAGE_DESCRIPTION_ACCEPT, StorageDescription } from "../models/storage.js";
import { isLoopbackHost, resolveUrl } from "../util/http.js";
import type { AuthContext, Authenticator, AuthRequest } from "./authenticator.js";
import type { CredentialProvider } from "./credentials.js";
import {
  exchangeToken,
  fetchAuthorizationServerMetadata,
  fetchProtectedResourceMetadata,
  isSameOrigin,
  isSameResource,
  isWithinRealm,
  type AuthorizationServerMetadata,
} from "./oauth.js";

/** Options of {@link TokenExchangeAuthenticator}. */
export interface TokenExchangeOptions {
  /** Allow plain-http authorization servers on non-loopback hosts (testing only). */
  allowInsecureHttp?: boolean;
  /**
   * Decide whether to trust an authorization server named by a storage's
   * protected resource metadata for that storage. Default: trust. Use it when
   * presenting tokens that are not audience-restricted to the authorization
   * server (e.g. static OpenID/SAML tokens).
   */
  authorizationServerFilter?: (issuer: string, storage: string) => boolean | Promise<boolean>;
  /** Refresh access tokens this many seconds before expiry (default 30). */
  refreshSkewSeconds?: number;
  /** Clock in epoch milliseconds (testing). */
  clock?: () => number;
}

/** What a `401` leads to once its checks pass. */
interface Grant {
  /** The authorization server. */
  readonly issuer: string;
  /** The storage the token is for (the token request's `resource`). */
  readonly storage: string;
  /** URLs, each treated as a directory, the token is sent to without a `401` first. */
  readonly scopes: readonly string[];
}

interface CachedToken extends Grant {
  readonly key: string;
  readonly token: string;
  readonly expiresAt: number;
}

/** The length of a scope's path as a directory: the longest decides between tokens whose scopes contain a URL. */
function scopeLength(scope: string): number {
  const path = new URL(scope).pathname;
  return path.endsWith("/") ? path.length : path.length + 1;
}

const withoutFragment = (url: string): string => url.split("#")[0]!;

/** GET a storage description for the discovery checks: no credentials, no redirect. */
async function fetchStorageDescription(url: string, context: AuthContext): Promise<StorageDescription> {
  let response: Response;
  try {
    response = await context.fetch(url, {
      headers: { accept: STORAGE_DESCRIPTION_ACCEPT },
      redirect: "error",
      signal: context.signal ?? null,
    });
  } catch (e) {
    throw new AuthenticationError(`could not fetch the storage description ${url}`, { cause: e });
  }
  if (!response.ok) throw new AuthenticationError(`storage description request to ${url} failed with ${response.status}`);
  try {
    return new StorageDescription(await response.json(), response.url || url);
  } catch (e) {
    throw new AuthenticationError(`the storage description ${url} cannot be read`, { cause: e });
  }
}

/**
 * Implements the LWS OAuth 2.0 flow: on a `401` with
 * `WWW-Authenticate: Bearer resource_metadata="…"` it reads the protected
 * resource metadata (RFC 9728), checks that the metadata and the storage the
 * `401` links to describe the server that answered, exchanges a subject token
 * from the {@link CredentialProvider} for an access token for that storage at
 * the first usable authorization server, and lets the client retry. The
 * `as_uri`/`realm` challenge of the drafts before 19 October 2026 is still
 * followed. Tokens are cached per (issuer, storage) and sent proactively to
 * URLs inside the storage and its root (or inside the realm); the retry of the
 * request whose `401` passed the checks carries its token wherever it is.
 */
export class TokenExchangeAuthenticator implements Authenticator {
  readonly credentials: CredentialProvider;
  readonly #options: TokenExchangeOptions;
  readonly #tokens = new Map<string, CachedToken>();
  readonly #inflight = new Map<string, Promise<CachedToken>>();
  readonly #metadata = new Map<string, Promise<AuthorizationServerMetadata>>();
  readonly #storages = new Map<string, Promise<StorageDescription>>();
  readonly #used = new WeakMap<AuthRequest, CachedToken>();
  /** Per operation (the client's context): the URL whose 401 passed the checks, and the token its retry carries. */
  readonly #retries = new WeakMap<AuthContext, { url: string; token: CachedToken }>();

  constructor(credentials: CredentialProvider, options: TokenExchangeOptions = {}) {
    this.credentials = credentials;
    this.#options = options;
  }

  #now(): number {
    return (this.#options.clock ?? Date.now)();
  }

  #valid(t: CachedToken): boolean {
    return t.expiresAt - (this.#options.refreshSkewSeconds ?? 30) * 1000 > this.#now();
  }

  /** The token whose scope contains `url`; where several do, the one with the longest scope path. */
  #tokenFor(url: string): CachedToken | undefined {
    let best: CachedToken | undefined;
    let bestLength = -1;
    for (const t of this.#tokens.values()) {
      if (!this.#valid(t)) {
        this.#tokens.delete(t.key);
        continue;
      }
      for (const scope of t.scopes) {
        if (!isWithinRealm(url, scope)) continue;
        const length = scopeLength(scope);
        if (length > bestLength) {
          best = t;
          bestLength = length;
        }
      }
    }
    return best;
  }

  authorize(request: AuthRequest, context?: AuthContext): void {
    // The retry of a request whose 401 passed the checks carries the token, even outside its scope.
    const retry = context && this.#retries.get(context);
    if (context && retry) this.#retries.delete(context);
    const t = retry && retry.url === request.url && this.#valid(retry.token) ? retry.token : this.#tokenFor(request.url);
    if (!t) return;
    request.headers.set("authorization", `Bearer ${t.token}`);
    this.#used.set(request, t);
  }

  hasCredentials(url: string): boolean {
    return this.#tokenFor(url) !== undefined;
  }

  /** Forget all cached access tokens, authorization server metadata and storage descriptions. */
  clear(): void {
    this.#tokens.clear();
    this.#metadata.clear();
    this.#storages.clear();
  }

  async handleChallenge(request: AuthRequest, response: Response, context: AuthContext): Promise<boolean> {
    const bearer = parseWwwAuthenticate(response.headers.get("www-authenticate")).filter((c) => c.is("Bearer"));
    const current = bearer.find((c) => c.resourceMetadata !== undefined);
    const legacy = bearer.find((c) => c.asUri && c.realm);
    // The checks are against the URL of the request the 401 answered: after redirects, the last hop's.
    const url = response.url || request.url;
    let grant: Grant;
    if (current) grant = await this.#discover(url, current.resourceMetadata!, response, context);
    else if (legacy) grant = await this.#legacyGrant(url, legacy.asUri!, legacy.realm!);
    else return false;
    // A challenge that fails a check has thrown, and the token the request carried is kept: a
    // storage can hold a resource whose 401 links to another storage, and believing it would cost
    // the client a valid token.

    const key = `${grant.issuer} ${grant.storage}`;
    const cached = this.#tokens.get(key);
    let token: CachedToken;
    if (cached && cached !== this.#used.get(request) && this.#valid(cached)) {
      token = cached; // obtained meanwhile, or for a URL outside its scope: no new exchange
    } else {
      if (cached) this.#tokens.delete(key); // refused: exchange again
      let pending = this.#inflight.get(key);
      if (!pending) {
        pending = this.#obtain(key, grant, context).finally(() => this.#inflight.delete(key));
        this.#inflight.set(key, pending);
      }
      token = await pending;
      this.#tokens.set(key, token);
    }
    // The URL that drew the 401 has passed the checks: its retry carries the token whatever its scope.
    // After a redirect the retry goes to the first hop, which has not, and gets the token only inside its scope.
    if (withoutFragment(request.url) === withoutFragment(url)) this.#retries.set(context, { url: request.url, token });
    return true;
  }

  /**
   * The discovery checks of a `401` with `resource_metadata` (lws10-core "Discovery
   * Validation by a Client"), and the authorization server they lead to.
   */
  async #discover(url: string, resourceMetadata: string, response: Response, context: AuthContext): Promise<Grant> {
    // The metadata must be on the requested origin; it is not fetched otherwise.
    const metadataUrl = resolveUrl(resourceMetadata, url);
    if (!isSameOrigin(metadataUrl, url)) {
      throw new AuthenticationError(`protected resource metadata ${metadataUrl} is not on the origin of ${url}`);
    }
    // The token is for the storage the 401 links to.
    const storage = parseLinkHeader(response.headers.get("link"), url).find((l) => l.rel === Rel.STORAGE)?.href;
    if (storage === undefined) throw new AuthenticationError(`the 401 of ${url} has no rel="${Rel.STORAGE}" link`);
    // The metadata must describe the URL requested, and nothing else.
    const metadata = await fetchProtectedResourceMetadata(metadataUrl, { fetch: context.fetch, signal: context.signal });
    if (!isSameResource(url, metadata.resource)) {
      throw new AuthenticationError(`protected resource metadata ${metadataUrl} describes ${metadata.resource}, not ${url}`);
    }
    // The storage's root must be on the requested origin.
    const root = (await this.#loadStorage(storage, context)).service(ServiceType.STORAGE_ROOT)?.serviceEndpoint;
    if (root === undefined) throw new AuthenticationError(`the storage description ${storage} has no StorageRoot service`);
    if (!isSameOrigin(root, url)) {
      throw new AuthenticationError(`the root ${root} of storage ${storage} is not on the origin of ${url}`);
    }
    // The issuer is the first authorization server that is secure and trusted.
    for (const issuer of metadata.authorizationServers) {
      if (this.#secure(issuer) && (await this.#trusted(issuer, storage))) return { issuer, storage, scopes: [storage, root] };
    }
    throw new AuthenticationError(
      `none of the authorization servers ${metadata.authorizationServers.join(", ")} is usable for storage ${storage}`,
    );
  }

  /** The challenge of the drafts before 19 October 2026: the realm check, then `as_uri` is the issuer. */
  async #legacyGrant(url: string, issuer: string, realm: string): Promise<Grant> {
    if (!isWithinRealm(url, realm)) {
      throw new AuthenticationError(`request URL ${url} is not inside the challenge realm ${realm}`);
    }
    if (!this.#secure(issuer)) throw new AuthenticationError(`authorization server ${issuer} must use https`);
    if (!(await this.#trusted(issuer, realm))) {
      throw new AuthenticationError(`authorization server ${issuer} is not trusted for realm ${realm}`);
    }
    return { issuer, storage: realm, scopes: [realm] };
  }

  /** Transport security: `https`, or `http` on a loopback host (or with `allowInsecureHttp`). */
  #secure(uri: string): boolean {
    let u: URL;
    try {
      u = new URL(uri);
    } catch {
      return false;
    }
    if (u.protocol === "https:") return true;
    return u.protocol === "http:" && (this.#options.allowInsecureHttp === true || isLoopbackHost(u.hostname));
  }

  async #trusted(issuer: string, storage: string): Promise<boolean> {
    const filter = this.#options.authorizationServerFilter;
    return !filter || (await filter(issuer, storage));
  }

  #loadMetadata(issuer: string, context: AuthContext): Promise<AuthorizationServerMetadata> {
    let m = this.#metadata.get(issuer);
    if (!m) {
      m = fetchAuthorizationServerMetadata(issuer, { fetch: context.fetch, signal: context.signal });
      m.catch(() => this.#metadata.delete(issuer));
      this.#metadata.set(issuer, m);
    }
    return m;
  }

  #loadStorage(storage: string, context: AuthContext): Promise<StorageDescription> {
    let d = this.#storages.get(storage);
    if (!d) {
      d = fetchStorageDescription(storage, context);
      d.catch(() => this.#storages.delete(storage));
      this.#storages.set(storage, d);
    }
    return d;
  }

  async #obtain(key: string, grant: Grant, context: AuthContext): Promise<CachedToken> {
    const { issuer, storage } = grant;
    const metadata = await this.#loadMetadata(issuer, context);
    if (!this.#secure(metadata.token_endpoint)) {
      throw new AuthenticationError(`token endpoint ${metadata.token_endpoint} must use https`);
    }
    const supported = metadata.subject_token_types_supported;
    if (Array.isArray(supported) && !supported.includes(this.credentials.tokenType)) {
      throw new AuthenticationError(
        `authorization server ${issuer} does not accept subject tokens of type ${this.credentials.tokenType}`,
      );
    }
    const subjectToken = await this.credentials.getSubjectToken({ issuer, storage, metadata, signal: context.signal });
    const result = await exchangeToken(
      metadata,
      { resource: storage, subjectToken, subjectTokenType: this.credentials.tokenType },
      { fetch: context.fetch, signal: context.signal, now: this.#now() },
    );
    return { ...grant, key, token: result.accessToken, expiresAt: result.expiresAt };
  }
}
