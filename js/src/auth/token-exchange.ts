// SPDX-License-Identifier: MIT
// The LWS authorization flow: 401 challenge → AS metadata → token exchange → retry.
import { AuthenticationError } from "../errors.js";
import { parseWwwAuthenticate } from "../http/www-authenticate.js";
import { isLoopbackHost } from "../util/http.js";
import type { AuthContext, Authenticator, AuthRequest } from "./authenticator.js";
import type { CredentialProvider } from "./credentials.js";
import {
  exchangeToken,
  fetchAuthorizationServerMetadata,
  isWithinRealm,
  type AuthorizationServerMetadata,
} from "./oauth.js";

/** Options of {@link TokenExchangeAuthenticator}. */
export interface TokenExchangeOptions {
  /** Allow plain-http authorization servers on non-loopback hosts (testing only). */
  allowInsecureHttp?: boolean;
  /**
   * Decide whether to trust an authorization server named by a storage's
   * challenge. Default: trust. Use it when presenting tokens that are not
   * audience-restricted to the authorization server (e.g. static OpenID/SAML tokens).
   */
  authorizationServerFilter?: (asUri: string, realm: string) => boolean | Promise<boolean>;
  /** Refresh access tokens this many seconds before expiry (default 30). */
  refreshSkewSeconds?: number;
  /** Clock in epoch milliseconds (testing). */
  clock?: () => number;
}

interface CachedToken {
  readonly key: string;
  readonly issuer: string;
  readonly realm: string;
  readonly token: string;
  readonly expiresAt: number;
}

/**
 * Implements the LWS OAuth 2.0 flow: on a `401` with
 * `WWW-Authenticate: Bearer as_uri="…", realm="…"` it verifies the realm,
 * discovers the authorization server, exchanges a subject token from the
 * {@link CredentialProvider} for an access token, and lets the client retry.
 * Tokens are cached per (issuer, realm) and sent proactively to URLs inside
 * their realm.
 */
export class TokenExchangeAuthenticator implements Authenticator {
  readonly credentials: CredentialProvider;
  readonly #options: TokenExchangeOptions;
  readonly #tokens = new Map<string, CachedToken>();
  readonly #inflight = new Map<string, Promise<CachedToken>>();
  readonly #metadata = new Map<string, Promise<AuthorizationServerMetadata>>();
  readonly #used = new WeakMap<AuthRequest, string>();

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

  #tokenFor(url: string): CachedToken | undefined {
    let best: CachedToken | undefined;
    for (const t of this.#tokens.values()) {
      if (!this.#valid(t)) {
        this.#tokens.delete(t.key);
        continue;
      }
      if (isWithinRealm(url, t.realm) && (!best || t.realm.length > best.realm.length)) best = t;
    }
    return best;
  }

  authorize(request: AuthRequest): void {
    const t = this.#tokenFor(request.url);
    if (!t) return;
    request.headers.set("authorization", `Bearer ${t.token}`);
    this.#used.set(request, t.key);
  }

  hasCredentials(url: string): boolean {
    return this.#tokenFor(url) !== undefined;
  }

  /** Forget all cached access tokens and metadata. */
  clear(): void {
    this.#tokens.clear();
    this.#metadata.clear();
  }

  async handleChallenge(request: AuthRequest, response: Response, context: AuthContext): Promise<boolean> {
    const challenge = parseWwwAuthenticate(response.headers.get("www-authenticate")).find(
      (c) => c.is("Bearer") && c.asUri && c.realm,
    );
    if (!challenge) return false;
    const issuer = challenge.asUri!;
    const realm = challenge.realm!;

    if (!isWithinRealm(request.url, realm)) {
      throw new AuthenticationError(`request URL ${request.url} is not inside the challenge realm ${realm}`);
    }
    this.#checkTransport(issuer, "authorization server");
    if (this.#options.authorizationServerFilter && !(await this.#options.authorizationServerFilter(issuer, realm))) {
      throw new AuthenticationError(`authorization server ${issuer} is not trusted for realm ${realm}`);
    }

    const key = `${issuer} ${realm}`;
    const usedKey = this.#used.get(request);
    if (usedKey !== undefined) this.#tokens.delete(usedKey);
    const cached = this.#tokens.get(key);
    if (cached && this.#valid(cached) && usedKey !== key) return true; // another request refreshed it meanwhile

    let pending = this.#inflight.get(key);
    if (!pending) {
      pending = this.#obtain(key, issuer, realm, context).finally(() => this.#inflight.delete(key));
      this.#inflight.set(key, pending);
    }
    const token = await pending;
    this.#tokens.set(key, token);
    return true;
  }

  #checkTransport(uri: string, what: string): void {
    let u: URL;
    try {
      u = new URL(uri);
    } catch {
      throw new AuthenticationError(`${what} URI ${uri} is not a valid URL`);
    }
    if (u.protocol === "https:") return;
    if (u.protocol === "http:" && (this.#options.allowInsecureHttp || isLoopbackHost(u.hostname))) return;
    throw new AuthenticationError(`${what} ${uri} must use https`);
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

  async #obtain(key: string, issuer: string, realm: string, context: AuthContext): Promise<CachedToken> {
    const metadata = await this.#loadMetadata(issuer, context);
    this.#checkTransport(metadata.token_endpoint, "token endpoint");
    const supported = metadata.subject_token_types_supported;
    if (Array.isArray(supported) && !supported.includes(this.credentials.tokenType)) {
      throw new AuthenticationError(
        `authorization server ${issuer} does not accept subject tokens of type ${this.credentials.tokenType}`,
      );
    }
    const subjectToken = await this.credentials.getSubjectToken({ issuer, realm, metadata, signal: context.signal });
    const result = await exchangeToken(
      metadata,
      { resource: realm, subjectToken, subjectTokenType: this.credentials.tokenType },
      { fetch: context.fetch, signal: context.signal, now: this.#now() },
    );
    return { key, issuer, realm, token: result.accessToken, expiresAt: result.expiresAt };
  }
}
