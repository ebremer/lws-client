// SPDX-License-Identifier: MIT
// The pluggable Authenticator contract and a static bearer-token implementation.
import { isWithinRealm } from "./oauth.js";

/** The request being authorized. `headers` may be modified. */
export interface AuthRequest {
  readonly url: string;
  readonly method: string;
  readonly headers: Headers;
}

/** Services the client lends to authenticators. */
export interface AuthContext {
  /** The client's fetch implementation (use it for metadata and token requests). */
  readonly fetch: typeof fetch;
  /** The operation's abort signal. */
  readonly signal?: AbortSignal | undefined;
}

/**
 * Pluggable authentication. The client calls {@link authorize} before every
 * request and {@link handleChallenge} on a `401`; returning `true` makes the
 * client retry the request once.
 */
export interface Authenticator {
  authorize(request: AuthRequest, context: AuthContext): void | Promise<void>;
  handleChallenge(request: AuthRequest, response: Response, context: AuthContext): boolean | Promise<boolean>;
  /** Whether credentials for `url` are already available (lets the client avoid a 401 on streaming uploads). */
  hasCredentials?(url: string): boolean;
}

/** Options of {@link BearerTokenAuthenticator}. */
export interface BearerTokenOptions {
  /** Only send the token to URLs inside this realm (recommended). */
  realm?: string;
}

/** Sends a known access token (or one produced by a callback) as `Authorization: Bearer`. */
export class BearerTokenAuthenticator implements Authenticator {
  readonly #token: string | (() => string | Promise<string>);
  readonly #realm: string | undefined;

  constructor(token: string | (() => string | Promise<string>), options: BearerTokenOptions = {}) {
    this.#token = token;
    this.#realm = options.realm;
  }

  async authorize(request: AuthRequest): Promise<void> {
    if (this.#realm !== undefined && !isWithinRealm(request.url, this.#realm)) return;
    const token = typeof this.#token === "function" ? await this.#token() : this.#token;
    request.headers.set("authorization", `Bearer ${token}`);
  }

  handleChallenge(): boolean {
    // A supplier may produce a fresh token on the retry; a static token cannot change.
    return typeof this.#token === "function";
  }

  hasCredentials(url: string): boolean {
    return this.#realm === undefined || isWithinRealm(url, this.#realm);
  }
}
