// SPDX-License-Identifier: MIT
// OAuth 2.0 building blocks of the LWS authorization flow: realm containment,
// authorization server metadata (RFC 8414) and token exchange (RFC 8693).
import { GRANT_TYPE_TOKEN_EXCHANGE, MediaType, WELL_KNOWN_LWS_CONFIGURATION } from "../constants.js";
import { AuthenticationError } from "../errors.js";
import { decodeJwt } from "../crypto/jwt.js";
import { isObject } from "../util/types.js";

/** LWS authorization server metadata (`/.well-known/lws-configuration`). */
export interface AuthorizationServerMetadata {
  issuer: string;
  token_endpoint: string;
  jwks_uri?: string;
  grant_types_supported?: string[];
  subject_token_types_supported?: string[];
  subject_identifier_types_supported?: string[];
  [member: string]: unknown;
}

/** A token endpoint result. */
export interface TokenResponse {
  accessToken: string;
  tokenType: string;
  /** Expiry as epoch milliseconds. */
  expiresAt: number;
  issuedTokenType?: string | undefined;
  scope?: string | undefined;
  raw: Record<string, unknown>;
}

/**
 * True when `url` is logically contained in `realm`: same scheme, host and
 * port, and the path equals the realm path or lies below it.
 */
export function isWithinRealm(url: string | URL, realm: string | URL): boolean {
  let u: URL;
  let r: URL;
  try {
    u = new URL(url);
    r = new URL(realm);
  } catch {
    return false;
  }
  if (u.protocol !== r.protocol || u.host !== r.host) return false;
  if (u.pathname === r.pathname) return true;
  const dir = r.pathname.endsWith("/") ? r.pathname : r.pathname + "/";
  return u.pathname.startsWith(dir);
}

/** Metadata URL for an issuer (RFC 8414 §3.1 well-known path insertion). */
export function metadataUrl(issuer: string): string {
  const u = new URL(issuer);
  const path = u.pathname.replace(/\/+$/, "");
  return `${u.origin}${WELL_KNOWN_LWS_CONFIGURATION}${path}`;
}

const stripSlash = (s: string): string => s.replace(/\/$/, "");

/** Fetch and validate the authorization server metadata of `issuer`. */
export async function fetchAuthorizationServerMetadata(
  issuer: string,
  options: { fetch?: typeof fetch; signal?: AbortSignal | undefined } = {},
): Promise<AuthorizationServerMetadata> {
  const doFetch = options.fetch ?? globalThis.fetch;
  const url = metadataUrl(issuer);
  let response: Response;
  try {
    response = await doFetch(url, { headers: { accept: MediaType.JSON }, signal: options.signal ?? null });
  } catch (e) {
    throw new AuthenticationError(`could not fetch authorization server metadata from ${url}`, { cause: e });
  }
  if (!response.ok) {
    throw new AuthenticationError(`authorization server metadata request to ${url} failed with ${response.status}`);
  }
  let json: unknown;
  try {
    json = await response.json();
  } catch (e) {
    throw new AuthenticationError(`authorization server metadata at ${url} is not JSON`, { cause: e });
  }
  if (!isObject(json) || typeof json["issuer"] !== "string" || typeof json["token_endpoint"] !== "string") {
    throw new AuthenticationError(`authorization server metadata at ${url} lacks issuer or token_endpoint`);
  }
  if (stripSlash(json["issuer"]) !== stripSlash(issuer)) {
    throw new AuthenticationError(`authorization server metadata issuer ${json["issuer"]} does not match ${issuer}`);
  }
  return json as AuthorizationServerMetadata;
}

/** Compute a token's expiry (epoch ms): `expires_in`, else the JWT `exp`, else 300 s. */
export function tokenExpiry(body: Record<string, unknown>, nowMs: number): number {
  const expiresIn = body["expires_in"];
  if (typeof expiresIn === "number" && Number.isFinite(expiresIn)) return nowMs + expiresIn * 1000;
  if (typeof expiresIn === "string" && /^\d+$/.test(expiresIn)) return nowMs + Number(expiresIn) * 1000;
  const token = body["access_token"];
  if (typeof token === "string") {
    try {
      const exp = decodeJwt(token).payload["exp"];
      if (typeof exp === "number") return exp * 1000;
    } catch {
      // not a JWT
    }
  }
  return nowMs + 300_000;
}

/** Input of {@link exchangeToken}. */
export interface TokenExchangeRequest {
  /** The realm (becomes the access token audience). */
  resource: string;
  subjectToken: string;
  subjectTokenType: string;
}

/** Perform an OAuth 2.0 Token Exchange at the metadata's token endpoint. */
export async function exchangeToken(
  metadata: AuthorizationServerMetadata,
  request: TokenExchangeRequest,
  options: { fetch?: typeof fetch; signal?: AbortSignal | undefined; now?: number } = {},
): Promise<TokenResponse> {
  const doFetch = options.fetch ?? globalThis.fetch;
  const form = new URLSearchParams({
    grant_type: GRANT_TYPE_TOKEN_EXCHANGE,
    resource: request.resource,
    subject_token: request.subjectToken,
    subject_token_type: request.subjectTokenType,
  });
  let response: Response;
  try {
    response = await doFetch(metadata.token_endpoint, {
      method: "POST",
      headers: { "content-type": MediaType.FORM, accept: MediaType.JSON },
      body: form.toString(),
      signal: options.signal ?? null,
    });
  } catch (e) {
    throw new AuthenticationError(`token request to ${metadata.token_endpoint} failed`, { cause: e });
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  if (!response.ok) {
    const error = isObject(body) && typeof body["error"] === "string" ? body["error"] : undefined;
    const description = isObject(body) && typeof body["error_description"] === "string" ? body["error_description"] : undefined;
    throw new AuthenticationError(
      `token exchange failed with ${response.status}${error ? ` (${error}${description ? `: ${description}` : ""})` : ""}`,
      { error, errorDescription: description },
    );
  }
  if (!isObject(body) || typeof body["access_token"] !== "string") {
    throw new AuthenticationError("token response has no access_token");
  }
  const tokenType = typeof body["token_type"] === "string" ? body["token_type"] : "";
  if (tokenType.toLowerCase() !== "bearer") {
    throw new AuthenticationError(`unsupported token_type ${JSON.stringify(body["token_type"])} (expected Bearer)`);
  }
  return {
    accessToken: body["access_token"],
    tokenType,
    expiresAt: tokenExpiry(body, options.now ?? Date.now()),
    issuedTokenType: typeof body["issued_token_type"] === "string" ? body["issued_token_type"] : undefined,
    scope: typeof body["scope"] === "string" ? body["scope"] : undefined,
    raw: body,
  };
}
