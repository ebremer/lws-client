// SPDX-License-Identifier: MIT
// Error hierarchy mapping the LWS abstract responses onto HTTP statuses.
import { parseWwwAuthenticate, type AuthChallenge } from "./http/www-authenticate.js";
import { parseProblemDetails, type ProblemDetails } from "./http/problem.js";
import { splitHeaderList, mediaTypeEssence } from "./util/http.js";

/** Base class of every error raised by this library. */
export class LwsError extends Error {
  override name = "LwsError";
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** Details used to construct an {@link HttpError}. */
export interface HttpErrorInit {
  status: number;
  method: string;
  url: string;
  headers: Headers;
  problem?: ProblemDetails | undefined;
  body?: string | undefined;
}

/** A non-success HTTP response. Subclasses identify the LWS abstract response. */
export class HttpError extends LwsError {
  override name = "HttpError";
  /** HTTP status code. */
  readonly status: number;
  /** Request method. */
  readonly method: string;
  /** Request URL. */
  readonly url: string;
  /** Response headers. */
  readonly headers: Headers;
  /** Parsed RFC 9457 problem details, when the server sent them. */
  readonly problem: ProblemDetails | undefined;
  /** Response body text (truncated to 4 KiB). */
  readonly body: string | undefined;

  constructor(init: HttpErrorInit, message?: string) {
    super(
      message ??
        `${init.method} ${init.url} failed with ${init.status}` +
          (init.problem?.title ? `: ${init.problem.title}` : "") +
          (init.problem?.detail ? ` — ${init.problem.detail}` : ""),
    );
    this.status = init.status;
    this.method = init.method;
    this.url = init.url;
    this.headers = init.headers;
    this.problem = init.problem;
    this.body = init.body;
  }
}

/** 400 Bad Request. */
export class BadRequestError extends HttpError {
  override name = "BadRequestError";
}
/** 401 Unauthorized — the LWS "unknown requester" response. */
export class UnauthorizedError extends HttpError {
  override name = "UnauthorizedError";
  /** Parsed `WWW-Authenticate` challenges. */
  get challenges(): AuthChallenge[] {
    return parseWwwAuthenticate(this.headers.get("www-authenticate"));
  }
}
/** 403 Forbidden — the LWS "not permitted" response. */
export class ForbiddenError extends HttpError {
  override name = "ForbiddenError";
}
/** 404 Not Found — the LWS "target not found" response. */
export class NotFoundError extends HttpError {
  override name = "NotFoundError";
}
/** 405 Method Not Allowed. */
export class MethodNotAllowedError extends HttpError {
  override name = "MethodNotAllowedError";
  /** Methods advertised in `Allow`. */
  get allow(): string[] {
    return splitHeaderList(this.headers.get("allow")).map((m) => m.toUpperCase());
  }
}
/** 406 Not Acceptable. */
export class NotAcceptableError extends HttpError {
  override name = "NotAcceptableError";
}
/** 409 Conflict — the LWS "conflict" response (e.g. deleting a non-empty container). */
export class ConflictError extends HttpError {
  override name = "ConflictError";
}
/** 410 Gone. */
export class GoneError extends HttpError {
  override name = "GoneError";
}
/** 412 Precondition Failed (an `If-Match` / `If-None-Match` check failed). */
export class PreconditionFailedError extends HttpError {
  override name = "PreconditionFailedError";
}
/** 415 Unsupported Media Type. */
export class UnsupportedMediaTypeError extends HttpError {
  override name = "UnsupportedMediaTypeError";
  /** Patch formats advertised in `Accept-Patch`. */
  get acceptPatch(): string[] {
    return splitHeaderList(this.headers.get("accept-patch")).map((m) => mediaTypeEssence(m) ?? m);
  }
  /** Query formats advertised in `Accept-Query`. */
  get acceptQuery(): string[] {
    return splitHeaderList(this.headers.get("accept-query")).map((m) => mediaTypeEssence(m.replace(/"/g, "")) ?? m);
  }
}
/** 422 Unprocessable Content. */
export class UnprocessableContentError extends HttpError {
  override name = "UnprocessableContentError";
}
/** 501 Not Implemented. */
export class NotImplementedError extends HttpError {
  override name = "NotImplementedError";
}
/** 507 Insufficient Storage — quota exceeded. */
export class InsufficientStorageError extends HttpError {
  override name = "InsufficientStorageError";
}

/** Failure of the LWS authorization flow (realm check, metadata, token exchange). */
export class AuthenticationError extends LwsError {
  override name = "AuthenticationError";
  /** OAuth `error` code from the token endpoint, if any. */
  readonly error: string | undefined;
  /** OAuth `error_description`, if any. */
  readonly errorDescription: string | undefined;
  constructor(message: string, options?: { error?: string | undefined; errorDescription?: string | undefined; cause?: unknown }) {
    super(message, options);
    this.error = options?.error;
    this.errorDescription = options?.errorDescription;
  }
}

/** The server's response violates the LWS specification (missing Location, wrong media type, bad JSON…). */
export class ProtocolError extends LwsError {
  override name = "ProtocolError";
}

/** A webhook delivery failed signature or digest verification. */
export class SignatureVerificationError extends LwsError {
  override name = "SignatureVerificationError";
}

const BY_STATUS: Record<number, typeof HttpError> = {
  400: BadRequestError,
  401: UnauthorizedError,
  403: ForbiddenError,
  404: NotFoundError,
  405: MethodNotAllowedError,
  406: NotAcceptableError,
  409: ConflictError,
  410: GoneError,
  412: PreconditionFailedError,
  415: UnsupportedMediaTypeError,
  422: UnprocessableContentError,
  501: NotImplementedError,
  507: InsufficientStorageError,
};

/** Create the matching {@link HttpError} subclass for a status. */
export function httpError(init: HttpErrorInit): HttpError {
  const Ctor = BY_STATUS[init.status] ?? HttpError;
  return new Ctor(init);
}

/** Build an {@link HttpError} from a failed fetch Response (consumes its body). */
export async function errorFromResponse(response: Response, method: string, url: string): Promise<HttpError> {
  let body: string | undefined;
  try {
    body = await response.text();
  } catch {
    body = undefined;
  }
  const problem = body ? parseProblemDetails(response.headers.get("content-type"), body) : undefined;
  return httpError({
    status: response.status,
    method,
    url,
    headers: response.headers,
    problem,
    body: body && body.length > 4096 ? body.slice(0, 4096) : body,
  });
}
