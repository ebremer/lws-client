// SPDX-License-Identifier: MIT
import Foundation

/// Every error the LWS client throws.
///
/// An error status maps to one case per LWS abstract response (``notFound(_:)``, ``conflict(_:)``,
/// ``preconditionFailed(_:)``, …), each carrying the full ``HTTPError``; other statuses, 5xx (the LWS "unknown
/// error") included, are ``http(_:)``.
///
/// ```swift
/// do {
///     try await client.update(note, body: Data("again".utf8), contentType: "text/plain", options: .init(ifMatch: etag))
/// } catch LWSError.preconditionFailed {
///     // someone changed it meanwhile
/// }
/// ```
public enum LWSError: Error, Sendable, CustomStringConvertible, LocalizedError {
    /// 400 Bad Request.
    case badRequest(HTTPError)
    /// 401 Unauthorized ("unknown requester"), after authentication handling; see ``HTTPError/challenges``.
    case unauthorized(HTTPError)
    /// 403 Forbidden ("not permitted").
    case forbidden(HTTPError)
    /// 404 Not Found ("target not found").
    case notFound(HTTPError)
    /// 405 Method Not Allowed; see ``HTTPError/allow``.
    case methodNotAllowed(HTTPError)
    /// 406 Not Acceptable.
    case notAcceptable(HTTPError)
    /// 409 Conflict ("conflict"), e.g. deleting a non-empty container without recursion.
    case conflict(HTTPError)
    /// 410 Gone.
    case gone(HTTPError)
    /// 412 Precondition Failed: an `If-Match` / `If-None-Match` condition did not hold.
    case preconditionFailed(HTTPError)
    /// 415 Unsupported Media Type; see ``HTTPError/acceptPatch`` and ``HTTPError/acceptQuery``.
    case unsupportedMediaType(HTTPError)
    /// 422 Unprocessable Content.
    case unprocessableContent(HTTPError)
    /// 501 Not Implemented.
    case notImplemented(HTTPError)
    /// 507 Insufficient Storage ("quota exceeded").
    case insufficientStorage(HTTPError)
    /// Any other error status.
    case http(HTTPError)
    /// Obtaining an access token failed: realm, HTTPS, filter or issuer checks, or a refused token exchange.
    case authentication(AuthenticationError)
    /// A server response violates the specification (a missing `Location`, a wrong media type, bad JSON, …).
    case protocolError(String)
    /// A webhook delivery failed verification.
    case signatureVerification(String)
    /// No response: connection failure, TLS failure or timeout.
    case transport(TransportError)
    /// An argument is not acceptable: a URL that is not absolute http(s), an invalid query or key, ….
    case invalidArgument(String)

    /// The error for an error response, by status.
    public static func from(_ error: HTTPError) -> LWSError {
        switch error.status {
        case 400: return .badRequest(error)
        case 401: return .unauthorized(error)
        case 403: return .forbidden(error)
        case 404: return .notFound(error)
        case 405: return .methodNotAllowed(error)
        case 406: return .notAcceptable(error)
        case 409: return .conflict(error)
        case 410: return .gone(error)
        case 412: return .preconditionFailed(error)
        case 415: return .unsupportedMediaType(error)
        case 422: return .unprocessableContent(error)
        case 501: return .notImplemented(error)
        case 507: return .insufficientStorage(error)
        default: return .http(error)
        }
    }

    /// The error response, for the HTTP cases.
    public var httpError: HTTPError? {
        switch self {
        case .badRequest(let e), .unauthorized(let e), .forbidden(let e), .notFound(let e), .methodNotAllowed(let e),
             .notAcceptable(let e), .conflict(let e), .gone(let e), .preconditionFailed(let e), .unsupportedMediaType(let e),
             .unprocessableContent(let e), .notImplemented(let e), .insufficientStorage(let e), .http(let e):
            return e
        default:
            return nil
        }
    }

    /// The HTTP status: of the error response, or of the authorization server response that failed.
    public var status: Int? {
        if let e = httpError { return e.status }
        if case .authentication(let a) = self { return a.status }
        return nil
    }

    public var description: String {
        switch self {
        case .badRequest(let e): return "bad request: \(e)"
        case .unauthorized(let e): return "unauthorized: \(e)"
        case .forbidden(let e): return "forbidden: \(e)"
        case .notFound(let e): return "not found: \(e)"
        case .methodNotAllowed(let e): return "method not allowed: \(e)"
        case .notAcceptable(let e): return "not acceptable: \(e)"
        case .conflict(let e): return "conflict: \(e)"
        case .gone(let e): return "gone: \(e)"
        case .preconditionFailed(let e): return "precondition failed: \(e)"
        case .unsupportedMediaType(let e): return "unsupported media type: \(e)"
        case .unprocessableContent(let e): return "unprocessable content: \(e)"
        case .notImplemented(let e): return "not implemented: \(e)"
        case .insufficientStorage(let e): return "insufficient storage: \(e)"
        case .http(let e): return "HTTP error: \(e)"
        case .authentication(let a): return "authentication failed: \(a.message)"
        case .protocolError(let m): return "protocol error: \(m)"
        case .signatureVerification(let m): return "signature verification failed: \(m)"
        case .transport(let t): return "transport error: \(t.message)"
        case .invalidArgument(let m): return "invalid argument: \(m)"
        }
    }

    public var errorDescription: String? { description }
}

/// An error response: the request, the status, the headers and the body.
public struct HTTPError: Sendable, CustomStringConvertible {
    /// The longest body text kept, in bytes.
    public static let maxBodyLength = 4096

    /// The HTTP status code.
    public let status: Int
    /// The request method.
    public let method: String
    /// The request URL (of the final redirect hop).
    public let url: URL
    /// The response headers.
    public let headers: HTTPHeaders
    /// The RFC 9457 problem details, when the body carried them.
    public let problem: ProblemDetails?
    /// The response body as text (truncated to ``maxBodyLength`` bytes).
    public let body: String

    public init(status: Int, method: String, url: URL, headers: HTTPHeaders, body: Data) {
        self.status = status
        self.method = method
        self.url = url
        self.headers = headers
        problem = ProblemDetails.parse(contentType: headers.first("content-type"), body: body)
        self.body = String(decoding: body.prefix(Self.maxBodyLength), as: UTF8.self)
    }

    /// The challenges of the `WWW-Authenticate` header (for a 401).
    public var challenges: [AuthChallenge] { WWWAuthenticate.parse(headers.all("www-authenticate")) }

    /// The methods of the `Allow` header (for a 405).
    public var allow: [String] { HeaderLists.split(headers.all("allow")) }

    /// The media types of the `Accept-Patch` header (for a 415 answering a PATCH).
    public var acceptPatch: [String] { HeaderLists.split(headers.all("accept-patch")) }

    /// The media types of the `Accept-Query` header (for a 415 answering a QUERY).
    public var acceptQuery: [String] { HeaderLists.split(headers.all("accept-query")).map(HeaderLists.unquote) }

    /// The links of the response (e.g. the storage link of a 401).
    public var links: [Link] { LinkHeader.parse(headers.all("link"), base: url) }

    public var description: String {
        var s = "\(method) \(url.absoluteString) failed with HTTP \(status)"
        if let title = problem?.title { s += ": " + title }
        if let detail = problem?.detail { s += " (" + detail + ")" }
        return s
    }
}

/// Why obtaining an access token failed. A refused token exchange carries the OAuth `error` code and the
/// status of the token endpoint's response.
public struct AuthenticationError: Sendable, CustomStringConvertible {
    /// What happened.
    public let message: String
    /// The OAuth 2.0 `error` code (RFC 6749 section 5.2), when the token endpoint returned one.
    public let error: String?
    /// The OAuth 2.0 `error_description`, when present.
    public let errorDescription: String?
    /// The HTTP status of the authorization server response that failed, when there was one.
    public let status: Int?
    /// The underlying error, if any.
    public let underlying: (any Error)?

    public init(_ message: String, error: String? = nil, errorDescription: String? = nil, status: Int? = nil,
                underlying: (any Error)? = nil)
    {
        self.message = message
        self.error = error
        self.errorDescription = errorDescription
        self.status = status
        self.underlying = underlying
    }

    public var description: String { message }
}

/// Why no response arrived: connection refused, TLS failure or timeout.
public struct TransportError: Sendable, CustomStringConvertible {
    /// What happened.
    public let message: String
    /// Whether the request timed out.
    public let isTimeout: Bool
    /// The HTTP stack's error (a `URLError` with ``URLSessionTransport``).
    public let underlying: (any Error)?

    public init(_ message: String, isTimeout: Bool = false, underlying: (any Error)? = nil) {
        self.message = message
        self.isTimeout = isTimeout
        self.underlying = underlying
    }

    public var description: String { message }
}

extension LWSError {
    static func authFailure(_ message: String, error: String? = nil, errorDescription: String? = nil, status: Int? = nil,
                            underlying: (any Error)? = nil) -> LWSError
    {
        .authentication(AuthenticationError(message, error: error, errorDescription: errorDescription, status: status, underlying: underlying))
    }
}
