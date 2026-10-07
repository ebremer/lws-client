// SPDX-License-Identifier: MIT
import Foundation

/// The configuration of an ``LWSClient``.
public struct LWSClientOptions: Sendable {
    /// The HTTP engine (default: a ``URLSessionTransport``). It must not follow redirects: the client follows them
    /// itself, so that credentials are evaluated afresh for every target.
    public var transport: any HTTPTransport
    /// Request authentication (e.g. ``TokenExchangeAuthenticator``); anonymous when nil.
    public var authenticator: (any Authenticator)?
    /// The `User-Agent` header (default `lws-client-swift/0.1.0`; nil sends the transport's own).
    public var userAgent: String?
    /// Headers sent with every request.
    public var defaultHeaders: HTTPHeaders
    /// The time limit of each HTTP request (each redirect hop), in seconds; default 30, nil for none.
    public var timeout: TimeInterval?
    /// The most redirects followed for one operation (default 10).
    public var maxRedirects: Int

    public init(transport: (any HTTPTransport)? = nil, authenticator: (any Authenticator)? = nil,
                userAgent: String? = LWSClient.defaultUserAgent, defaultHeaders: HTTPHeaders = HTTPHeaders(),
                timeout: TimeInterval? = 30, maxRedirects: Int = 10)
    {
        self.transport = transport ?? URLSessionTransport()
        self.authenticator = authenticator
        self.userAgent = userAgent
        self.defaultHeaders = defaultHeaders
        self.timeout = timeout
        self.maxRedirects = maxRedirects
    }
}

/// What every operation's options carry: extra headers and a time limit.
public protocol OperationOptions: Sendable {
    /// Extra request headers (they replace defaults of the same name).
    var headers: HTTPHeaders { get }
    /// A time limit for this operation's requests, instead of ``LWSClientOptions/timeout``.
    var timeout: TimeInterval? { get }
}

/// Options accepted by every operation.
public struct RequestOptions: OperationOptions {
    public var headers: HTTPHeaders
    public var timeout: TimeInterval?

    public init(headers: HTTPHeaders = HTTPHeaders(), timeout: TimeInterval? = nil) {
        self.headers = headers
        self.timeout = timeout
    }
}

/// A byte range of a read: `bytes=start-end`, `bytes=start-` or the last bytes, `bytes=-length`.
public struct ByteRange: Sendable, Hashable {
    /// The first byte, or nil for a suffix range.
    public let start: Int64?
    /// The last byte (inclusive), or nil for an open-ended range (or the suffix length when `start` is nil).
    public let end: Int64?

    private init(start: Int64?, end: Int64?) {
        self.start = start
        self.end = end
    }

    /// Bytes `range.lowerBound` to `range.upperBound`, inclusive.
    public static func bytes(_ range: ClosedRange<Int64>) -> ByteRange { ByteRange(start: range.lowerBound, end: range.upperBound) }
    /// Every byte from `start` on.
    public static func from(_ start: Int64) -> ByteRange { ByteRange(start: start, end: nil) }
    /// The last `length` bytes.
    public static func suffix(_ length: Int64) -> ByteRange { ByteRange(start: nil, end: length) }

    /// The `Range` header value.
    public var headerValue: String {
        "bytes=" + (start.map(String.init) ?? "") + "-" + (end.map(String.init) ?? "")
    }
}

/// Options of ``LWSClient/read(_:options:)``.
public struct ReadOptions: OperationOptions {
    /// The `Accept` header (content negotiation).
    public var accept: String?
    /// A byte range.
    public var range: ByteRange?
    /// Conditional read: answered `304` (``Resource/notModified``) while the entity tag matches.
    public var ifNoneMatch: String?
    /// Conditional read by date.
    public var ifModifiedSince: Date?
    /// The `Prefer` header (e.g. link relation preferences).
    public var prefer: String?
    public var headers: HTTPHeaders
    public var timeout: TimeInterval?

    public init(accept: String? = nil, range: ByteRange? = nil, ifNoneMatch: String? = nil, ifModifiedSince: Date? = nil,
                prefer: String? = nil, headers: HTTPHeaders = HTTPHeaders(), timeout: TimeInterval? = nil)
    {
        self.accept = accept
        self.range = range
        self.ifNoneMatch = ifNoneMatch
        self.ifModifiedSince = ifModifiedSince
        self.prefer = prefer
        self.headers = headers
        self.timeout = timeout
    }
}

/// Options of the create operations.
public struct CreateOptions: OperationOptions {
    /// The identity hint for the new resource's name, sent as `Slug`.
    public var slug: String?
    /// User-managed metadata links, sent as `Link` headers.
    public var links: [Link]
    /// Additional type IRIs, sent as `Link: <type>; rel="type"`.
    public var types: [String]
    public var headers: HTTPHeaders
    public var timeout: TimeInterval?

    public init(slug: String? = nil, links: [Link] = [], types: [String] = [], headers: HTTPHeaders = HTTPHeaders(),
                timeout: TimeInterval? = nil)
    {
        self.slug = slug
        self.links = links
        self.types = types
        self.headers = headers
        self.timeout = timeout
    }
}

/// Options of ``LWSClient/update(_:body:contentType:options:)`` and the patch operations.
public struct UpdateOptions: OperationOptions {
    /// Only update while the current entity tag matches (optimistic concurrency); else
    /// ``LWSError/preconditionFailed(_:)``.
    public var ifMatch: String?
    /// `If-None-Match` (e.g. `"*"` to create only).
    public var ifNoneMatch: String?
    /// Links sent with the update (applied to the linkset only with ``setLinkset``).
    public var links: [Link]
    /// Update the content and the linkset atomically (`Prefer: set-linkset`).
    public var setLinkset: Bool
    public var headers: HTTPHeaders
    public var timeout: TimeInterval?

    public init(ifMatch: String? = nil, ifNoneMatch: String? = nil, links: [Link] = [], setLinkset: Bool = false,
                headers: HTTPHeaders = HTTPHeaders(), timeout: TimeInterval? = nil)
    {
        self.ifMatch = ifMatch
        self.ifNoneMatch = ifNoneMatch
        self.links = links
        self.setLinkset = setLinkset
        self.headers = headers
        self.timeout = timeout
    }
}

/// Options of ``LWSClient/delete(_:options:)``.
public struct DeleteOptions: OperationOptions {
    /// Only delete while the current entity tag matches.
    public var ifMatch: String?
    /// Delete a container and everything in it (`Depth: infinity`).
    public var recursive: Bool
    public var headers: HTTPHeaders
    public var timeout: TimeInterval?

    public init(ifMatch: String? = nil, recursive: Bool = false, headers: HTTPHeaders = HTTPHeaders(), timeout: TimeInterval? = nil) {
        self.ifMatch = ifMatch
        self.recursive = recursive
        self.headers = headers
        self.timeout = timeout
    }
}
