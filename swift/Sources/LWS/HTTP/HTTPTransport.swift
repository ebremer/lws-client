// SPDX-License-Identifier: MIT
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// One HTTP request, as handed to an ``HTTPTransport``.
public struct HTTPRequest: Sendable {
    /// The method (`GET`, `QUERY`, …).
    public var method: String
    /// The absolute target URL.
    public var url: URL
    /// The header fields (a name may repeat, e.g. `Link`).
    public var headers: HTTPHeaders
    /// The body, if any.
    public var body: Data?
    /// How long the request may take, in seconds (nil: no limit of the client's).
    public var timeout: TimeInterval?

    public init(method: String, url: URL, headers: HTTPHeaders = HTTPHeaders(), body: Data? = nil, timeout: TimeInterval? = nil) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        self.timeout = timeout
    }
}

/// One HTTP response, with its whole body.
public struct HTTPResponse: Sendable {
    /// The URL that answered: the request URL, unless the transport followed a redirect.
    public var url: URL
    /// The status code.
    public var status: Int
    /// The header fields.
    public var headers: HTTPHeaders
    /// The body (empty for `HEAD` and `304`).
    public var body: Data

    public init(url: URL, status: Int, headers: HTTPHeaders = HTTPHeaders(), body: Data = Data()) {
        self.url = url
        self.status = status
        self.headers = headers
        self.body = body
    }
}

/// The HTTP engine of an ``LWSClient`` and a ``TokenExchangeAuthenticator``: ``URLSessionTransport`` by default,
/// or any other (a test double, an AsyncHTTPClient adapter, …).
///
/// A transport sends exactly one request and must **not** follow redirects: the client follows them itself, so
/// that every hop is authorized for its own URL, and authorization server requests refuse them. Errors other
/// than ``LWSError`` and `CancellationError` become ``LWSError/transport(_:)``.
public protocol HTTPTransport: Sendable {
    /// Sends one request and returns the response with its whole body.
    func send(_ request: HTTPRequest) async throws -> HTTPResponse
}

/// The default transport: a private `URLSession` that follows no redirects and keeps no cookies or cache.
public final class URLSessionTransport: HTTPTransport, @unchecked Sendable {
    private let session: URLSession

    /// Creates the transport with its own session, made from `configuration` (default `.ephemeral`) with
    /// cookies and caching turned off.
    public init(configuration: URLSessionConfiguration = .ephemeral) {
        let c = configuration
        c.httpShouldSetCookies = false
        c.httpCookieAcceptPolicy = .never
        c.httpCookieStorage = nil
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = URLSession(configuration: c, delegate: RedirectRefuser(), delegateQueue: nil)
    }

    deinit {
        session.finishTasksAndInvalidate()
    }

    public func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        var r = URLRequest(url: request.url)
        r.httpMethod = request.method
        r.timeoutInterval = request.timeout ?? 3600
        for f in request.headers where !HTTPHeaders.same(f.name, "content-length") && !HTTPHeaders.same(f.name, "host") {
            r.addValue(f.value, forHTTPHeaderField: f.name)
        }
        r.httpBody = request.body
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: r)
        } catch let e as URLError {
            if e.code == .cancelled, Task.isCancelled { throw CancellationError() }
            let what = "\(request.method) \(request.url.absoluteString)"
            if e.code == .timedOut { throw LWSError.transport(TransportError("\(what) timed out", isTimeout: true, underlying: e)) }
            throw LWSError.transport(TransportError("\(what) failed: \(e.localizedDescription) (\(e.code.rawValue))", underlying: e))
        }
        guard let http = response as? HTTPURLResponse else {
            throw LWSError.transport(TransportError("\(request.method) \(request.url.absoluteString) got no HTTP response"))
        }
        var headers = HTTPHeaders()
        for (k, v) in http.allHeaderFields {
            guard let name = k as? String else { continue }
            headers.add(name, v as? String ?? String(describing: v))
        }
        return HTTPResponse(url: http.url ?? request.url, status: http.statusCode, headers: headers, body: data)
    }
}

/// Refuses every redirect, so that the 3xx response itself is returned.
private final class RedirectRefuser: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void)
    {
        completionHandler(nil)
    }
}

/// Runs `operation` with a time limit; exceeding it is a transport timeout (internal).
func withTimeLimit<T: Sendable>(_ seconds: TimeInterval?, _ what: @autoclosure () -> String,
                                _ operation: @escaping @Sendable () async throws -> T) async throws -> T
{
    guard let seconds, seconds > 0, seconds.isFinite else { return try await operation() }
    let description = what()
    return try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            throw LWSError.transport(TransportError("\(description) timed out after \(seconds.formatted()) s", isTimeout: true))
        }
        defer { group.cancelAll() }
        guard let first = try await group.next() else { throw CancellationError() }
        return first
    }
}

extension TimeInterval {
    fileprivate func formatted() -> String {
        self == rounded() ? String(Int64(self)) : String(self)
    }
}

/// Sends through a transport, turning foreign errors into transport errors (internal).
func sendThrough(_ transport: any HTTPTransport, _ request: HTTPRequest) async throws -> HTTPResponse {
    let what = "\(request.method) \(request.url.absoluteString)"
    do {
        return try await withTimeLimit(request.timeout, what) { try await transport.send(request) }
    } catch let e as LWSError {
        throw e
    } catch is CancellationError {
        throw CancellationError()
    } catch {
        throw LWSError.transport(TransportError("\(what) failed: \(error)", underlying: error))
    }
}
