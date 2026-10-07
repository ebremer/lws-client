// SPDX-License-Identifier: MIT
import Foundation

/// Client for the W3C Linked Web Storage (LWS) Protocol 1.0.
///
/// ```swift
/// let me = try SelfSignedCredentials.didKey(.generateP256())
/// let client = LWSClient(authenticator: TokenExchangeAuthenticator(credentials: me))
/// let storage = try await client.discoverStorage(URL(string: "https://storage.example/root/")!)
/// let note = try await client.createText(in: try storage.storageRoot(), text: "Hello", options: .init(slug: "hello.txt"))
/// for try await item in client.listContainer(try storage.storageRoot()) { print(item.id) }
/// ```
///
/// Instances are immutable and safe to share between tasks. Every operation is `async` and honours task
/// cancellation; errors are ``LWSError``s (``LWSError/notFound(_:)``, ``LWSError/preconditionFailed(_:)``,
/// ``LWSError/conflict(_:)``, …), and arguments that are not absolute http(s) URLs are
/// ``LWSError/invalidArgument(_:)``.
///
/// Redirects are followed by the client itself (at most ``LWSClientOptions/maxRedirects``), authorizing every hop
/// afresh for its own URL, so that an access token never leaves its realm. `POST` is never sent twice, except for
/// the single retry after a `401` that the authenticator handled (when nothing was created).
public final class LWSClient: Sendable {
    /// The library version.
    public static let version = "0.1.0"
    /// The default `User-Agent`.
    public static let defaultUserAgent = "lws-client-swift/" + version

    /// The configuration.
    public let options: LWSClientOptions

    /// Creates a client.
    /// - Throws: nothing; invalid options (a negative ``LWSClientOptions/maxRedirects``) are clamped.
    public init(options: LWSClientOptions = LWSClientOptions()) {
        var o = options
        o.maxRedirects = max(0, o.maxRedirects)
        self.options = o
    }

    /// Creates a client with an authenticator and the default options.
    public convenience init(authenticator: (any Authenticator)?) {
        self.init(options: LWSClientOptions(authenticator: authenticator))
    }

    /// The configured authenticator, if any.
    public var authenticator: (any Authenticator)? { options.authenticator }

    /// A client with another authenticator, sharing this client's transport.
    public func withAuthenticator(_ authenticator: (any Authenticator)?) -> LWSClient {
        var o = options
        o.authenticator = authenticator
        return LWSClient(options: o)
    }

    // MARK: - The request pipeline

    struct Call: Sendable {
        var method: String
        var url: URL
        var body: Data?
        var headers: HTTPHeaders
        var timeout: TimeInterval?
    }

    /// The final response of a call, with the method and URL of the hop that produced it.
    struct Answer: Sendable {
        let method: String
        let url: URL
        let status: Int
        let headers: HTTPHeaders
        let body: Data

        var metadata: ResourceMetadata { ResourceMetadata(url: url, status: status, headers: headers) }

        /// Throws the error for a non-2xx status.
        func check() throws {
            guard status / 100 == 2 else {
                throw LWSError.from(HTTPError(status: status, method: method, url: url, headers: headers, body: body))
            }
        }
    }

    private static let redirects: Set<Int> = [301, 302, 303, 307, 308]
    private static let safeMethods: Set<String> = ["GET", "HEAD", "OPTIONS", "QUERY"]

    /// Sends a call: authenticating, retrying once after a handled 401, following redirects.
    func send(_ call: Call) async throws -> Answer {
        var method = call.method
        var url = call.url
        var body = call.body
        var headers = call.headers
        let timeout = call.timeout ?? options.timeout
        var userAuth = headers.contains("Authorization") || options.defaultHeaders.contains("Authorization")
        var hops = 0
        while true {
            var attempt = try await prepare(method, url, headers, keepUserAuthorization: userAuth)
            var response = try await dispatch(attempt, body, timeout)
            if response.status == 401, let authenticator = options.authenticator {
                let retry = try await authenticator.handleChallenge(attempt, response: AuthResponse(url: url, status: 401, headers: response.headers))
                if retry {
                    attempt = try await prepare(method, url, headers, keepUserAuthorization: userAuth)
                    response = try await dispatch(attempt, body, timeout)
                }
            }
            let answer = Answer(method: method, url: url, status: response.status, headers: response.headers, body: response.body)
            guard Self.redirects.contains(response.status),
                  let location = response.headers.first("location"),
                  let target = URLs.resolve(location, against: url), URLs.isHTTP(target)
            else { return answer }
            let safe = Self.safeMethods.contains(method)
            switch response.status {
            case 303 where safe:
                // See Other: retrieve the result with GET (HEAD stays HEAD), without a body.
                if method != "HEAD" { method = "GET" }
                body = nil
                headers = HTTPHeaders(headers.filter { !$0.name.lowercased().hasPrefix("content-") }.map { ($0.name, $0.value) })
            case 301 where safe, 302 where safe, 307, 308:
                break
            default:
                return answer
            }
            hops += 1
            if hops > options.maxRedirects {
                throw LWSError.protocolError("Too many redirects (more than \(options.maxRedirects)) at \(url.absoluteString)")
            }
            // An Authorization header the caller set explicitly survives same-origin redirects only; the
            // authenticator's tokens are evaluated afresh for the new URL.
            if userAuth, !URLs.sameOrigin(url, target) { userAuth = false }
            url = target
        }
    }

    private func prepare(_ method: String, _ url: URL, _ callHeaders: HTTPHeaders, keepUserAuthorization: Bool) async throws -> AuthRequest {
        var request = AuthRequest(method: method, url: url, headers: options.defaultHeaders)
        if let ua = options.userAgent, !request.headers.contains("User-Agent"), !callHeaders.contains("User-Agent") {
            request.headers.add("User-Agent", ua)
        }
        for name in callHeaders.names { request.headers.remove(name) }
        for f in callHeaders { request.headers.add(f.name, f.value) }
        if !keepUserAuthorization { request.headers.remove("Authorization") }
        if let authenticator = options.authenticator { request = try await authenticator.authorize(request) }
        return request
    }

    private func dispatch(_ attempt: AuthRequest, _ body: Data?, _ timeout: TimeInterval?) async throws -> HTTPResponse {
        try await sendThrough(options.transport, HTTPRequest(method: attempt.method, url: attempt.url, headers: attempt.headers, body: body, timeout: timeout))
    }
}

/// A lazy listing: pages are fetched as the sequence is iterated, following `rel="next"` links (a page seen before
/// ends the listing).
///
/// ```swift
/// for try await item in client.listContainer(folder) { print(item.id) }
/// ```
public struct PagedSequence<Element: Sendable>: AsyncSequence, Sendable {
    /// One page: its elements and the next page's URL.
    public typealias Page = (elements: [Element], next: URL?)

    private let firstURL: String?
    private let load: @Sendable () async throws -> Page
    private let fetch: @Sendable (URL) async throws -> Page

    init(first: URL?, load: @escaping @Sendable () async throws -> Page, fetch: @escaping @Sendable (URL) async throws -> Page) {
        firstURL = first?.absoluteString
        self.load = load
        self.fetch = fetch
    }

    public func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(firstURL: firstURL, load: load, fetch: fetch)
    }

    /// Every element, fetching every page.
    public func collect() async throws -> [Element] {
        var out: [Element] = []
        for try await e in self { out.append(e) }
        return out
    }

    /// Iterates a ``PagedSequence``.
    public struct AsyncIterator: AsyncIteratorProtocol {
        private let load: @Sendable () async throws -> Page
        private let fetch: @Sendable (URL) async throws -> Page
        private var buffer: [Element] = []
        private var index = 0
        private var nextURL: URL?
        private var started = false
        private var seen: Set<String> = []

        init(firstURL: String?, load: @escaping @Sendable () async throws -> Page, fetch: @escaping @Sendable (URL) async throws -> Page) {
            self.load = load
            self.fetch = fetch
            if let firstURL { seen.insert(firstURL) }
        }

        public mutating func next() async throws -> Element? {
            while true {
                if index < buffer.count {
                    index += 1
                    return buffer[index - 1]
                }
                let page: Page
                if !started {
                    started = true
                    page = try await load()
                } else {
                    guard let n = nextURL, seen.insert(n.absoluteString).inserted else { return nil }
                    page = try await fetch(n)
                }
                buffer = page.elements
                index = 0
                nextURL = page.next
            }
        }
    }
}
