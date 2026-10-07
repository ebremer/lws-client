// SPDX-License-Identifier: MIT
import Foundation

/// Pluggable request authentication for ``LWSClient``.
///
/// The client calls ``authorize(_:)`` before every request attempt (every redirect hop included, each for its own
/// URL). When an attempt is answered `401 Unauthorized` it calls ``handleChallenge(_:response:)``; returning true
/// makes it send the request once more, authorizing it again first.
///
/// Provided implementations: ``TokenExchangeAuthenticator`` (the LWS OAuth 2.0 token exchange flow) and
/// ``BearerTokenAuthenticator`` (a known access token). Others (cookies, DPoP, mTLS, …) implement this protocol.
public protocol Authenticator: Sendable {
    /// Returns the request with credentials added, typically an `Authorization` header.
    func authorize(_ request: AuthRequest) async throws -> AuthRequest

    /// Reacts to a `401` response, e.g. by obtaining a token; returns whether to send the request again.
    func handleChallenge(_ request: AuthRequest, response: AuthResponse) async throws -> Bool
}

/// A request attempt as an ``Authenticator`` sees it: method, target and headers.
public struct AuthRequest: Sendable, CustomStringConvertible {
    /// The request method.
    public let method: String
    /// The request URL.
    public let url: URL
    /// The request headers (a name may repeat, e.g. `Link`).
    public var headers: HTTPHeaders

    public init(method: String, url: URL, headers: HTTPHeaders = HTTPHeaders()) {
        self.method = method
        self.url = url
        self.headers = headers
    }

    public var description: String { "\(method) \(url.absoluteString)" }
}

/// A `401` response passed to ``Authenticator/handleChallenge(_:response:)``.
public struct AuthResponse: Sendable {
    /// The request URL.
    public let url: URL
    /// The status code.
    public let status: Int
    /// The response headers.
    public let headers: HTTPHeaders

    public init(url: URL, status: Int, headers: HTTPHeaders) {
        self.url = url
        self.status = status
        self.headers = headers
    }

    /// The parsed `WWW-Authenticate` challenges.
    public var challenges: [AuthChallenge] { WWWAuthenticate.parse(headers.all("www-authenticate")) }
}

/// Sends a known access token as `Authorization: Bearer …`, optionally only to URLs inside a realm (recommended,
/// so that the token never reaches another server).
public struct BearerTokenAuthenticator: Authenticator {
    private let token: @Sendable () async throws -> String?
    /// The realm the token is restricted to, or nil.
    public let realm: URL?

    /// Sends `token`, only to URLs inside `realm` when one is given (nil sends it everywhere: use a dedicated client).
    public init(token: String, realm: URL? = nil) {
        self.token = { token }
        self.realm = realm
    }

    /// Sends a token from `tokenSupplier`, asked per request (nil sends none).
    public init(realm: URL? = nil, tokenSupplier: @escaping @Sendable () async throws -> String?) {
        token = tokenSupplier
        self.realm = realm
    }

    public func authorize(_ request: AuthRequest) async throws -> AuthRequest {
        if let realm, !URLs.contains(realm: realm, request.url) { return request }
        guard let t = try await token() else { return request }
        var r = request
        r.headers.set("Authorization", "Bearer " + t)
        return r
    }

    public func handleChallenge(_ request: AuthRequest, response: AuthResponse) async throws -> Bool {
        false
    }
}
