// SPDX-License-Identifier: MIT
import Foundation

/// Options of ``TokenExchangeAuthenticator``.
public struct TokenExchangeOptions: Sendable {
    /// Allow plain-HTTP authorization servers beyond loopback hosts (testing only).
    public var allowInsecureHttp: Bool
    /// Decides whether to trust an authorization server (its issuer, first argument) for a storage (second argument)
    /// before any credential is sent to it. Default: trust every server that passes the discovery and HTTPS checks.
    ///
    /// A malicious storage can name any authorization server. Self-signed tokens are audience-bound to that
    /// server, but static OpenID or SAML tokens may not be: use this filter or audience-restricted tokens.
    public var authorizationServerFilter: (@Sendable (URL, URL) -> Bool)?
    /// The HTTP engine for discovery, metadata and token requests (default: a ``URLSessionTransport`` of its own).
    /// It must not follow redirects; a response from another URL than the one requested is refused.
    public var transport: (any HTTPTransport)?
    /// Refresh tokens this long before they expire, in seconds (default 30).
    public var refreshMargin: TimeInterval
    /// The time limit of each discovery, metadata and token request, in seconds (default 30).
    public var timeout: TimeInterval
    /// The `User-Agent` of discovery, metadata and token requests.
    public var userAgent: String?
    /// The clock.
    public var now: @Sendable () -> Date

    public init(allowInsecureHttp: Bool = false, authorizationServerFilter: (@Sendable (URL, URL) -> Bool)? = nil,
                transport: (any HTTPTransport)? = nil, refreshMargin: TimeInterval = 30, timeout: TimeInterval = 30,
                userAgent: String? = LWSClient.defaultUserAgent, now: @escaping @Sendable () -> Date = { Date() })
    {
        self.allowInsecureHttp = allowInsecureHttp
        self.authorizationServerFilter = authorizationServerFilter
        self.transport = transport
        self.refreshMargin = refreshMargin
        self.timeout = timeout
        self.userAgent = userAgent
        self.now = now
    }
}

/// The LWS authorization flow (OAuth 2.0 protected resource metadata, RFC 9728, and token exchange, RFC 8693):
///
/// 1. a request is answered `401` with `WWW-Authenticate: Bearer resource_metadata="…"` and a `Link` to the storage
///    that holds the resource;
/// 2. the metadata URL must be on the requested origin; the metadata (read without following a redirect) must name
///    the requested URL as its `resource`; the storage's description must put its root on the requested origin;
/// 3. the first of the metadata's `authorization_servers` that uses HTTPS (loopback hosts excepted) and passes the
///    optional filter is the issuer; its metadata is read from `/.well-known/lws-configuration` (never following a
///    redirect) and its `issuer` checked;
/// 4. the ``CredentialProvider``'s subject token is exchanged for an access token with `resource` = the storage;
/// 5. the request is sent again with the token, even where its URL lies outside the token's scope, as it has just
///    passed the checks; later the token is sent ahead (until 30 seconds before it expires) to every URL inside the
///    storage or its root, and nowhere else: a `401` elsewhere runs the checks again and reuses it.
///
/// A challenge with `as_uri` and `realm` instead, as in the drafts before 19 October 2026, is still followed: the
/// realm must contain the request URL, `as_uri` is the issuer, and the realm the storage and the token's only scope.
/// A challenge that fails a check is not acted on: a token the request carried stays cached.
///
/// Concurrent requests share a single in-flight exchange per issuer and storage.
public actor TokenExchangeAuthenticator: Authenticator {
    /// The credential provider.
    public nonisolated let credentials: any CredentialProvider
    private let options: TokenExchangeOptions
    private let transport: any HTTPTransport

    /// Where a challenge leads: the authorization server, the storage the token is for, and the URLs it is sent to.
    private struct Target: Sendable {
        let issuerText: String
        let issuer: URL
        let storage: URL
        let scopes: [URL]

        var key: String { issuerText + " " + storage.absoluteString }
    }

    private struct Entry: Sendable {
        let scopes: [URL]
        let token: AccessToken
    }

    private var tokens: [String: Entry] = [:]
    private var metadata: [String: AuthorizationServerMetadata] = [:]
    private var descriptions: [String: StorageDescription] = [:]
    private var inflight: [String: Task<Entry, any Error>] = [:]
    /// Request URL → the token its handled challenge led to, and how many retries of it are still to come.
    private var retries: [String: (token: AccessToken, pending: Int)] = [:]

    /// Creates the authenticator.
    public init(credentials: any CredentialProvider, options: TokenExchangeOptions = TokenExchangeOptions()) {
        self.credentials = credentials
        self.options = options
        transport = options.transport ?? URLSessionTransport()
    }

    public func authorize(_ request: AuthRequest) async throws -> AuthRequest {
        let now = options.now()
        var best: (length: Int, token: AccessToken)?
        for e in tokens.values where e.token.isValid(at: now, margin: options.refreshMargin) {
            for scope in e.scopes where URLs.contains(realm: scope, request.url) {
                // The longest scope wins; a path not ending in "/" counts as one that does.
                let path = URLs.path(scope)
                let length = path.hasSuffix("/") ? path.count : path.count + 1
                if best == nil || length > best!.length { best = (length, e.token) }
            }
        }
        guard let best else { return request }
        var r = request
        r.headers.set("Authorization", "Bearer " + best.token.value)
        return r
    }

    /// - Throws: ``LWSError/authentication(_:)`` when a discovery check fails (the metadata is on another origin or
    ///   describes another resource, the storage root is on another origin, …), the request URL is outside the realm
    ///   of a challenge of the drafts before 19 October 2026, no authorization server is secure and accepted, or the
    ///   token exchange failed. A cached token stays in use when the challenge is refused.
    public func handleChallenge(_ request: AuthRequest, response: AuthResponse) async throws -> Bool {
        let challenges = response.challenges
        let target: Target
        if let c = challenges.first(where: { $0.isScheme("Bearer") && $0.resourceMetadata != nil }) {
            target = try await discover(request.url, c.resourceMetadata!, response.headers)
        } else if let c = challenges.first(where: { $0.isScheme("Bearer") && $0.asURI != nil && $0.realm != nil }) {
            target = try legacyTarget(request.url, c.asURI!, c.realm!)
        } else {
            return false
        }
        // Every check comes before the cached token the request carried is touched: a decoy challenge must not
        // evict a working token. One that leads to the same issuer and storage refused it: exchange again.
        if let sent = request.headers.first("Authorization"), let cached = tokens[target.key], "Bearer " + cached.token.value == sent {
            tokens[target.key] = nil
        }
        let token: AccessToken
        if let cached = tokens[target.key], cached.token.isValid(at: options.now(), margin: options.refreshMargin) {
            token = cached.token  // obtained concurrently, or for another URL of the storage: reuse it
        } else {
            token = try await obtain(target).token
        }
        let url = request.url.absoluteString
        retries[url] = (token, (retries[url]?.pending ?? 0) + 1)
        return true
    }

    /// The retry of a request whose challenge passed the checks carries the token that challenge led to, even where
    /// its URL lies outside the token's scope; every other request is authorized by ``authorize(_:)``.
    public func authorizeRetry(_ request: AuthRequest) async throws -> AuthRequest {
        let url = request.url.absoluteString
        guard let retry = retries[url] else { return try await authorize(request) }
        retries[url] = retry.pending > 1 ? (retry.token, retry.pending - 1) : nil
        var r = request
        r.headers.set("Authorization", "Bearer " + retry.token.value)
        return r
    }

    /// Returns a valid access token for a storage from an authorization server (its issuer), performing the token
    /// exchange when needed. A token obtained here is sent ahead to URLs inside the storage.
    /// - Throws: ``LWSError/authentication(_:)`` when the exchange fails.
    public func accessToken(issuer: String, storage: String) async throws -> AccessToken {
        guard let issuerURL = URLs.resolve(issuer, against: nil) else { throw LWSError.invalidArgument("Not an absolute URL: \(issuer)") }
        guard let storageURL = URLs.resolve(storage, against: nil) else { throw LWSError.invalidArgument("Not an absolute URL: \(storage)") }
        let target = Target(issuerText: issuer, issuer: issuerURL, storage: storageURL, scopes: [storageURL])
        if let e = tokens[target.key], e.token.isValid(at: options.now(), margin: options.refreshMargin) { return e.token }
        try requireSecure(issuerURL, "authorization server")
        return try await obtain(target).token
    }

    /// Forgets every cached token, metadata document and storage description.
    public func clear() {
        tokens.removeAll()
        retries.removeAll()
        metadata.removeAll()
        descriptions.removeAll()
    }

    // MARK: - Discovery

    /// The checks of a challenge with `resource_metadata` (lws10-core "Discovery Validation by a Client"), in order,
    /// and the authorization server it leads to.
    private func discover(_ requestURL: URL, _ metadataText: String, _ headers: HTTPHeaders) async throws -> Target {
        guard let metadataURL = URLs.resolve(metadataText, against: requestURL), URLs.isHTTP(metadataURL) else {
            throw LWSError.authFailure("The challenge resource_metadata is not an http(s) URL: \(metadataText)")
        }
        guard URLs.sameOrigin(metadataURL, requestURL) else {
            throw LWSError.authFailure("The protected resource metadata \(metadataURL.absoluteString) is not on the origin of \(requestURL.absoluteString)")
        }
        guard let storage = LinkHeader.parse(headers.all("link"), base: requestURL).first(rel: LinkRelation.storage)?.href else {
            throw LWSError.authFailure("The 401 of \(requestURL.absoluteString) has no storage link (rel=\"\(LinkRelation.storage)\")")
        }
        let resourceMetadata = try await protectedResourceMetadata(metadataURL)
        guard URLs.isSameResource(resourceMetadata.resource, requestURL) else {
            throw LWSError.authFailure("The protected resource metadata \(metadataURL.absoluteString) describes \(resourceMetadata.resource), "
                + "not \(requestURL.absoluteString)")
        }
        let root: URL
        do {
            root = try await storageDescription(storage).storageRoot()
        } catch LWSError.protocolError(let m) {
            throw LWSError.authFailure("Invalid storage description at \(storage.absoluteString): \(m)")
        }
        guard URLs.sameOrigin(root, requestURL) else {
            throw LWSError.authFailure("The storage root \(root.absoluteString) of \(storage.absoluteString) is not on the origin of \(requestURL.absoluteString)")
        }
        for issuerText in resourceMetadata.authorizationServers {
            guard let issuer = URLs.resolve(issuerText, against: nil), URLs.isHTTP(issuer), isSecure(issuer) else { continue }
            if let filter = options.authorizationServerFilter, !filter(issuer, storage) { continue }
            return Target(issuerText: issuerText, issuer: issuer, storage: storage, scopes: [storage, root])
        }
        throw LWSError.authFailure("None of the authorization servers of \(metadataURL.absoluteString) "
            + "(\(resourceMetadata.authorizationServers.joined(separator: ", "))) uses HTTPS and passes the authorization server filter")
    }

    /// A challenge of the drafts before 19 October 2026: the realm must contain the request URL; `as_uri` is the
    /// issuer, and the realm is the storage the token is for and its only scope.
    private func legacyTarget(_ requestURL: URL, _ asText: String, _ realmText: String) throws -> Target {
        guard let issuer = URLs.resolve(asText, against: nil) else {
            throw LWSError.authFailure("The challenge as_uri is not an absolute URL: \(asText)")
        }
        guard let realm = URLs.resolve(realmText, against: nil) else {
            throw LWSError.authFailure("The challenge realm is not an absolute URL: \(realmText)")
        }
        guard URLs.contains(realm: realm, requestURL) else {
            throw LWSError.authFailure("Request URL \(requestURL.absoluteString) is not within the challenge realm \(realmText)")
        }
        try requireSecure(issuer, "authorization server")
        if let filter = options.authorizationServerFilter, !filter(issuer, realm) {
            throw LWSError.authFailure("Authorization server \(asText) was rejected by the authorization server filter")
        }
        return Target(issuerText: asText, issuer: issuer, storage: realm, scopes: [realm])
    }

    /// Reads protected resource metadata, without credentials or redirects. It is not cached: it describes one
    /// resource.
    private func protectedResourceMetadata(_ url: URL) async throws -> ProtectedResourceMetadata {
        let r = try await sendRefusingRedirects(HTTPRequest(method: "GET", url: url, headers: ["Accept": MediaType.json]), "protected resource metadata")
        guard r.status == 200 else {
            throw LWSError.authFailure("Cannot read protected resource metadata \(url.absoluteString): HTTP \(r.status)", status: r.status)
        }
        guard HeaderLists.isJSON(r.headers.first("content-type") ?? MediaType.json) else {
            throw LWSError.authFailure("Protected resource metadata \(url.absoluteString) is not JSON", status: r.status)
        }
        do {
            return try ProtectedResourceMetadata.parse(LWSJSON.parse(r.body, "Protected resource metadata"))
        } catch LWSError.protocolError(let m) {
            throw LWSError.authFailure("Invalid protected resource metadata at \(url.absoluteString): \(m)", status: r.status)
        }
    }

    /// Reads a storage description, without credentials or redirects, and keeps it until ``clear()``.
    private func storageDescription(_ storage: URL) async throws -> StorageDescription {
        if let cached = descriptions[storage.absoluteString] { return cached }
        let r = try await sendRefusingRedirects(HTTPRequest(method: "GET", url: storage, headers: ["Accept": StorageDescription.accept]),
                                                "storage description")
        guard r.status == 200 else {
            throw LWSError.authFailure("Cannot read the storage description \(storage.absoluteString): HTTP \(r.status)", status: r.status)
        }
        let description = try StorageDescription.parse(contentType: r.headers.first("content-type"), body: r.body, url: storage)
        descriptions[storage.absoluteString] = description
        return description
    }

    // MARK: - Token exchange

    private func obtain(_ target: Target) async throws -> Entry {
        let key = target.key
        if let running = inflight[key] { return try await running.value }
        let task = Task<Entry, any Error> {
            defer { self.inflight[key] = nil }
            let entry = Entry(scopes: target.scopes, token: try await self.exchange(target))
            self.tokens[key] = entry
            return entry
        }
        inflight[key] = task
        return try await task.value
    }

    private func exchange(_ target: Target) async throws -> AccessToken {
        let md = try await serverMetadata(target.issuerText, target.issuer)
        try requireSecure(md.tokenEndpoint, "token endpoint")
        guard md.supportsSubjectTokenType(credentials.tokenType) else {
            throw LWSError.authFailure("Authorization server \(target.issuerText) does not accept subject tokens of type \(credentials.tokenType) "
                + "(supported: \(md.subjectTokenTypesSupported.joined(separator: ", ")))")
        }
        let credentials = self.credentials
        let context = CredentialContext(issuer: target.issuer, storage: target.storage, metadata: md)
        let subjectToken = try await withTimeLimit(options.timeout, "The credential provider") {
            try await credentials.subjectToken(for: context)
        }
        let form = [
            ("grant_type", Vocabulary.grantTypeTokenExchange),
            ("resource", target.storage.absoluteString),
            ("subject_token", subjectToken),
            ("subject_token_type", self.credentials.tokenType),
        ].map { Self.formEncode($0.0) + "=" + Self.formEncode($0.1) }.joined(separator: "&")
        let r = try await post(md.tokenEndpoint, Data(form.utf8), "token endpoint")
        let json = r.body.isEmpty ? nil : (try? JSONValue(parsing: r.body))?.objectValue
        guard r.status / 100 == 2 else {
            let error = json?.string("error")
            let description = json?.string("error_description")
            throw LWSError.authFailure("Token exchange at \(md.tokenEndpoint.absoluteString) failed with HTTP \(r.status)"
                + (error.map { ": " + $0 } ?? "") + (description.map { " (\($0))" } ?? ""),
                error: error, errorDescription: description, status: r.status)
        }
        guard let json else { throw LWSError.authFailure("The token endpoint returned no JSON object", status: r.status) }
        return try AccessToken.fromTokenResponse(json, now: options.now())
    }

    private func serverMetadata(_ issuerText: String, _ issuer: URL) async throws -> AuthorizationServerMetadata {
        if let cached = metadata[issuerText] { return cached }
        let url = AuthorizationServerMetadata.metadataURL(issuer: issuer)
        let r = try await sendRefusingRedirects(HTTPRequest(method: "GET", url: url, headers: ["Accept": MediaType.json]), "authorization server metadata")
        guard r.status == 200 else {
            throw LWSError.authFailure("Cannot read authorization server metadata \(url.absoluteString): HTTP \(r.status)", status: r.status)
        }
        guard HeaderLists.isJSON(r.headers.first("content-type") ?? MediaType.json) else {
            throw LWSError.authFailure("Authorization server metadata \(url.absoluteString) is not JSON", status: r.status)
        }
        let md: AuthorizationServerMetadata
        do {
            md = try AuthorizationServerMetadata.parse(LWSJSON.parse(r.body, "Authorization server metadata"), base: url)
        } catch LWSError.protocolError(let m) {
            throw LWSError.authFailure("Invalid authorization server metadata at \(url.absoluteString): \(m)", status: r.status)
        }
        let sameIssuer = URLs.equalsIgnoringTrailingSlash(md.issuer, issuerText)
            || URLs.resolve(md.issuer, against: nil).map { URLs.equalsIgnoringTrailingSlash(URLs.canonical($0), URLs.canonical(issuer)) } == true
        guard sameIssuer else {
            throw LWSError.authFailure("Authorization server metadata issuer \(md.issuer) does not match the issuer \(issuerText)", status: r.status)
        }
        metadata[issuerText] = md
        return md
    }

    private func post(_ url: URL, _ body: Data, _ what: String) async throws -> HTTPResponse {
        try await sendRefusingRedirects(
            HTTPRequest(method: "POST", url: url, headers: ["Content-Type": MediaType.form, "Accept": MediaType.json], body: body), what)
    }

    /// Sends a discovery, metadata or token request; a redirect is refused, since it would carry the subject token, or
    /// the checks of the flow, to another URL.
    private func sendRefusingRedirects(_ request: HTTPRequest, _ what: String) async throws -> HTTPResponse {
        var r = request
        if let ua = options.userAgent { r.headers.set("User-Agent", ua) }
        r.timeout = options.timeout
        let response = try await sendThrough(transport, r)
        if (300..<400).contains(response.status) || response.url.absoluteString != request.url.absoluteString {
            let location = response.headers.first("location").map { " to \($0)" } ?? ""
            throw LWSError.authFailure("Refusing the redirect\(location) of the \(what) request \(request.url.absoluteString) "
                + "(HTTP \(response.status)): discovery, metadata and token requests follow no redirect", status: response.status)
        }
        return response
    }

    private func isSecure(_ url: URL) -> Bool {
        switch url.scheme?.lowercased() {
        case "https": return true
        case "http": return options.allowInsecureHttp || URLs.isLoopback(url)
        default: return false
        }
    }

    private func requireSecure(_ url: URL, _ what: String) throws {
        guard isSecure(url) else { throw LWSError.authFailure("Refusing to use the insecure \(what) \(url.absoluteString) (HTTPS required)") }
    }

    /// `application/x-www-form-urlencoded` encoding: unreserved characters kept, space as `+`.
    static func formEncode(_ s: String) -> String {
        var out = ""
        for b in s.utf8 {
            switch b {
            case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "0")...UInt8(ascii: "9"),
                 UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "~"):
                out.unicodeScalars.append(Unicode.Scalar(b))
            case UInt8(ascii: " "):
                out += "+"
            default:
                out += "%" + String(format: "%02X", b)
            }
        }
        return out
    }
}
