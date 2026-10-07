// SPDX-License-Identifier: MIT
import Foundation

/// Options of ``TokenExchangeAuthenticator``.
public struct TokenExchangeOptions: Sendable {
    /// Allow plain-HTTP authorization servers beyond loopback hosts (testing only).
    public var allowInsecureHttp: Bool
    /// Decides whether to trust an authorization server (`as_uri`, first argument) for a realm (second argument)
    /// before any credential is sent to it. Default: trust every server that passes the realm and HTTPS checks.
    ///
    /// A malicious storage can name any authorization server. Self-signed tokens are audience-bound to that
    /// server, but static OpenID or SAML tokens may not be: use this filter or audience-restricted tokens.
    public var authorizationServerFilter: (@Sendable (URL, URL) -> Bool)?
    /// The HTTP engine for metadata and token requests (default: a ``URLSessionTransport`` of its own). It must not
    /// follow redirects; a response from another URL than the one requested is refused.
    public var transport: (any HTTPTransport)?
    /// Refresh tokens this long before they expire, in seconds (default 30).
    public var refreshMargin: TimeInterval
    /// The time limit of each metadata and token request, in seconds (default 30).
    public var timeout: TimeInterval
    /// The `User-Agent` of metadata and token requests.
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

/// The LWS authorization flow (OAuth 2.0 token exchange, RFC 8693):
///
/// 1. a request is answered `401` with `WWW-Authenticate: Bearer as_uri="…", realm="…"`;
/// 2. the request URL must lie inside the realm, the authorization server must use HTTPS (loopback hosts
///    excepted) and pass the optional filter;
/// 3. the authorization server metadata is read from `/.well-known/lws-configuration` (never following a
///    redirect) and its `issuer` checked;
/// 4. the ``CredentialProvider``'s subject token is exchanged for an access token with `resource = realm`;
/// 5. the request is sent again with the token, and the token is reused (until 30 seconds before it expires) for
///    every URL inside the realm, and never sent outside it.
///
/// Concurrent requests share a single in-flight exchange per realm.
public actor TokenExchangeAuthenticator: Authenticator {
    /// The credential provider.
    public nonisolated let credentials: any CredentialProvider
    private let options: TokenExchangeOptions
    private let transport: any HTTPTransport

    private struct Entry: Sendable {
        let realm: URL
        let token: AccessToken
    }

    private var tokens: [String: Entry] = [:]
    private var metadata: [String: AuthorizationServerMetadata] = [:]
    private var inflight: [String: Task<Entry, any Error>] = [:]

    /// Creates the authenticator.
    public init(credentials: any CredentialProvider, options: TokenExchangeOptions = TokenExchangeOptions()) {
        self.credentials = credentials
        self.options = options
        transport = options.transport ?? URLSessionTransport()
    }

    public func authorize(_ request: AuthRequest) async throws -> AuthRequest {
        let now = options.now()
        var best: Entry?
        for e in tokens.values where e.token.isValid(at: now, margin: options.refreshMargin) && URLs.contains(realm: e.realm, request.url) {
            if best == nil || URLs.path(e.realm).count > URLs.path(best!.realm).count { best = e }
        }
        guard let best else { return request }
        var r = request
        r.headers.set("Authorization", "Bearer " + best.token.value)
        return r
    }

    /// - Throws: ``LWSError/authentication(_:)`` when the request URL is outside the challenge realm, the
    ///   authorization server is insecure or rejected, or the token exchange failed. A cached token stays in use
    ///   when the challenge is refused.
    public func handleChallenge(_ request: AuthRequest, response: AuthResponse) async throws -> Bool {
        guard let challenge = response.challenges.first(where: { $0.isScheme("Bearer") && $0.asURI != nil && $0.realm != nil }) else {
            return false
        }
        let asText = challenge.asURI!
        let realmText = challenge.realm!
        guard let asURI = URLs.resolve(asText, against: nil) else {
            throw LWSError.authFailure("The challenge as_uri is not an absolute URL: \(asText)")
        }
        guard let realm = URLs.resolve(realmText, against: nil) else {
            throw LWSError.authFailure("The challenge realm is not an absolute URL: \(realmText)")
        }
        // Every check comes before the cached token the request carried is touched: a decoy challenge must not
        // evict a working token.
        guard URLs.contains(realm: realm, request.url) else {
            throw LWSError.authFailure("Request URL \(request.url.absoluteString) is not within the challenge realm \(realmText)")
        }
        try requireSecure(asURI, "authorization server")
        if let filter = options.authorizationServerFilter, !filter(asURI, realm) {
            throw LWSError.authFailure("Authorization server \(asText) was rejected by the authorization server filter")
        }
        if let sent = request.headers.first("Authorization") {
            for (k, e) in tokens where "Bearer " + e.token.value == sent { tokens[k] = nil }
        }
        let key = Self.key(asText, realmText)
        if let cached = tokens[key], cached.token.isValid(at: options.now(), margin: options.refreshMargin) {
            return true  // obtained concurrently: retry with it
        }
        _ = try await obtain(asText, asURI, realmText, realm)
        return true
    }

    /// Returns a valid access token for a realm, performing the token exchange when needed.
    /// - Throws: ``LWSError/authentication(_:)`` when the exchange fails.
    public func accessToken(asURI: String, realm: String) async throws -> AccessToken {
        if let e = tokens[Self.key(asURI, realm)], e.token.isValid(at: options.now(), margin: options.refreshMargin) { return e.token }
        guard let issuer = URLs.resolve(asURI, against: nil) else { throw LWSError.invalidArgument("Not an absolute URL: \(asURI)") }
        guard let realmURL = URLs.resolve(realm, against: nil) else { throw LWSError.invalidArgument("Not an absolute URL: \(realm)") }
        try requireSecure(issuer, "authorization server")
        return try await obtain(asURI, issuer, realm, realmURL).token
    }

    /// Forgets every cached token and metadata document.
    public func clear() {
        tokens.removeAll()
        metadata.removeAll()
    }

    private func obtain(_ asText: String, _ asURI: URL, _ realmText: String, _ realm: URL) async throws -> Entry {
        let key = Self.key(asText, realmText)
        if let running = inflight[key] { return try await running.value }
        let task = Task<Entry, any Error> {
            defer { self.inflight[key] = nil }
            let entry = Entry(realm: realm, token: try await self.exchange(asText, asURI, realmText, realm))
            self.tokens[key] = entry
            return entry
        }
        inflight[key] = task
        return try await task.value
    }

    private func exchange(_ asText: String, _ asURI: URL, _ realmText: String, _ realm: URL) async throws -> AccessToken {
        let md = try await serverMetadata(asText, asURI)
        try requireSecure(md.tokenEndpoint, "token endpoint")
        guard md.supportsSubjectTokenType(credentials.tokenType) else {
            throw LWSError.authFailure("Authorization server \(asText) does not accept subject tokens of type \(credentials.tokenType) "
                + "(supported: \(md.subjectTokenTypesSupported.joined(separator: ", ")))")
        }
        let credentials = self.credentials
        let context = CredentialContext(issuer: asURI, realm: realm, metadata: md)
        let subjectToken = try await withTimeLimit(options.timeout, "The credential provider") {
            try await credentials.subjectToken(for: context)
        }
        let form = [
            ("grant_type", Vocabulary.grantTypeTokenExchange),
            ("resource", realmText),
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

    private func serverMetadata(_ asText: String, _ asURI: URL) async throws -> AuthorizationServerMetadata {
        if let cached = metadata[asText] { return cached }
        let url = AuthorizationServerMetadata.metadataURL(issuer: asURI)
        let r = try await get(url, "authorization server metadata")
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
        let sameIssuer = URLs.equalsIgnoringTrailingSlash(md.issuer, asText)
            || URLs.resolve(md.issuer, against: nil).map { URLs.equalsIgnoringTrailingSlash(URLs.canonical($0), URLs.canonical(asURI)) } == true
        guard sameIssuer else {
            throw LWSError.authFailure("Authorization server metadata issuer \(md.issuer) does not match as_uri \(asText)", status: r.status)
        }
        metadata[asText] = md
        return md
    }

    private func get(_ url: URL, _ what: String) async throws -> HTTPResponse {
        try await sendRefusingRedirects(HTTPRequest(method: "GET", url: url, headers: ["Accept": MediaType.json]), what)
    }

    private func post(_ url: URL, _ body: Data, _ what: String) async throws -> HTTPResponse {
        try await sendRefusingRedirects(
            HTTPRequest(method: "POST", url: url, headers: ["Content-Type": MediaType.form, "Accept": MediaType.json], body: body), what)
    }

    /// Sends a metadata or token request; a redirect is refused, since it would carry credentials to another URL.
    private func sendRefusingRedirects(_ request: HTTPRequest, _ what: String) async throws -> HTTPResponse {
        var r = request
        if let ua = options.userAgent { r.headers.set("User-Agent", ua) }
        r.timeout = options.timeout
        let response = try await sendThrough(transport, r)
        if (300..<400).contains(response.status) || response.url.absoluteString != request.url.absoluteString {
            let location = response.headers.first("location").map { " to \($0)" } ?? ""
            throw LWSError.authFailure("Refusing the redirect\(location) of the \(what) request \(request.url.absoluteString) "
                + "(HTTP \(response.status)): it would carry credentials to another URL", status: response.status)
        }
        return response
    }

    private func requireSecure(_ url: URL, _ what: String) throws {
        switch url.scheme?.lowercased() {
        case "https": return
        case "http" where options.allowInsecureHttp || URLs.isLoopback(url): return
        default: throw LWSError.authFailure("Refusing to use the insecure \(what) \(url.absoluteString) (HTTPS required)")
        }
    }

    private static func key(_ asURI: String, _ realm: String) -> String { asURI + " " + realm }

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
