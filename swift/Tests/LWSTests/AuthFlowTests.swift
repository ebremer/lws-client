// SPDX-License-Identifier: MIT
import Foundation
import Testing
@testable import LWS

/// The LWS authorization flow (`401 → metadata → token exchange → retry`) and its security checks, against a fake
/// storage protected by a fake authorization server.
@Suite struct AuthFlowTests {
    private static let base = "https://storage.example"
    private static let realm = base + "/"
    private static let asURI = "https://as.example"
    private static let metadata = asURI + "/.well-known/lws-configuration"
    private static let tokenEndpoint = asURI + "/token"

    /// The authorization server's state, shared with the routes.
    final class State: @unchecked Sendable {
        private let lock = NSLock()
        private var tokens = Set<String>()
        private var count = 0
        var expiresIn = 300

        var exchanges: Int { lock.withLock { count } }

        func mint() -> String {
            lock.withLock {
                count += 1
                tokens.insert("at-\(count)")
                return "at-\(count)"
            }
        }

        func allow(_ token: String) { _ = lock.withLock { tokens.insert(token) } }
        func revokeAll() { lock.withLock { tokens.removeAll() } }
        func isValid(_ token: String) -> Bool { lock.withLock { tokens.contains(token) } }
    }

    private let server = FakeServer()
    private let state = State()
    private let clock = FakeClock(Date(timeIntervalSince1970: 1_790_000_000))

    init() {
        let state = state
        server.on("GET", Self.metadata) { _ in Respond.json(200, Self.metadataJSON(Self.asURI)) }
        server.on("POST", Self.tokenEndpoint) { _ in
            let token = state.mint()
            return Respond.json(200, #"{"access_token":"\#(token)","token_type":"Bearer","expires_in":\#(state.expiresIn)}"#)
        }
        protect("GET", Self.base + "/root/a") { Respond.text(200, "a") }
        protect("GET", Self.base + "/root/b") { Respond.text(200, "b") }
        protect("POST", Self.base + "/root/") { Respond.status(201, ("Location", "/root/new")) }
        protect("HEAD", Self.base + "/root/") { Respond.status(200) }
    }

    private static func metadataJSON(_ issuer: String, _ tokenEndpoint: String = tokenEndpoint) -> String {
        #"{"issuer":"\#(issuer)","token_endpoint":"\#(tokenEndpoint)","grant_types_supported":["\#(Vocabulary.grantTypeTokenExchange)"],"#
            + #""subject_token_types_supported":["\#(TokenType.jwt)","\#(TokenType.idToken)"]}"#
    }

    private static func challenge(asURI: String = asURI, realm: String = realm, error: String = "invalid_token") -> HTTPResponse {
        Respond.status(401, ("WWW-Authenticate", #"Bearer as_uri="\#(asURI)", realm="\#(realm)", error="\#(error)""#))
    }

    private static func authorized(_ r: Recorded, _ state: State) -> Bool {
        guard let a = r.header("Authorization"), a.hasPrefix("Bearer ") else { return false }
        return state.isValid(String(a.dropFirst(7)))
    }

    private func protect(_ method: String, _ url: String, _ ok: @escaping @Sendable () -> HTTPResponse) {
        let state = state
        server.on(method, url) { r in Self.authorized(r, state) ? ok() : Self.challenge() }
    }

    private func authenticator(_ credentials: (any CredentialProvider)? = nil, _ options: TokenExchangeOptions = TokenExchangeOptions())
        -> TokenExchangeAuthenticator
    {
        var o = options
        o.transport = server
        o.now = clock.function
        return TokenExchangeAuthenticator(credentials: credentials ?? OpenIDCredentials(idToken: "id-token"), options: o)
    }

    private func client(_ authenticator: any Authenticator) -> LWSClient {
        LWSClient(options: LWSClientOptions(transport: server, authenticator: authenticator))
    }

    private var trace: [String] { server.requests.map { "\($0.method) \($0.url.absoluteString)" } }

    private func form(_ r: Recorded) -> [String: String] {
        Dictionary(uniqueKeysWithValues: r.text.split(separator: "&").map { p in
            let kv = p.split(separator: "=", maxSplits: 1).map { String($0).replacingOccurrences(of: "+", with: " ").removingPercentEncoding! }
            return (kv[0], kv[1])
        })
    }

    // MARK: - The flow

    @Test func fullFlowWithSelfSignedCredentials() async throws {
        let key = SigningKey.generateP256()
        let credentials = try SelfSignedCredentials.didKey(key).withClock(clock.function)
        let client = client(authenticator(credentials))

        let r = try await client.read(url(Self.base + "/root/a"))
        #expect(r.text == "a")
        #expect(trace == ["GET \(Self.base)/root/a", "GET \(Self.metadata)", "POST \(Self.tokenEndpoint)", "GET \(Self.base)/root/a"])
        let exchange = try #require(server.requests("POST", Self.tokenEndpoint).first)
        #expect(exchange.header("Content-Type") == "application/x-www-form-urlencoded")
        let f = form(exchange)
        #expect(f["grant_type"] == Vocabulary.grantTypeTokenExchange)
        #expect(f["resource"] == Self.realm)
        #expect(f["subject_token_type"] == TokenType.jwt)
        let jwt = try #require(f["subject_token"])
        #expect(JWT.verify(jwt, key: key.publicKey))
        let header = try JWT.decodeHeader(jwt)
        #expect(header.string("alg") == "ES256")
        #expect(header.string("typ") == "JWT")
        #expect(header.string("kid") == credentials.keyID)
        let claims = try JWT.decodeClaims(jwt)
        #expect(claims.string("sub") == credentials.agent)
        #expect(claims.string("iss") == credentials.agent)
        #expect(claims.string("client_id") == credentials.agent)
        #expect(credentials.agent.hasPrefix("did:key:zDn"))
        #expect(claims["aud"] == [.string(Self.asURI)])
        #expect(claims.integer("iat") == 1_790_000_000)
        #expect(claims.integer("exp") == 1_790_000_300)
        #expect(UUID(uuidString: claims.string("jti") ?? "") != nil)
        #expect(server.requests.last?.header("Authorization") == "Bearer at-1")
        #expect(server.requests("GET", Self.metadata).first?.header("User-Agent") == LWSClient.defaultUserAgent)
    }

    @Test func proactiveReuseInsideTheRealmOnly() async throws {
        let auth = authenticator()
        let client = client(auth)
        server.on("GET", "https://elsewhere.example/x") { _ in Respond.text(200, "x") }
        _ = try await client.read(url(Self.base + "/root/a"))
        let before = server.requests.count
        _ = try await client.read(url(Self.base + "/root/b"))
        #expect(server.requests[before].header("Authorization") == "Bearer at-1")
        #expect(server.requests.count == before + 1)
        _ = try await client.read(url("https://elsewhere.example/x"))
        #expect(server.requests.last?.header("Authorization") == nil)
        _ = try? await client.read(url("http://storage.example/root/a"))
        #expect(server.requests.last?.header("Authorization") == nil)
        #expect(state.exchanges == 1)
        #expect(try await auth.accessToken(asURI: Self.asURI, realm: Self.realm).value == "at-1")
    }

    @Test func openIDAndSAMLSubjectTokens() async throws {
        let oidc = client(authenticator(OpenIDCredentials { ctx in
            #expect(ctx.metadata.issuer == Self.asURI)
            #expect(ctx.realm.absoluteString == Self.realm)
            return "my-id-token"
        }))
        _ = try await oidc.read(url(Self.base + "/root/a"))
        let first = try #require(server.requests("POST", Self.tokenEndpoint).first)
        #expect(first.text.contains("subject_token=my-id-token"))
        #expect(first.text.contains("subject_token_type=" + TokenExchangeAuthenticator.formEncode(TokenType.idToken)))

        server.on("GET", Self.metadata) { _ in Respond.json(200, #"{"issuer":"\#(Self.asURI)","token_endpoint":"\#(Self.tokenEndpoint)"}"#) }
        let saml = client(authenticator(SAMLCredentials.fromXML("<saml:Assertion/>")))
        _ = try await saml.read(url(Self.base + "/root/a"))
        let second = try #require(server.requests("POST", Self.tokenEndpoint).last)
        #expect(second.text.contains("subject_token=" + SAMLCredentials.encode("<saml:Assertion/>")))
        #expect(second.text.contains("subject_token_type=" + TokenExchangeAuthenticator.formEncode(TokenType.saml2)))
        #expect(SAMLCredentials.encode("<saml:Assertion/>") == "PHNhbWw6QXNzZXJ0aW9uLz4")
    }

    @Test func aRejectedTokenIsDroppedAndExchangedOnce() async throws {
        let client = client(authenticator())
        _ = try await client.read(url(Self.base + "/root/a"))
        state.revokeAll()  // the server revokes at-1
        _ = try await client.read(url(Self.base + "/root/b"))
        #expect(state.exchanges == 2)
        #expect(server.requests("GET", Self.base + "/root/b").map { $0.header("Authorization") } == ["Bearer at-1", "Bearer at-2"])
    }

    @Test func expiringTokensAreRefreshedBeforeTheyExpire() async throws {
        state.expiresIn = 60
        let client = client(authenticator())
        _ = try await client.read(url(Self.base + "/root/a"))
        clock.advance(29)
        _ = try await client.read(url(Self.base + "/root/a"))
        #expect(state.exchanges == 1)
        clock.advance(2)  // inside the 30 s refresh margin
        let before = server.requests.count
        _ = try await client.read(url(Self.base + "/root/a"))
        #expect(server.requests[before].header("Authorization") == nil)
        #expect(state.exchanges == 2)
    }

    @Test func concurrentRequestsShareOneExchange() async throws {
        let gate = Gate()
        server.beforeRespond = { r in if r.url.absoluteString == Self.tokenEndpoint { await gate.wait() } }
        let client = client(authenticator())
        let results = try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<8 { group.addTask { try await client.read(url(Self.base + "/root/a")).text } }
            try await Task.sleep(nanoseconds: 200_000_000)
            await gate.open()
            var out: [String] = []
            for try await t in group { out.append(t) }
            return out
        }
        #expect(results == Array(repeating: "a", count: 8))
        #expect(state.exchanges == 1)
    }

    @Test func postIsRetriedOnceAfterA401Only() async throws {
        let client = client(authenticator())
        let created = try await client.createText(in: url(Self.base + "/root/"), text: "hello")
        #expect(created.location.absoluteString == Self.base + "/root/new")
        let posts = server.requests("POST", Self.base + "/root/")
        #expect(posts.map { $0.header("Authorization") } == [nil, "Bearer at-1"])
        #expect(posts.allSatisfy { $0.text == "hello" })

        // A server that keeps refusing: exactly one retry, then unauthorized.
        server.on("POST", Self.base + "/root/stubborn/") { _ in Self.challenge() }
        #expect(kind(await error { try await client.createText(in: url(Self.base + "/root/stubborn/"), text: "x") }) == "unauthorized")
        #expect(server.requests("POST", Self.base + "/root/stubborn/").count == 2)
    }

    @Test func aChallengeWithoutAnAuthorizationServerIsUnauthorized() async throws {
        server.on("GET", Self.base + "/basic") { _ in Respond.status(401, ("WWW-Authenticate", "Basic realm=\"x\"")) }
        let client = client(authenticator())
        let e = await error { try await client.read(url(Self.base + "/basic")) }
        #expect(kind(e) == "unauthorized")
        #expect((e as? LWSError)?.httpError?.challenges.first?.isScheme("basic") == true)
        #expect(state.exchanges == 0)
    }

    // MARK: - The checks

    @Test func theRealmMustContainTheRequestURL() async throws {
        server.on("GET", Self.base + "/root/other") { _ in Self.challenge(realm: Self.base + "/other/") }
        server.on("GET", Self.base + "/storage_10/x") { _ in Self.challenge(realm: Self.base + "/storage_1") }
        let client = client(authenticator())
        #expect(kind(await error { try await client.read(url(Self.base + "/root/other")) }) == "authentication")
        #expect(kind(await error { try await client.read(url(Self.base + "/storage_10/x")) }) == "authentication")
        #expect(server.requests("GET", Self.metadata).isEmpty)
        #expect(state.exchanges == 0)
    }

    @Test func aDecoyChallengeLeavesTheCachedTokenInUse() async throws {
        let client = client(authenticator())
        _ = try await client.read(url(Self.base + "/root/a"))
        #expect(state.exchanges == 1)

        // The storage answers a request that carried the cached token with challenges that must all be refused: a
        // realm that does not contain the URL, an insecure authorization server, one the filter rejects.
        let decoys = [
            #"Bearer as_uri="\#(Self.asURI)", realm="https://evil.example/""#,
            #"Bearer as_uri="http://as.evil.example", realm="\#(Self.realm)""#,
        ]
        for decoy in decoys {
            server.on("GET", Self.base + "/root/decoy") { _ in Respond.status(401, ("WWW-Authenticate", decoy)) }
            #expect(kind(await error { try await client.read(url(Self.base + "/root/decoy")) }) == "authentication")
            #expect(server.requests("GET", Self.base + "/root/decoy").last?.header("Authorization") == "Bearer at-1")
            let before = server.requests.count
            _ = try await client.read(url(Self.base + "/root/b"))
            #expect(server.requests[before].header("Authorization") == "Bearer at-1")
            #expect(server.requests.count == before + 1)
        }

        let filtered = self.client(authenticator(nil, TokenExchangeOptions(authorizationServerFilter: { asURI, _ in asURI.host == "as.example" })))
        _ = try await filtered.read(url(Self.base + "/root/a"))
        server.on("GET", Self.base + "/root/decoy") { _ in Self.challenge(asURI: "https://as.attacker.example") }
        #expect(kind(await error { try await filtered.read(url(Self.base + "/root/decoy")) }) == "authentication")
        _ = try await filtered.read(url(Self.base + "/root/b"))
        #expect(server.requests.last?.header("Authorization") == "Bearer at-2")
        #expect(!server.requests.contains { ($0.url.host ?? "").contains("attacker") || ($0.url.host ?? "").contains("evil") })
        #expect(state.exchanges == 2)
    }

    @Test func insecureAuthorizationServersAreRefusedUnlessAllowed() async throws {
        let insecure = "http://as.example"
        let state = state
        server.on("GET", Self.base + "/root/c") { r in Self.authorized(r, state) ? Respond.text(200, "c") : Self.challenge(asURI: insecure) }
        server.on("GET", insecure + "/.well-known/lws-configuration") { _ in Respond.json(200, Self.metadataJSON(insecure, insecure + "/token")) }
        server.on("POST", insecure + "/token") { _ in Respond.json(200, #"{"access_token":"at-1","token_type":"bearer"}"#) }
        state.allow("at-1")
        let strict = await error { try await self.client(authenticator()).read(url(Self.base + "/root/c")) }
        guard case .authentication(let a)? = strict as? LWSError else {
            Issue.record("expected an authentication error, got \(String(describing: strict))")
            return
        }
        #expect(a.message.contains("HTTPS"))
        #expect(a.status == nil)
        let lax = self.client(authenticator(nil, TokenExchangeOptions(allowInsecureHttp: true)))
        #expect(try await lax.read(url(Self.base + "/root/c")).text == "c")
        // An https AS whose token endpoint is plain http is refused too.
        server.on("GET", Self.metadata) { _ in Respond.json(200, Self.metadataJSON(Self.asURI, "http://as.example/token")) }
        #expect(kind(await error { try await self.client(authenticator()).read(url(Self.base + "/root/a")) }) == "authentication")
    }

    @Test func loopbackAuthorizationServersMayUseHTTP() async throws {
        let local = "http://localhost:8787"
        let state = state
        server.on("GET", local + "/root/x") { r in Self.authorized(r, state) ? Respond.text(200, "x") : Self.challenge(asURI: local, realm: local + "/") }
        server.on("GET", local + "/.well-known/lws-configuration") { _ in Respond.json(200, Self.metadataJSON(local, local + "/oauth/token")) }
        server.on("POST", local + "/oauth/token") { _ in Respond.json(200, #"{"access_token":"at-local","token_type":"Bearer"}"#) }
        state.allow("at-local")
        let client = client(authenticator())
        #expect(try await client.read(url(local + "/root/x")).text == "x")
        #expect(server.requests("POST", local + "/oauth/token").first?.text.contains("resource=" + TokenExchangeAuthenticator.formEncode(local + "/")) == true)
    }

    @Test func metadataAndTokenRequestsNeverFollowRedirects() async throws {
        let client = client(authenticator())

        server.on("GET", Self.metadata) { _ in Respond.status(307, ("Location", "https://attacker.example/.well-known/lws-configuration")) }
        let md = await error { try await client.read(url(Self.base + "/root/a")) }
        #expect(kind(md) == "authentication")
        #expect((md as? LWSError)?.status == 307)
        #expect(server.requests("POST", Self.tokenEndpoint).isEmpty)

        server.on("GET", Self.metadata) { _ in Respond.json(200, Self.metadataJSON(Self.asURI)) }
        server.on("POST", Self.tokenEndpoint) { _ in Respond.status(308, ("Location", "https://attacker.example/token")) }
        let token = await error { try await client.read(url(Self.base + "/root/a")) }
        #expect(kind(token) == "authentication")
        #expect((token as? LWSError)?.status == 308)
        #expect(String(describing: token!).lowercased().contains("redirect"))
        #expect(server.requests("POST", Self.tokenEndpoint).count == 1)
        #expect(!server.requests.contains { $0.url.host == "attacker.example" })
    }

    /// A transport that follows redirects by itself: the response comes from another URL.
    private struct FollowingTransport: HTTPTransport {
        let inner: FakeServer

        func send(_ request: HTTPRequest) async throws -> HTTPResponse {
            var r = try await inner.send(request)
            r.url = url("https://attacker.example/landed")
            return r
        }
    }

    @Test func aTransportThatFollowsRedirectsIsRefused() async throws {
        var o = TokenExchangeOptions()
        o.transport = FollowingTransport(inner: server)
        let client = client(TokenExchangeAuthenticator(credentials: OpenIDCredentials(idToken: "x"), options: o))
        let e = await error { try await client.read(url(Self.base + "/root/a")) }
        #expect(kind(e) == "authentication")
        #expect(server.requests("POST", Self.tokenEndpoint).isEmpty)
    }

    @Test func authorizationServerFailures() async throws {
        let client = client(authenticator())

        server.on("POST", Self.tokenEndpoint) { _ in Respond.json(400, #"{"error":"invalid_target","error_description":"resource is not a known storage"}"#) }
        let e = await error { try await client.read(url(Self.base + "/root/a")) }
        guard case .authentication(let a)? = e as? LWSError else {
            Issue.record("expected an authentication error, got \(String(describing: e))")
            return
        }
        #expect(a.error == "invalid_target")
        #expect(a.errorDescription == "resource is not a known storage")
        #expect(a.status == 400)

        server.on("POST", Self.tokenEndpoint) { _ in Respond.json(200, #"{"access_token":"x","token_type":"DPoP"}"#) }
        #expect(kind(await error { try await client.read(url(Self.base + "/root/a")) }) == "authentication")
        server.on("POST", Self.tokenEndpoint) { _ in Respond.text(200, "not json") }
        #expect(kind(await error { try await client.read(url(Self.base + "/root/a")) }) == "authentication")

        let other = self.client(authenticator())
        server.on("GET", Self.metadata) { _ in Respond.json(200, Self.metadataJSON("https://not-the-as.example")) }
        #expect(kind(await error { try await other.read(url(Self.base + "/root/a")) }) == "authentication")
        server.on("GET", Self.metadata) { _ in Respond.status(404) }
        #expect((await error { try await other.read(url(Self.base + "/root/a")) } as? LWSError)?.status == 404)
        server.on("GET", Self.metadata) { _ in Respond.json(200, #"{"issuer":"https://as.example"}"#) }
        #expect(kind(await error { try await other.read(url(Self.base + "/root/a")) }) == "authentication")
        server.on("GET", Self.metadata) { _ in
            Respond.json(200, #"{"issuer":"\#(Self.asURI)/","token_endpoint":"\#(Self.tokenEndpoint)","subject_token_types_supported":["\#(TokenType.saml2)"]}"#)
        }
        let unsupported = await error { try await other.read(url(Self.base + "/root/a")) }
        #expect(kind(unsupported) == "authentication")
        #expect(String(describing: unsupported!).contains("does not accept"))
    }

    @Test func tokensNeverLeaveTheirRealmOnRedirects() async throws {
        let state = state
        server.on("GET", Self.base + "/root/moved") { r in Self.authorized(r, state) ? Respond.status(302, ("Location", "https://cdn.example/blob")) : Self.challenge() }
        server.on("GET", "https://cdn.example/blob") { _ in Respond.text(200, "blob") }
        server.on("GET", Self.base + "/root/renamed") { r in Self.authorized(r, state) ? Respond.status(308, ("Location", "/root/a")) : Self.challenge() }
        let client = client(authenticator())
        #expect(try await client.read(url(Self.base + "/root/moved")).text == "blob")
        #expect(server.requests("GET", "https://cdn.example/blob").first?.header("Authorization") == nil)
        #expect(try await client.read(url(Self.base + "/root/renamed")).text == "a")
        #expect(server.requests.last?.header("Authorization") == "Bearer at-1")
        #expect(state.exchanges == 1)
    }

    @Test func anExplicitAuthorizationHeaderSurvivesSameOriginRedirectsOnly() async throws {
        let client = LWSClient(options: LWSClientOptions(transport: server))
        server.on("GET", Self.base + "/x") { _ in Respond.status(301, ("Location", "/y")) }
        server.on("GET", Self.base + "/y") { _ in Respond.status(302, ("Location", "https://other.example/z")) }
        server.on("GET", "https://other.example/z") { _ in Respond.text(200, "z") }
        _ = try await client.read(url(Self.base + "/x"), options: ReadOptions(headers: ["Authorization": "Bearer mine"]))
        #expect(server.requests.map { $0.header("Authorization") } == ["Bearer mine", "Bearer mine", nil])
    }

    @Test func bearerTokenAuthenticatorRestrictsToItsRealm() async throws {
        let asked = Counter()
        let bearer = BearerTokenAuthenticator(realm: url(Self.base + "/root/")) { "at-\(asked.next() + 1)" }
        let client = client(bearer)
        state.allow("at-1")
        state.allow("at-2")
        server.on("GET", Self.base + "/public") { _ in Respond.text(200, "p") }
        _ = try await client.read(url(Self.base + "/root/a"))
        _ = try await client.read(url(Self.base + "/public"))
        #expect(server.requests.map { $0.header("Authorization") } == ["Bearer at-1", nil])
        #expect(asked.next() == 1)
        // A refused bearer token is not retried.
        state.revokeAll()
        #expect(kind(await error { try await client.read(url(Self.base + "/root/a")) }) == "unauthorized")
        #expect(state.exchanges == 0)
        #expect(bearer.realm?.absoluteString == Self.base + "/root/")
    }

    @Test func selfSignedCredentialsCacheTokensPerAudience() async throws {
        let ed = try SelfSignedCredentials.didKey(.generateEd25519()).withClock(clock.function)
        #expect(ed.agent.hasPrefix("did:key:z6Mk"))
        #expect(ed.algorithm == "EdDSA")
        #expect(try DIDKey.keyID(forDID: ed.agent) == ed.keyID)
        let md = try AuthorizationServerMetadata.parse(JSONValue(parsing: Self.metadataJSON(Self.asURI)), base: url(Self.metadata))
        let other = try AuthorizationServerMetadata.parse(JSONValue(parsing: Self.metadataJSON("https://as2.example", "https://as2.example/t")),
                                                          base: url(Self.metadata))
        let context = CredentialContext(issuer: url(Self.asURI), realm: url(Self.realm), metadata: md)
        let t1 = try await ed.subjectToken(for: context)
        #expect(try await ed.subjectToken(for: context) == t1)
        let t2 = try await ed.subjectToken(for: CredentialContext(issuer: url(Self.asURI), realm: url(Self.realm), metadata: other))
        #expect(t1 != t2)
        #expect(try JWT.decodeClaims(t2)["aud"]?[0] == "https://as2.example")
        #expect(JWT.verify(t1, key: ed.publicKey))
        #expect(try JWT.decodeHeader(t1).string("alg") == "EdDSA")
        clock.advance(241)  // within 60 s of the 300 s expiry: a new token
        #expect(try await ed.subjectToken(for: context) != t1)

        let key = SigningKey.generateP256()
        let agent = SelfSignedCredentials.forAgent(url("https://bot.example/id"), key: key, keyID: "https://bot.example/id#key-1").withLifetime(60)
        let token = try agent.createToken(audience: Self.asURI)
        #expect(try JWT.decodeClaims(token).string("sub") == "https://bot.example/id")
        #expect(try JWT.decodeHeader(token).string("kid") == "https://bot.example/id#key-1")
        let claims = try JWT.decodeClaims(token)
        #expect(claims.integer("exp")! - claims.integer("iat")! == 60)
        #expect(!JWT.verify(token, key: SigningKey.generateP256().publicKey))
        #expect(!JWT.verify(token, key: ed.publicKey))  // the header alg must be the key's
    }

    @Test func keyHelpers() throws {
        let p256 = try SigningKey.generate(algorithm: "ES256")
        let ed = try SigningKey.generate(algorithm: "EdDSA")
        for key in [p256, ed] {
            let back = try SigningKey(jwk: key.jwk)
            #expect(back.publicKey.jwk == key.publicKey.jwk)
            #expect(key.publicKey.verify(try back.sign(Data("x".utf8)), for: Data("x".utf8)))
            #expect(try DIDKey.publicKey(DIDKey.did(for: key.publicKey)).jwk == key.publicKey.jwk)
        }
        #expect(kind(syncError { try SigningKey(jwk: ["kty": "RSA", "crv": "x", "d": "AA"]) }) == "invalidArgument")
        #expect(kind(syncError { try VerificationKey(jwk: ["kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"]) }) == "invalidArgument")
        #expect(kind(syncError { try DIDKey.publicKey("did:web:example.org") }) == "invalidArgument")
        let p384 = try SigningKey.generate(algorithm: "ES384")
        #expect(p384.algorithm == "ES384")
        #expect(try p384.sign(Data("x".utf8)).count == 96)
        #expect(kind(syncError { try DIDKey.did(for: p384.publicKey) }) == "invalidArgument")

        let cid = ControlledIdentifierDocument.create(agent: "https://bot.example/id", key: ed.publicKey, kid: "key-1")
        #expect(cid.string("id") == "https://bot.example/id")
        let method = try #require(cid["authentication"]?[0])
        #expect(method["id"] == "https://bot.example/id#key-1")
        #expect(method["type"] == "JsonWebKey")
        #expect(method["publicKeyJwk"]?["alg"] == "EdDSA")
        #expect(method["publicKeyJwk"]?["kid"] == "key-1")
        #expect(ControlledIdentifierDocument.create(agent: "https://bot.example/id", publicJWK: p256.jwk, kid: "did:x#k")["authentication"]?[0]?["publicKeyJwk"]?["d"]
            == nil)
        #expect(cid["@context"]?[0] == .string(Vocabulary.cidContext))
    }
}

/// A one-shot gate that tasks wait on until it opens.
actor Gate {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if isOpen { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func open() {
        isOpen = true
        for w in waiters { w.resume() }
        waiters.removeAll()
    }
}
