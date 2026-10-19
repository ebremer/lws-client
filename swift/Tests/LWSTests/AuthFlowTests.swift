// SPDX-License-Identifier: MIT
import Foundation
import Testing
@testable import LWS

/// The LWS authorization flow (`401 → protected resource metadata → storage description → AS metadata → token
/// exchange → retry`) and its security checks, against a fake storage protected by a fake authorization server.
@Suite struct AuthFlowTests {
    private static let base = "https://storage.example"
    private static let storage = base + "/"
    private static let root = base + "/root/"
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

    /// What a callback was called with.
    final class Calls: @unchecked Sendable {
        private let lock = NSLock()
        private var recorded: [String] = []

        var all: [String] { lock.withLock { recorded } }
        func record(_ call: String) { lock.withLock { recorded.append(call) } }
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
        server.on("GET", Self.storage) { _ in Respond.json(200, Self.descriptionJSON(Self.storage, Self.root), contentType: MediaType.lwsCID) }
        protect("GET", Self.root + "a") { Respond.text(200, "a") }
        protect("GET", Self.root + "b") { Respond.text(200, "b") }
        protect("POST", Self.root) { Respond.status(201, ("Location", "/root/new")) }
        protect("HEAD", Self.root) { Respond.status(200) }
    }

    private static func metadataJSON(_ issuer: String, _ tokenEndpoint: String = tokenEndpoint) -> String {
        #"{"issuer":"\#(issuer)","token_endpoint":"\#(tokenEndpoint)","grant_types_supported":["\#(Vocabulary.grantTypeTokenExchange)"],"#
            + #""subject_token_types_supported":["\#(TokenType.jwt)","\#(TokenType.idToken)"]}"#
    }

    private static func descriptionJSON(_ id: String, _ root: String) -> String {
        #"{"@context":["\#(Vocabulary.cidContext)","\#(Vocabulary.context)"],"id":"\#(id)","type":"Storage","#
            + #""service":[{"type":"StorageRoot","serviceEndpoint":"\#(root)"}]}"#
    }

    /// The protected resource metadata URL of a resource: `/.well-known/oauth-protected-resource` + its path.
    private static func resourceMetadata(_ resource: String) -> String {
        var c = URLComponents(string: resource)!
        c.percentEncodedPath = Vocabulary.wellKnownOAuthProtectedResource + c.percentEncodedPath
        return c.string!
    }

    private static func resourceMetadataJSON(_ resource: String, _ servers: [String] = [asURI]) -> String {
        JSONValue.object(["resource": .string(resource), "authorization_servers": .array(servers.map { .string($0) })]).serialized()
    }

    private static func challenge(_ resource: String, storage: String = storage, error: String = "invalid_token") -> HTTPResponse {
        Respond.status(401, ("WWW-Authenticate", #"Bearer resource_metadata="\#(resourceMetadata(resource))", error="\#(error)""#),
                       ("Link", #"<\#(storage)>; rel="\#(LinkRelation.storage)""#))
    }

    /// The challenge of the drafts before 19 October 2026.
    private static func legacyChallenge(asURI: String = asURI, realm: String = storage) -> HTTPResponse {
        Respond.status(401, ("WWW-Authenticate", #"Bearer as_uri="\#(asURI)", realm="\#(realm)", error="invalid_token""#))
    }

    private static func authorized(_ r: Recorded, _ state: State) -> Bool {
        guard let a = r.header("Authorization"), a.hasPrefix("Bearer ") else { return false }
        return state.isValid(String(a.dropFirst(7)))
    }

    /// Serves a resource that needs a token, and its protected resource metadata.
    private func protect(_ method: String, _ url: String, _ ok: @escaping @Sendable () -> HTTPResponse) {
        let state = state
        server.on(method, url) { r in Self.authorized(r, state) ? ok() : Self.challenge(url) }
        publishMetadata(url)
    }

    private func publishMetadata(_ resource: String, _ servers: [String] = [asURI]) {
        server.on("GET", Self.resourceMetadata(resource)) { _ in Respond.json(200, Self.resourceMetadataJSON(resource, servers)) }
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

        let r = try await client.read(url(Self.root + "a"))
        #expect(r.text == "a")
        let prm = Self.resourceMetadata(Self.root + "a")
        #expect(trace == ["GET \(Self.root)a", "GET \(prm)", "GET \(Self.storage)", "GET \(Self.metadata)", "POST \(Self.tokenEndpoint)", "GET \(Self.root)a"])
        #expect(prm == Self.base + "/.well-known/oauth-protected-resource/root/a")
        let discovery = server.requests.dropFirst().prefix(3)
        #expect(discovery.allSatisfy { $0.header("Authorization") == nil })
        #expect(discovery.allSatisfy { $0.header("User-Agent") == LWSClient.defaultUserAgent })
        #expect(server.requests("GET", prm).first?.header("Accept") == "application/json")
        #expect(server.requests("GET", Self.storage).first?.header("Accept") == "application/lws+cid, application/ld+json;q=0.9, application/json;q=0.8")
        let exchange = try #require(server.requests("POST", Self.tokenEndpoint).first)
        #expect(exchange.header("Content-Type") == "application/x-www-form-urlencoded")
        let f = form(exchange)
        #expect(f["grant_type"] == Vocabulary.grantTypeTokenExchange)
        #expect(f["resource"] == Self.storage)
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

    @Test func proactiveReuseInsideTheStorageAndItsRootOnly() async throws {
        let auth = authenticator()
        let client = client(auth)
        server.on("GET", "https://elsewhere.example/x") { _ in Respond.text(200, "x") }
        _ = try await client.read(url(Self.root + "a"))
        let before = server.requests.count
        _ = try await client.read(url(Self.root + "b"))
        #expect(server.requests[before].header("Authorization") == "Bearer at-1")
        #expect(server.requests.count == before + 1)
        _ = try await client.read(url("https://elsewhere.example/x"))
        #expect(server.requests.last?.header("Authorization") == nil)
        _ = try? await client.read(url("http://storage.example/root/a"))
        #expect(server.requests.last?.header("Authorization") == nil)
        #expect(state.exchanges == 1)
        #expect(try await auth.accessToken(issuer: Self.asURI, storage: Self.storage).value == "at-1")
    }

    @Test func theTokenIsScopedToTheStorageAndItsRoot() async throws {
        // A storage at /alice whose root is /alice/: the token goes to both, and to nothing beside them.
        let alice = Self.base + "/alice"
        let state = state
        server.on("GET", alice) { _ in Respond.json(200, Self.descriptionJSON(alice, alice + "/"), contentType: MediaType.lwsCID) }
        server.on("GET", alice + "/notes/a") { r in Self.authorized(r, state) ? Respond.text(200, "a") : Self.challenge(alice + "/notes/a", storage: alice) }
        publishMetadata(alice + "/notes/a")
        let client = client(authenticator())
        _ = try await client.read(url(alice + "/notes/a"))
        #expect(form(try #require(server.requests("POST", Self.tokenEndpoint).first))["resource"] == alice)
        for (target, sends) in [(alice, true), (alice + "/", true), (alice + "/x/y", true), (Self.base + "/alicex", false), (Self.base + "/bob/", false)] {
            server.on("GET", target) { _ in Respond.text(200, "ok") }
            _ = try await client.read(url(target))
            #expect(server.requests.last?.header("Authorization") == (sends ? "Bearer at-1" : nil), "\(target)")
        }
    }

    @Test func theRetryCarriesTheTokenOutsideItsScope() async throws {
        // A storage at /alice (root /alice/) whose 401s also come from service endpoints beside it.
        let alice = Self.base + "/alice"
        let state = state
        server.on("GET", alice) { _ in Respond.json(200, Self.descriptionJSON(alice, alice + "/"), contentType: MediaType.lwsCID) }
        for path in ["/services/inbox", "/services/other"] {
            let u = Self.base + path
            server.on("GET", u) { r in Self.authorized(r, state) ? Respond.text(200, path) : Self.challenge(u, storage: alice) }
            publishMetadata(u)
        }
        let moved = Self.base + "/services/moved"
        server.on("GET", moved) { r in
            Self.authorized(r, state) ? Respond.status(302, ("Location", "/services/landing")) : Self.challenge(moved, storage: alice)
        }
        publishMetadata(moved)
        server.on("GET", Self.base + "/services/landing") { _ in Respond.text(200, "landed") }
        let client = client(authenticator())

        #expect(try await client.read(url(Self.base + "/services/inbox")).text == "/services/inbox")
        #expect(server.requests("GET", Self.base + "/services/inbox").map { $0.header("Authorization") } == [nil, "Bearer at-1"])
        // A later URL outside the scope gets no token up front; its 401 reuses the cached token.
        #expect(try await client.read(url(Self.base + "/services/other")).text == "/services/other")
        #expect(server.requests("GET", Self.base + "/services/other").map { $0.header("Authorization") } == [nil, "Bearer at-1"])
        #expect(state.exchanges == 1)
        #expect(server.requests("GET", alice).count == 1)
        // Only the retry carries it: not the next request to the same URL, nor a redirect hop after the retry.
        let before = server.requests.count
        _ = try? await client.read(url(Self.base + "/services/inbox"))
        #expect(server.requests[before].header("Authorization") == nil)
        #expect(try await client.read(url(moved)).text == "landed")
        #expect(server.requests("GET", moved).map { $0.header("Authorization") } == [nil, "Bearer at-1"])
        #expect(server.requests("GET", Self.base + "/services/landing").first?.header("Authorization") == nil)
        #expect(state.exchanges == 1)
    }

    @Test func openIDAndSAMLSubjectTokens() async throws {
        let oidc = client(authenticator(OpenIDCredentials { ctx in
            #expect(ctx.metadata.issuer == Self.asURI)
            #expect(ctx.issuer.absoluteString == Self.asURI)
            #expect(ctx.storage.absoluteString == Self.storage)
            return "my-id-token"
        }))
        _ = try await oidc.read(url(Self.root + "a"))
        let first = try #require(server.requests("POST", Self.tokenEndpoint).first)
        #expect(first.text.contains("subject_token=my-id-token"))
        #expect(first.text.contains("subject_token_type=" + TokenExchangeAuthenticator.formEncode(TokenType.idToken)))

        server.on("GET", Self.metadata) { _ in Respond.json(200, #"{"issuer":"\#(Self.asURI)","token_endpoint":"\#(Self.tokenEndpoint)"}"#) }
        let saml = client(authenticator(SAMLCredentials.fromXML("<saml:Assertion/>")))
        _ = try await saml.read(url(Self.root + "a"))
        let second = try #require(server.requests("POST", Self.tokenEndpoint).last)
        #expect(second.text.contains("subject_token=" + SAMLCredentials.encode("<saml:Assertion/>")))
        #expect(second.text.contains("subject_token_type=" + TokenExchangeAuthenticator.formEncode(TokenType.saml2)))
        #expect(SAMLCredentials.encode("<saml:Assertion/>") == "PHNhbWw6QXNzZXJ0aW9uLz4")
    }

    @Test func aRejectedTokenIsDroppedAndExchangedOnce() async throws {
        let client = client(authenticator())
        _ = try await client.read(url(Self.root + "a"))
        state.revokeAll()  // the server revokes at-1
        _ = try await client.read(url(Self.root + "b"))
        #expect(state.exchanges == 2)
        #expect(server.requests("GET", Self.root + "b").map { $0.header("Authorization") } == ["Bearer at-1", "Bearer at-2"])
    }

    @Test func expiringTokensAreRefreshedBeforeTheyExpire() async throws {
        state.expiresIn = 60
        let client = client(authenticator())
        _ = try await client.read(url(Self.root + "a"))
        clock.advance(29)
        _ = try await client.read(url(Self.root + "a"))
        #expect(state.exchanges == 1)
        clock.advance(2)  // inside the 30 s refresh margin
        let before = server.requests.count
        _ = try await client.read(url(Self.root + "a"))
        #expect(server.requests[before].header("Authorization") == nil)
        #expect(state.exchanges == 2)
    }

    @Test func concurrentRequestsShareOneExchange() async throws {
        let gate = Gate()
        server.beforeRespond = { r in if r.url.absoluteString == Self.tokenEndpoint { await gate.wait() } }
        let client = client(authenticator())
        let results = try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<8 { group.addTask { try await client.read(url(Self.root + "a")).text } }
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
        let created = try await client.createText(in: url(Self.root), text: "hello")
        #expect(created.location.absoluteString == Self.base + "/root/new")
        let posts = server.requests("POST", Self.root)
        #expect(posts.map { $0.header("Authorization") } == [nil, "Bearer at-1"])
        #expect(posts.allSatisfy { $0.text == "hello" })

        // A server that keeps refusing: exactly one retry, then unauthorized.
        let stubborn = Self.root + "stubborn/"
        server.on("POST", stubborn) { _ in Self.challenge(stubborn) }
        publishMetadata(stubborn)
        #expect(kind(await error { try await client.createText(in: url(stubborn), text: "x") }) == "unauthorized")
        #expect(server.requests("POST", stubborn).count == 2)
    }

    @Test func aChallengeWithoutAnAuthorizationServerIsUnauthorized() async throws {
        server.on("GET", Self.base + "/basic") { _ in Respond.status(401, ("WWW-Authenticate", "Basic realm=\"x\"")) }
        let client = client(authenticator())
        let e = await error { try await client.read(url(Self.base + "/basic")) }
        #expect(kind(e) == "unauthorized")
        #expect((e as? LWSError)?.httpError?.challenges.first?.isScheme("basic") == true)
        #expect(state.exchanges == 0)
    }

    @Test func storageDescriptionsAreKeptUntilClear() async throws {
        let auth = authenticator()
        let client = client(auth)
        _ = try await client.read(url(Self.root + "a"))
        state.revokeAll()
        _ = try await client.read(url(Self.root + "b"))  // a second discovery, for another resource
        #expect(server.requests("GET", Self.resourceMetadata(Self.root + "b")).count == 1)
        #expect(server.requests("GET", Self.storage).count == 1)
        #expect(server.requests("GET", Self.metadata).count == 1)
        await auth.clear()
        _ = try await client.read(url(Self.root + "a"))
        #expect(server.requests("GET", Self.storage).count == 2)
        #expect(server.requests("GET", Self.metadata).count == 2)
        #expect(state.exchanges == 3)
    }

    @Test func theIssuerIsTheFirstSecureAndAcceptedAuthorizationServer() async throws {
        let c = Self.root + "c"
        protect("GET", c) { Respond.text(200, "c") }
        publishMetadata(c, ["not a url", "http://plain.example", "https://refused.example", Self.asURI, "https://later.example"])
        let calls = Calls()
        let client = client(authenticator(nil, TokenExchangeOptions(authorizationServerFilter: { issuer, storage in
            calls.record(issuer.absoluteString + " " + storage.absoluteString)
            return issuer.host != "refused.example"
        })))
        #expect(try await client.read(url(c)).text == "c")
        #expect(calls.all == ["https://refused.example \(Self.storage)", "\(Self.asURI) \(Self.storage)"])
        #expect(server.requests("POST", Self.tokenEndpoint).count == 1)
        #expect(!server.requests.contains { ["plain.example", "refused.example", "later.example"].contains($0.url.host ?? "") })
    }

    @Test func aChallengeOfTheDraftsBefore19October2026IsStillFollowed() async throws {
        let realm = Self.base + "/legacy/"
        let state = state
        server.on("GET", realm + "a") { r in Self.authorized(r, state) ? Respond.text(200, "a") : Self.legacyChallenge(realm: realm) }
        server.on("GET", Self.base + "/elsewhere") { _ in Respond.text(200, "e") }
        let client = client(authenticator())
        #expect(try await client.read(url(realm + "a")).text == "a")
        #expect(trace == ["GET \(realm)a", "GET \(Self.metadata)", "POST \(Self.tokenEndpoint)", "GET \(realm)a"])
        #expect(form(try #require(server.requests("POST", Self.tokenEndpoint).first))["resource"] == realm)
        // The realm alone is the token's scope.
        _ = try await client.read(url(Self.base + "/elsewhere"))
        #expect(server.requests.last?.header("Authorization") == nil)

        // The realm must contain the request URL.
        server.on("GET", Self.root + "other") { _ in Self.legacyChallenge(realm: Self.base + "/other/") }
        server.on("GET", Self.base + "/storage_10/x") { _ in Self.legacyChallenge(realm: Self.base + "/storage_1") }
        #expect(kind(await error { try await client.read(url(Self.root + "other")) }) == "authentication")
        #expect(kind(await error { try await client.read(url(Self.base + "/storage_10/x")) }) == "authentication")
        #expect(server.requests("GET", Self.metadata).count == 1)
        #expect(state.exchanges == 1)
    }

    // MARK: - The checks

    @Test func aDecoyChallengeLeavesTheCachedTokenInUse() async throws {
        let client = client(authenticator())
        _ = try await client.read(url(Self.root + "a"))
        #expect(state.exchanges == 1)

        // The storage answers a request that carried the cached token with challenges that must all be refused:
        // metadata on another origin, metadata about another resource, a storage whose root is on another origin, an
        // insecure authorization server, no storage link, a realm that does not contain the URL.
        let decoy = Self.root + "decoy"
        let storageLink = ("Link", #"<\#(Self.storage)>; rel="\#(LinkRelation.storage)""#)
        let elsewhere = "https://evil.example" + Vocabulary.wellKnownOAuthProtectedResource + "/root/decoy"
        server.on("GET", Self.base + "/vault/") { _ in
            Respond.json(200, Self.descriptionJSON(Self.base + "/vault/", "https://evil.example/vault/"), contentType: MediaType.lwsCID)
        }
        let decoys: [(challenge: HTTPResponse, metadata: String)] = [
            (Respond.status(401, ("WWW-Authenticate", #"Bearer resource_metadata="\#(elsewhere)""#), storageLink), Self.resourceMetadataJSON(decoy)),
            (Self.challenge(decoy), Self.resourceMetadataJSON(Self.root + "a")),
            (Self.challenge(decoy, storage: Self.base + "/vault/"), Self.resourceMetadataJSON(decoy)),
            (Self.challenge(decoy), Self.resourceMetadataJSON(decoy, ["http://as.evil.example"])),
            (Respond.status(401, ("WWW-Authenticate", #"Bearer resource_metadata="\#(Self.resourceMetadata(decoy))""#)), Self.resourceMetadataJSON(decoy)),
            (Self.legacyChallenge(realm: "https://evil.example/"), Self.resourceMetadataJSON(decoy)),
        ]
        for (challenge, metadata) in decoys {
            server.on("GET", decoy) { _ in challenge }
            server.on("GET", Self.resourceMetadata(decoy)) { _ in Respond.json(200, metadata) }
            #expect(kind(await error { try await client.read(url(decoy)) }) == "authentication")
            #expect(server.requests("GET", decoy).last?.header("Authorization") == "Bearer at-1")
            let before = server.requests.count
            _ = try await client.read(url(Self.root + "b"))
            #expect(server.requests[before].header("Authorization") == "Bearer at-1")
            #expect(server.requests.count == before + 1)
        }

        let filtered = self.client(authenticator(nil, TokenExchangeOptions(authorizationServerFilter: { issuer, _ in issuer.host == "as.example" })))
        _ = try await filtered.read(url(Self.root + "a"))
        server.on("GET", decoy) { _ in Self.challenge(decoy) }
        publishMetadata(decoy, ["https://as.attacker.example"])
        #expect(kind(await error { try await filtered.read(url(decoy)) }) == "authentication")
        _ = try await filtered.read(url(Self.root + "b"))
        #expect(server.requests.last?.header("Authorization") == "Bearer at-2")
        #expect(!server.requests.contains { ($0.url.host ?? "").contains("attacker") || ($0.url.host ?? "").contains("evil") })
        #expect(state.exchanges == 2)
    }

    @Test func insecureAuthorizationServersAreRefusedUnlessAllowed() async throws {
        let insecure = "http://as.example"
        let c = Self.root + "c"
        let state = state
        server.on("GET", c) { r in Self.authorized(r, state) ? Respond.text(200, "c") : Self.challenge(c) }
        publishMetadata(c, [insecure])
        server.on("GET", insecure + "/.well-known/lws-configuration") { _ in Respond.json(200, Self.metadataJSON(insecure, insecure + "/token")) }
        server.on("POST", insecure + "/token") { _ in Respond.json(200, #"{"access_token":"at-1","token_type":"bearer"}"#) }
        state.allow("at-1")
        let strict = await error { try await self.client(authenticator()).read(url(c)) }
        guard case .authentication(let a)? = strict as? LWSError else {
            Issue.record("expected an authentication error, got \(String(describing: strict))")
            return
        }
        #expect(a.message.contains("HTTPS"))
        #expect(a.status == nil)
        #expect(server.requests("GET", insecure + "/.well-known/lws-configuration").isEmpty)
        let lax = self.client(authenticator(nil, TokenExchangeOptions(allowInsecureHttp: true)))
        #expect(try await lax.read(url(c)).text == "c")
        // An https AS whose token endpoint is plain http is refused too.
        server.on("GET", Self.metadata) { _ in Respond.json(200, Self.metadataJSON(Self.asURI, "http://as.example/token")) }
        #expect(kind(await error { try await self.client(authenticator()).read(url(Self.root + "a")) }) == "authentication")
    }

    @Test func loopbackAuthorizationServersMayUseHTTP() async throws {
        let local = "http://localhost:8787"
        let x = local + "/root/x"
        let state = state
        server.on("GET", x) { r in Self.authorized(r, state) ? Respond.text(200, "x") : Self.challenge(x, storage: local + "/") }
        publishMetadata(x, [local])
        server.on("GET", local + "/") { _ in Respond.json(200, Self.descriptionJSON(local + "/", local + "/root/"), contentType: MediaType.lwsCID) }
        server.on("GET", local + "/.well-known/lws-configuration") { _ in Respond.json(200, Self.metadataJSON(local, local + "/oauth/token")) }
        server.on("POST", local + "/oauth/token") { _ in Respond.json(200, #"{"access_token":"at-local","token_type":"Bearer"}"#) }
        state.allow("at-local")
        let client = client(authenticator())
        #expect(try await client.read(url(x)).text == "x")
        #expect(server.requests("POST", local + "/oauth/token").first?.text.contains("resource=" + TokenExchangeAuthenticator.formEncode(local + "/")) == true)
    }

    @Test func discoveryMetadataAndTokenRequestsNeverFollowRedirects() async throws {
        let client = client(authenticator())
        let a = Self.root + "a"

        server.on("GET", Self.resourceMetadata(a)) { _ in Respond.status(307, ("Location", "https://attacker.example/prm")) }
        let prm = await error { try await client.read(url(a)) }
        #expect(kind(prm) == "authentication")
        #expect((prm as? LWSError)?.status == 307)
        publishMetadata(a)

        server.on("GET", Self.storage) { _ in Respond.status(301, ("Location", "https://attacker.example/")) }
        let description = await error { try await client.read(url(a)) }
        #expect(kind(description) == "authentication")
        #expect((description as? LWSError)?.status == 301)
        server.on("GET", Self.storage) { _ in Respond.json(200, Self.descriptionJSON(Self.storage, Self.root), contentType: MediaType.lwsCID) }

        server.on("GET", Self.metadata) { _ in Respond.status(307, ("Location", "https://attacker.example/.well-known/lws-configuration")) }
        let md = await error { try await client.read(url(a)) }
        #expect(kind(md) == "authentication")
        #expect((md as? LWSError)?.status == 307)
        #expect(server.requests("POST", Self.tokenEndpoint).isEmpty)

        server.on("GET", Self.metadata) { _ in Respond.json(200, Self.metadataJSON(Self.asURI)) }
        server.on("POST", Self.tokenEndpoint) { _ in Respond.status(308, ("Location", "https://attacker.example/token")) }
        let token = await error { try await client.read(url(a)) }
        #expect(kind(token) == "authentication")
        #expect((token as? LWSError)?.status == 308)
        #expect(String(describing: token!).lowercased().contains("redirect"))
        #expect(server.requests("POST", Self.tokenEndpoint).count == 1)
        #expect(!server.requests.contains { $0.url.host == "attacker.example" })
    }

    @Test func discoveryDocumentFailures() async throws {
        let a = Self.root + "a"
        for body in [#"{"resource":"\#(a)"}"#, #"{"resource":"\#(a)","authorization_servers":[]}"#, "[]", "not json"] {
            server.on("GET", Self.resourceMetadata(a)) { _ in Respond.json(200, body) }
            #expect(kind(await error { try await self.client(authenticator()).read(url(a)) }) == "authentication", "\(body)")
        }
        server.on("GET", Self.resourceMetadata(a)) { _ in Respond.text(200, Self.resourceMetadataJSON(a), contentType: "text/html") }
        #expect(kind(await error { try await self.client(authenticator()).read(url(a)) }) == "authentication")
        publishMetadata(a)
        for (status, body) in [(404, ""), (200, #"{"id":"\#(Self.storage)","type":"Container"}"#), (200, "<html/>")] {
            server.on("GET", Self.storage) { _ in Respond.json(status, body, contentType: MediaType.lwsCID) }
            let e = await error { try await self.client(authenticator()).read(url(a)) }
            #expect(kind(e) == "authentication", "\(status) \(body)")
        }
        #expect(state.exchanges == 0)
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
        let e = await error { try await client.read(url(Self.root + "a")) }
        #expect(kind(e) == "authentication")
        #expect(server.requests("POST", Self.tokenEndpoint).isEmpty)
    }

    @Test func authorizationServerFailures() async throws {
        let client = client(authenticator())

        server.on("POST", Self.tokenEndpoint) { _ in Respond.json(400, #"{"error":"invalid_target","error_description":"resource is not a known storage"}"#) }
        let e = await error { try await client.read(url(Self.root + "a")) }
        guard case .authentication(let a)? = e as? LWSError else {
            Issue.record("expected an authentication error, got \(String(describing: e))")
            return
        }
        #expect(a.error == "invalid_target")
        #expect(a.errorDescription == "resource is not a known storage")
        #expect(a.status == 400)

        server.on("POST", Self.tokenEndpoint) { _ in Respond.json(200, #"{"access_token":"x","token_type":"DPoP"}"#) }
        #expect(kind(await error { try await client.read(url(Self.root + "a")) }) == "authentication")
        server.on("POST", Self.tokenEndpoint) { _ in Respond.text(200, "not json") }
        #expect(kind(await error { try await client.read(url(Self.root + "a")) }) == "authentication")

        let other = self.client(authenticator())
        server.on("GET", Self.metadata) { _ in Respond.json(200, Self.metadataJSON("https://not-the-as.example")) }
        #expect(kind(await error { try await other.read(url(Self.root + "a")) }) == "authentication")
        server.on("GET", Self.metadata) { _ in Respond.status(404) }
        #expect((await error { try await other.read(url(Self.root + "a")) } as? LWSError)?.status == 404)
        server.on("GET", Self.metadata) { _ in Respond.json(200, #"{"issuer":"https://as.example"}"#) }
        #expect(kind(await error { try await other.read(url(Self.root + "a")) }) == "authentication")
        server.on("GET", Self.metadata) { _ in
            Respond.json(200, #"{"issuer":"\#(Self.asURI)/","token_endpoint":"\#(Self.tokenEndpoint)","subject_token_types_supported":["\#(TokenType.saml2)"]}"#)
        }
        let unsupported = await error { try await other.read(url(Self.root + "a")) }
        #expect(kind(unsupported) == "authentication")
        #expect(String(describing: unsupported!).contains("does not accept"))
    }

    @Test func tokensNeverLeaveTheirScopeOnRedirects() async throws {
        let state = state
        let moved = Self.root + "moved"
        let renamed = Self.root + "renamed"
        server.on("GET", moved) { r in Self.authorized(r, state) ? Respond.status(302, ("Location", "https://cdn.example/blob")) : Self.challenge(moved) }
        server.on("GET", "https://cdn.example/blob") { _ in Respond.text(200, "blob") }
        server.on("GET", renamed) { r in Self.authorized(r, state) ? Respond.status(308, ("Location", "/root/a")) : Self.challenge(renamed) }
        publishMetadata(moved)
        publishMetadata(renamed)
        let client = client(authenticator())
        #expect(try await client.read(url(moved)).text == "blob")
        #expect(server.requests("GET", "https://cdn.example/blob").first?.header("Authorization") == nil)
        #expect(try await client.read(url(renamed)).text == "a")
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
        let bearer = BearerTokenAuthenticator(realm: url(Self.root)) { "at-\(asked.next() + 1)" }
        let client = client(bearer)
        state.allow("at-1")
        state.allow("at-2")
        server.on("GET", Self.base + "/public") { _ in Respond.text(200, "p") }
        _ = try await client.read(url(Self.root + "a"))
        _ = try await client.read(url(Self.base + "/public"))
        #expect(server.requests.map { $0.header("Authorization") } == ["Bearer at-1", nil])
        #expect(asked.next() == 1)
        // A refused bearer token is not retried.
        state.revokeAll()
        #expect(kind(await error { try await client.read(url(Self.root + "a")) }) == "unauthorized")
        #expect(state.exchanges == 0)
        #expect(bearer.realm?.absoluteString == Self.root)
    }

    // MARK: - The discovery vectors

    /// `{A}` and `{B}`: two origins of one loopback port, as a real server would see them.
    private static let originA = "http://127.0.0.1:8787"
    private static let originB = "http://localhost:8787"

    private static func expand(_ s: String) -> String {
        s.replacingOccurrences(of: "{A}", with: originA).replacingOccurrences(of: "{B}", with: originB)
    }

    /// `conformance/fixtures/discovery.json`, each case through the authenticator against a fake server that answers
    /// as the fixture describes.
    @Test(arguments: Fixtures.names("discovery.json"))
    func discoveryVectors(name: String) async throws {
        let c = Fixtures.case("discovery.json", name)
        let server = FakeServer()
        let request = Self.expand(c["request"]!.str)
        let challenge = HTTPHeaders(c["challenge"]!.object.map { ($0.key, Self.expand($0.value.str)) })
        server.on("GET", request) { r in
            r.header("Authorization") == "Bearer token-1" ? Respond.text(200, "ok") : HTTPResponse(url: url("about:blank"), status: 401, headers: challenge)
        }
        for d in c["documents"]!.object {
            let status = Int(d.value["status"]!.intValue!)
            let headers = HTTPHeaders(d.value["headers"]!.object.map { ($0.key, Self.expand($0.value.str)) })
            let body = d.value["body"]!.isNull ? Data() : Data(Self.expand(d.value["body"]!.serialized()).utf8)
            server.on("GET", Self.expand(d.key)) { _ in HTTPResponse(url: url("about:blank"), status: status, headers: headers, body: body) }
        }
        let tokenResponse = Fixtures.load("discovery.json")["tokenResponse"]!.serialized()
        server.on("POST", Self.originA + "/as/token") { _ in Respond.json(200, tokenResponse) }
        let auth = TokenExchangeAuthenticator(credentials: OpenIDCredentials(idToken: "id-token"), options: TokenExchangeOptions(transport: server))
        let client = LWSClient(options: LWSClientOptions(transport: server, authenticator: auth))

        let e = c["expected"]!
        let failure = await error { try await client.read(url(request)) }
        let outcomes = ["ok": "none", "AuthenticationError": "authentication", "UnauthorizedError": "unauthorized"]
        #expect(kind(failure) == outcomes[e["outcome"]!.str], "\(String(describing: failure))")
        if failure == nil { #expect(server.requests.last?.header("Authorization") == "Bearer token-1") }
        let posts = server.requests.filter { $0.method == "POST" }
        if let t = e["tokenRequest"], !t.isNull {
            #expect(posts.map(\.url.absoluteString) == [Self.expand(t["endpoint"]!.str)])
            #expect(posts.first.map(form)?["resource"] == Self.expand(t["resource"]!.str))
        } else {
            #expect(posts.isEmpty)
        }
        for u in e["notFetched"]!.strings {
            let target = url(Self.expand(u)).absoluteString
            #expect(!server.requests.contains { $0.url.absoluteString == target }, "\(target) was requested")
        }
        for t in e["then"]?.arrayValue ?? [] {
            let target = Self.expand(t["request"]!.str)
            server.on("GET", target) { _ in Respond.text(200, "ok") }
            _ = try await client.read(url(target))
            #expect(server.requests.last?.header("Authorization") == (t["sendsToken"]!.boolValue! ? "Bearer token-1" : nil), "\(target)")
        }
    }

    // MARK: - Credentials

    @Test func selfSignedCredentialsCacheTokensPerAudience() async throws {
        let ed = try SelfSignedCredentials.didKey(.generateEd25519()).withClock(clock.function)
        #expect(ed.agent.hasPrefix("did:key:z6Mk"))
        #expect(ed.algorithm == "EdDSA")
        #expect(try DIDKey.keyID(forDID: ed.agent) == ed.keyID)
        let md = try AuthorizationServerMetadata.parse(JSONValue(parsing: Self.metadataJSON(Self.asURI)), base: url(Self.metadata))
        let other = try AuthorizationServerMetadata.parse(JSONValue(parsing: Self.metadataJSON("https://as2.example", "https://as2.example/t")),
                                                          base: url(Self.metadata))
        let context = CredentialContext(issuer: url(Self.asURI), storage: url(Self.storage), metadata: md)
        let t1 = try await ed.subjectToken(for: context)
        #expect(try await ed.subjectToken(for: context) == t1)
        let t2 = try await ed.subjectToken(for: CredentialContext(issuer: url(Self.asURI), storage: url(Self.storage), metadata: other))
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
