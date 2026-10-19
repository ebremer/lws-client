// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.FakeTransport.Companion.response
import com.ebremer.lws.kotlin.auth.AuthorizationServerMetadata
import com.ebremer.lws.kotlin.auth.BearerTokenAuthenticator
import com.ebremer.lws.kotlin.auth.CredentialContext
import com.ebremer.lws.kotlin.auth.DidKey
import com.ebremer.lws.kotlin.auth.Jwt
import com.ebremer.lws.kotlin.auth.OpenIdCredentials
import com.ebremer.lws.kotlin.auth.SamlCredentials
import com.ebremer.lws.kotlin.auth.SelfSignedCredentials
import com.ebremer.lws.kotlin.auth.SigningKey
import com.ebremer.lws.kotlin.auth.TokenExchangeAuthenticator
import com.ebremer.lws.kotlin.http.HttpRequest
import com.ebremer.lws.kotlin.http.HttpResponse
import com.ebremer.lws.kotlin.internal.Base64Url
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URI
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** A clock the test moves. */
class MutableClock(var now: Instant) : Clock() {
    override fun getZone(): ZoneId = ZoneOffset.UTC

    override fun withZone(zone: ZoneId?): Clock = this

    override fun instant(): Instant = now
}

/**
 * The authorization flow: 401 → protected resource metadata → storage description → metadata → token exchange →
 * retry, its checks, and the challenge of the drafts before 19 October 2026.
 */
class AuthFlowTest {
    private val exchanges = mutableListOf<Map<String, String>>()
    private var issued = 0

    /** The token each storage accepts. */
    private val valid = mutableMapOf<String, String>()
    private val clock = MutableClock(Instant.ofEpochSecond(1_800_000_000))
    private lateinit var metadata: JsonObject

    /** The authorization servers the protected resource metadata names. */
    private var authorizationServers = listOf(AS)

    /** The realm of a challenge of the drafts before 19 October 2026 (`as_uri` AS); null for the RFC 9728 challenge. */
    private var challengeRealm: String? = null
    private lateinit var transport: FakeTransport
    private lateinit var auth: TokenExchangeAuthenticator
    private var override: (suspend (HttpRequest) -> HttpResponse?)? = null

    @BeforeEach
    fun setUp() {
        metadata = buildJsonObject {
            put("issuer", AS)
            put("token_endpoint", "$AS/token")
            put("subject_token_types_supported", JsonArray(listOf(TokenType.JWT, TokenType.ID_TOKEN, TokenType.SAML2).map(::JsonPrimitive)))
        }
    }

    /** The storage a URL is in: [STORAGE_B] below it and for its services (outside it), else [STORAGE]. */
    private fun storageOf(url: String): String = if (url.startsWith(STORAGE_B) || url.startsWith(SERVICES_B)) STORAGE_B else STORAGE

    /** The protected resource metadata URL of a resource of the origin (RFC 9728 section 3.1). */
    private fun metadataUrl(url: String): String = ORIGIN + Vocabulary.WELL_KNOWN_OAUTH_PROTECTED_RESOURCE + url.removePrefix(ORIGIN)

    private fun challenge(url: String): Array<Pair<String, String>> {
        challengeRealm?.let { return arrayOf("WWW-Authenticate" to "Bearer as_uri=\"$AS\", realm=\"$it\", error=\"invalid_token\"") }
        return arrayOf(
            "WWW-Authenticate" to "Bearer resource_metadata=\"${metadataUrl(url)}\", error=\"invalid_token\"",
            "Link" to "<${storageOf(url)}>; rel=\"https://www.w3.org/ns/lws#storage\"",
        )
    }

    private fun description(storage: String, root: String = storage + "root/"): JsonElement =
        json("""{"id":"$storage","type":"Storage","service":[{"type":"StorageRoot","serviceEndpoint":"$root"}]}""")

    private suspend fun handle(r: HttpRequest): HttpResponse {
        override?.invoke(r)?.let { return it }
        val u = r.url.toString()
        if (u == "$AS/.well-known/lws-configuration") return response(r, 200, "Content-Type" to "application/json", body = metadata)
        if (u == "$AS/token") {
            delay(10)
            val f = r.form
            exchanges.add(f)
            val token = "tok-" + ++issued
            valid[f.getValue("resource")] = token
            return response(r, 200, "Content-Type" to "application/json", body = json("""{"access_token":"$token","token_type":"Bearer","expires_in":3600}"""))
        }
        if (u.startsWith("https://other.example/")) return response(r, 200, body = r.headers["authorization"] ?: "anonymous")
        if (!u.startsWith(ORIGIN)) return response(r, 404)
        val prm = ORIGIN + Vocabulary.WELL_KNOWN_OAUTH_PROTECTED_RESOURCE
        if (u.startsWith(prm)) {
            val servers = JsonArray(authorizationServers.map(::JsonPrimitive))
            return response(r, 200, "Content-Type" to "application/json", body = JsonObject(mapOf("resource" to JsonPrimitive(ORIGIN + u.removePrefix(prm)), "authorization_servers" to servers)))
        }
        if (u == STORAGE || u == STORAGE_B) return response(r, 200, "Content-Type" to "application/lws+cid", body = description(u))
        val expected = valid[storageOf(u)]
        if (expected != null && r.headers["authorization"] == "Bearer $expected") {
            return if (r.method == "POST") response(r, 201, "Location" to "/c/new", body = "secret") else response(r, 200, body = "secret")
        }
        return response(r, 401, *challenge(u))
    }

    private fun client(
        credentials: SelfSignedCredentials? = null,
        allowInsecureHttp: Boolean = false,
        filter: ((String, String) -> Boolean)? = null,
    ): LwsClient {
        transport = FakeTransport(::handle)
        val c = credentials ?: SelfSignedCredentials.didKey(SigningKey.generateP256()).withClock(clock)
        auth = TokenExchangeAuthenticator(c, allowInsecureHttp = allowInsecureHttp, authorizationServerFilter = filter, transport = transport, clock = clock)
        return LwsClient(authenticator = auth, transport = transport)
    }

    private val log: List<String> get() = transport.requests.map { "${it.method} ${it.url}" }

    @Test
    fun fullFlowAndProactiveReuse() = runTest {
        val key = SigningKey.generateP256()
        val me = SelfSignedCredentials.didKey(key).withClock(clock)
        val client = client(me)
        assertEquals("secret", client.read(URI(STORAGE + "notes/a.txt")).text())
        assertEquals(
            listOf(
                "GET https://storage.example/notes/a.txt",
                "GET https://storage.example/.well-known/oauth-protected-resource/notes/a.txt",
                "GET https://storage.example/",
                "GET https://as.example/.well-known/lws-configuration",
                "POST https://as.example/token",
                "GET https://storage.example/notes/a.txt",
            ),
            log,
        )
        // The protected resource metadata and the storage description are read without credentials.
        val (prm, description) = transport.requests[1] to transport.requests[2]
        assertEquals(listOf<String?>("application/json", null), listOf(prm.headers["accept"], prm.headers["authorization"]))
        assertEquals(listOf<String?>(LwsClient.ACCEPT_DESCRIPTION, null), listOf(description.headers["accept"], description.headers["authorization"]))
        val f = exchanges.single()
        assertEquals(listOf(Vocabulary.GRANT_TYPE_TOKEN_EXCHANGE, STORAGE, TokenType.JWT), listOf(f["grant_type"], f["resource"], f["subject_token_type"]))
        assertEquals("application/x-www-form-urlencoded", transport.requests[4].headers["content-type"])
        assertEquals("Bearer tok-1", transport.requests[5].headers["authorization"])
        // The subject token: a self-signed JWT for the authorization server.
        val jwt = f.getValue("subject_token")
        assertTrue(Jwt.verify(jwt, key.publicKey))
        val claims = Jwt.decodeClaims(jwt)
        val did = DidKey.did(key.publicKey)
        assertEquals(listOf<JsonElement>(JsonPrimitive(did), JsonPrimitive(did), JsonPrimitive(did), JsonArray(listOf(JsonPrimitive(AS)))),
            listOf(claims["sub"]!!, claims["iss"]!!, claims["client_id"]!!, claims["aud"]!!))
        assertEquals(300L, claims.str("exp").toLong() - claims.str("iat").toLong())
        assertEquals(listOf("ES256", "JWT", DidKey.keyId(key.publicKey)), Jwt.decodeHeader(jwt).values.map { it.str })
        assertTrue(Regex("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$").matches(claims.str("jti")))
        // Proactive: the next request inside the storage carries the token at once; the metadata is cached.
        transport.requests.clear()
        client.read(URI(STORAGE + "other/b.txt"))
        assertEquals(listOf("GET https://storage.example/other/b.txt"), log)
        assertEquals("Bearer tok-1", transport.last.headers["authorization"])
        assertEquals("tok-1", auth.accessToken(AS, STORAGE).value)
        assertTrue(STORAGE in auth.toString())
        // Never outside the storage.
        assertEquals("anonymous", client.read(URI("https://other.example/x")).text())
    }

    @Test
    fun postBodyIsReplayedOnceAfterThe401() = runTest {
        val client = client()
        val created = client.createText(URI(STORAGE + "c/"), "Hello")
        assertEquals(URI(STORAGE + "c/new"), created.location)
        val posts = transport.requests.filter { it.url == URI(STORAGE + "c/") }
        assertEquals(listOf("Hello", "Hello"), posts.map { it.text })
    }

    @Test
    fun concurrentRequestsShareOneExchange() = runTest {
        val client = client()
        val bodies = (1..5).map { i -> async { client.read(URI(STORAGE + "n/$i")).text() } }.awaitAll()
        assertEquals(List(5) { "secret" }, bodies)
        assertEquals(1, exchanges.size)
    }

    @Test
    fun invalidTokenIsDroppedAndExchangedAgainOnce() = runTest {
        val client = client()
        client.read(URI(STORAGE + "a"))
        valid.clear() // the storage forgets the token
        client.read(URI(STORAGE + "a"))
        assertEquals(2, exchanges.size)
        assertEquals("Bearer tok-2", transport.last.headers["authorization"])
        // A storage that refuses every token: one retry, then the 401 surfaces.
        override = { r -> if (r.url == URI(STORAGE + "a")) response(r, 401, *challenge(STORAGE + "a")) else null }
        val e = assertFailsWith<UnauthorizedException> { client.read(URI(STORAGE + "a")) }
        assertEquals(metadataUrl(STORAGE + "a"), e.challenges[0].resourceMetadata)
        assertEquals(3, exchanges.size)
    }

    @Test
    fun tokensAreRefreshedBeforeTheyExpire() = runTest {
        val client = client()
        client.read(URI(STORAGE + "a"))
        clock.now = clock.now.plusSeconds(3600 - 31)
        client.read(URI(STORAGE + "a"))
        assertEquals(1, exchanges.size)
        clock.now = clock.now.plusSeconds(2) // inside the 30 s refresh margin: not sent, so the storage challenges and the client exchanges anew
        client.read(URI(STORAGE + "a"))
        assertEquals(2, exchanges.size)
    }

    @Test
    fun theLongestScopeThatHoldsTheUrlWins() = runTest {
        val client = client()
        client.read(URI(STORAGE + "a"))
        // The storage at /b/ refuses the token of the storage at /, which the request carried, and links to itself.
        assertEquals("secret", client.read(URI(STORAGE_B + "x")).text())
        assertEquals("Bearer tok-1", transport.requests.first { it.url == URI(STORAGE_B + "x") }.headers["authorization"])
        assertEquals(listOf(STORAGE, STORAGE_B), exchanges.map { it["resource"] })
        client.read(URI(STORAGE_B + "root/y"))
        assertEquals("Bearer tok-2", transport.last.headers["authorization"])
        client.read(URI(STORAGE + "c"))
        assertEquals("Bearer tok-1", transport.last.headers["authorization"], "the other token was not dropped")
        assertEquals(2, exchanges.size)
    }

    @Test
    fun theRetryCarriesTheTokenOutsideItsScope() = runTest {
        val client = client()
        // A URL of the storage at /b/ that is neither below it nor below its root passes the checks: the retry carries the token.
        assertEquals("secret", client.read(URI(SERVICES_B + "inbox")).text())
        assertEquals(listOf(null, "Bearer tok-1"), transport.requests.filter { it.url == URI(SERVICES_B + "inbox") }.map { it.headers["authorization"] })
        // Another such URL gets no token up front, and its 401 reuses the cached token without a second exchange.
        assertEquals("secret", client.read(URI(SERVICES_B + "other")).text())
        assertEquals(listOf(null, "Bearer tok-1"), transport.requests.filter { it.url == URI(SERVICES_B + "other") }.map { it.headers["authorization"] })
        assertEquals(1, exchanges.size)
        // Inside its scope, the token goes at once.
        transport.requests.clear()
        client.read(URI(STORAGE_B + "x"))
        assertEquals(listOf("Bearer tok-1"), transport.requests.map { it.headers["authorization"] })
    }

    @Test
    fun storageDescriptionsAreCachedUntilClear() = runTest {
        val client = client()
        client.read(URI(STORAGE + "a"))
        valid.clear()
        client.read(URI(STORAGE + "a")) // the metadata describes one resource, and is read again; the description is not
        val gets = { u: String -> transport.requests.count { it.url.toString() == u } }
        assertEquals(listOf(2, 1), listOf(gets(metadataUrl(STORAGE + "a")), gets(STORAGE)))
        auth.clear()
        client.read(URI(STORAGE + "a"))
        assertEquals(listOf(3, 2, 2), listOf(gets(metadataUrl(STORAGE + "a")), gets(STORAGE), gets("$AS/.well-known/lws-configuration")))
        assertEquals(3, exchanges.size)
    }

    @Test
    fun theChallengeOfEarlierDrafts() = runTest {
        challengeRealm = STORAGE
        val client = client()
        assertEquals("secret", client.read(URI(STORAGE + "notes/a.txt")).text())
        assertEquals(
            listOf(
                "GET https://storage.example/notes/a.txt",
                "GET https://as.example/.well-known/lws-configuration",
                "POST https://as.example/token",
                "GET https://storage.example/notes/a.txt",
            ),
            log,
        )
        assertEquals(STORAGE, exchanges.single()["resource"])
        client.read(URI(STORAGE + "b.txt"))
        assertEquals("Bearer tok-1", transport.last.headers["authorization"])
    }

    @Test
    fun realmMustContainTheRequest() = runTest {
        val client = client()
        challengeRealm = STORAGE + "alice/"
        val e = assertFailsWith<AuthenticationException> { client.read(URI(STORAGE + "bob/x")) }
        assertTrue("not within the challenge realm" in e.message!!)
        assertEquals(listOf("GET https://storage.example/bob/x"), log, "nothing is sent to the authorization server")
    }

    @Test
    fun aDecoyChallengeDoesNotEvictAWorkingToken() = runTest {
        val client = client()
        client.read(URI(STORAGE + "a"))
        // Resources whose 401 names a realm that does not contain them, or links to a storage whose root is elsewhere.
        override = { r ->
            when (r.url.toString()) {
                STORAGE + "decoy" -> response(r, 401, "WWW-Authenticate" to "Bearer as_uri=\"https://evil.example\", realm=\"https://evil.example/\"")
                STORAGE + "vault" -> response(
                    r, 401, "WWW-Authenticate" to "Bearer resource_metadata=\"${metadataUrl(STORAGE + "vault")}\"",
                    "Link" to "<${STORAGE}vault/>; rel=\"https://www.w3.org/ns/lws#storage\"",
                )
                STORAGE + "vault/" -> response(r, 200, "Content-Type" to "application/lws+cid", body = description(STORAGE + "vault/", "https://evil.example/vault/"))
                else -> null
            }
        }
        for (decoy in listOf("decoy", "vault")) {
            val e = assertFailsWith<AuthenticationException> { client.read(URI(STORAGE + decoy)) }
            assertEquals("Bearer tok-1", transport.requests.first { it.url == URI(STORAGE + decoy) }.headers["authorization"])
            if (decoy == "vault") assertTrue("not on the origin" in e.message!!, e.message)
        }
        client.read(URI(STORAGE + "a"))
        assertEquals("Bearer tok-1", transport.last.headers["authorization"])
        assertEquals(1, exchanges.size)
    }

    @Test
    fun authorizationServerMustUseHttps() = runTest {
        authorizationServers = listOf("http://as.example")
        val e = assertFailsWith<AuthenticationException> { client().read(URI(STORAGE + "a")) }
        assertTrue("insecure" in e.message!!)
        assertFalse(transport.requests.any { "lws-configuration" in it.url.toString() })
        // allowInsecureHttp, and loopback hosts, may use http (the metadata then fails here, past the check).
        for ((allow, a) in listOf(true to "http://as.example", false to "http://127.0.0.1:9")) {
            authorizationServers = listOf(a)
            val x = assertFailsWith<AuthenticationException> { client(allowInsecureHttp = allow).read(URI(STORAGE + "a")) }
            assertFalse("insecure" in x.message!!)
            assertTrue("lws-configuration" in transport.last.url.toString())
        }
        // The first acceptable server of the metadata is the one asked.
        authorizationServers = listOf("http://as.example", "not a url", AS)
        assertEquals("secret", client().read(URI(STORAGE + "a")).text())
        // An https issuer with an http token endpoint.
        metadata = JsonObject(metadata + ("token_endpoint" to JsonPrimitive("http://as.example/token")))
        assertFailsWith<AuthenticationException> { client().read(URI(STORAGE + "a")) }
    }

    @Test
    fun authorizationServerFilter() = runTest {
        var seen: List<String> = emptyList()
        val client = client(filter = { issuer, storage ->
            seen = listOf(issuer, storage)
            false
        })
        val e = assertFailsWith<AuthenticationException> { client.read(URI(STORAGE + "a")) }
        assertTrue("rejected by the authorization server filter" in e.message!!)
        assertEquals(listOf(AS, STORAGE), seen)
        assertEquals(listOf("GET ${STORAGE}a", "GET ${metadataUrl(STORAGE + "a")}", "GET $STORAGE"), log, "no credential is sent")
    }

    @Test
    fun metadataAndTokenRequestsNeverFollowRedirects() = runTest {
        override = { r -> if (r.url.toString() == "$AS/.well-known/lws-configuration") response(r, 302, "Location" to "https://evil.example/md") else null }
        var e = assertFailsWith<AuthenticationException> { client().read(URI(STORAGE + "a")) }
        assertEquals(302, e.status)
        assertTrue("Refusing the redirect to https://evil.example/md" in e.message!!)
        assertEquals(0, exchanges.size)
        override = { r -> if (r.url.toString() == "$AS/token") response(r, 307, "Location" to "https://evil.example/token") else null }
        e = assertFailsWith<AuthenticationException> { client().read(URI(STORAGE + "a")) }
        assertEquals(307, e.status)
        assertFalse(transport.requests.any { it.url.toString() == "https://evil.example/token" })
        // Nor do the protected resource metadata and the storage description.
        for (u in listOf(metadataUrl(STORAGE + "a"), STORAGE)) {
            override = { r -> if (r.url.toString() == u) response(r, 301, "Location" to "https://evil.example/doc") else null }
            e = assertFailsWith<AuthenticationException> { client().read(URI(STORAGE + "a")) }
            assertEquals(301, e.status, u)
            assertFalse(transport.requests.any { it.url.toString() == "https://evil.example/doc" })
        }
        assertEquals(0, exchanges.size)
        // A transport that answers from another URL than the one requested has followed a redirect.
        override = { r -> if (r.url.toString() == "$AS/.well-known/lws-configuration") HttpResponse(URI("https://evil.example/md"), 200) else null }
        assertFailsWith<AuthenticationException> { client().read(URI(STORAGE + "a")) }
    }

    @Test
    fun metadataProblems() = runTest {
        for (md in listOf(
            """{"issuer":"https://other.example","token_endpoint":"$AS/token"}""",
            """{"token_endpoint":"$AS/token"}""",
            """{"issuer":"$AS"}""",
            """{"issuer":"$AS","token_endpoint":"$AS/token","subject_token_types_supported":["${TokenType.SAML2}"]}""",
        )) {
            metadata = json(md) as JsonObject
            assertFailsWith<AuthenticationException>(md) { client().read(URI(STORAGE + "a")) }
            assertEquals(0, exchanges.size)
        }
        // The issuer may differ by one trailing slash.
        metadata = json("""{"issuer":"$AS/","token_endpoint":"/token"}""") as JsonObject
        assertEquals("secret", client().read(URI(STORAGE + "a")).text())
    }

    @Test
    fun tokenEndpointErrors() = runTest {
        override = { r ->
            if (r.url.toString() == "$AS/token") response(r, 400, "Content-Type" to "application/json", body = json("""{"error":"invalid_grant","error_description":"bad signature"}""")) else null
        }
        val e = assertFailsWith<AuthenticationException> { client().read(URI(STORAGE + "a")) }
        assertEquals(listOf<Any?>("invalid_grant", "bad signature", 400), listOf(e.oauthError, e.oauthErrorDescription, e.status))
        for (body in listOf("""{"access_token":"t","token_type":"DPoP"}""", """{"token_type":"Bearer"}""", "not json")) {
            override = { r -> if (r.url.toString() == "$AS/token") response(r, 200, "Content-Type" to "application/json", body = body) else null }
            val x = assertFailsWith<AuthenticationException>(body) { client().read(URI(STORAGE + "a")) }
            assertEquals(200, x.status)
        }
    }

    @Test
    fun noUsableChallengeSurfacesThe401() = runTest {
        override = { r -> response(r, 401, "WWW-Authenticate" to "Bearer realm=\"x\", DPoP algs=\"ES256\"") }
        val e = assertFailsWith<UnauthorizedException> { client().read(URI(STORAGE + "a")) }
        assertEquals(2, e.challenges.size)
        assertEquals(1, transport.requests.size)
    }

    @Test
    fun redirectHopsAreAuthorizedForTheirOwnUrl() = runTest {
        val client = client()
        client.read(URI(STORAGE + "a"))
        override = { r -> if (r.url == URI(STORAGE + "moved")) response(r, 302, "Location" to "https://other.example/landing") else null }
        assertEquals("anonymous", client.read(URI(STORAGE + "moved")).text())
        assertEquals("Bearer tok-1", transport.requests[transport.requests.size - 2].headers["authorization"])
    }

    @Test
    fun bearerTokenAuthenticator() = runTest {
        val t = FakeTransport { r -> response(r, 200, body = r.headers["authorization"] ?: "-") }
        val client = LwsClient(authenticator = BearerTokenAuthenticator("abc", realm = URI(STORAGE + "alice/")), transport = t)
        assertEquals("Bearer abc", client.read(URI(STORAGE + "alice/x")).text())
        assertEquals("-", client.read(URI(STORAGE + "bob/x")).text())
        var n = 0
        val dynamic = LwsClient(authenticator = BearerTokenAuthenticator { if (++n == 1) null else "t$n" }, transport = t)
        assertEquals(listOf("-", "Bearer t2"), listOf(dynamic.read(URI(STORAGE)).text(), dynamic.read(URI(STORAGE)).text()))
        assertFalse("abc" in BearerTokenAuthenticator("abc").toString())
    }

    @Test
    fun openIdAndSamlCredentials() = runTest {
        client() // sets up the transport (the storage and the authorization server)
        var seen: List<String> = emptyList()
        val openid = OpenIdCredentials { c ->
            seen = listOf(c.issuer, c.storage, c.metadata.issuer)
            "id.token.here"
        }
        var client = LwsClient(authenticator = TokenExchangeAuthenticator(openid, transport = transport), transport = transport)
        client.read(URI(STORAGE + "a"))
        assertEquals(listOf(AS, STORAGE, AS), seen)
        assertEquals(listOf("id.token.here", TokenType.ID_TOKEN), listOf(exchanges[0]["subject_token"], exchanges[0]["subject_token_type"]))
        val saml = SamlCredentials.fromXml("<saml:Assertion>é</saml:Assertion>")
        assertEquals(TokenType.SAML2, saml.tokenType)
        client = LwsClient(authenticator = TokenExchangeAuthenticator(saml, transport = transport), transport = transport)
        valid.clear()
        client.read(URI(STORAGE + "a"))
        assertEquals(Base64Url.encode("<saml:Assertion>é</saml:Assertion>".toByteArray()), exchanges[1]["subject_token"])
        assertEquals(TokenType.SAML2, exchanges[1]["subject_token_type"])
        assertEquals("abc", SamlCredentials.fromEncoded("abc").subjectToken(CredentialContext(AS, STORAGE, AuthorizationServerMetadata(AS, URI("$AS/token")))))
        assertEquals("fixed", OpenIdCredentials("fixed").subjectToken(CredentialContext(AS, STORAGE, AuthorizationServerMetadata(AS, URI("$AS/token")))))
    }

    @Test
    fun selfSignedCredentialsCacheAndOptions() = runTest {
        val c = MutableClock(Instant.ofEpochSecond(1_800_000_000))
        val key = SigningKey.generateEd25519()
        val creds = SelfSignedCredentials.forAgent("https://id.example/alice", key, "https://id.example/alice#key-1").withLifetime(120.seconds).withClock(c)
        fun context(issuer: String) = CredentialContext(issuer, STORAGE, AuthorizationServerMetadata(issuer, URI("$issuer/token")))
        val a = creds.subjectToken(context(AS))
        assertEquals(a, creds.subjectToken(context(AS)), "reused for the same audience")
        assertNotEquals(a, creds.subjectToken(context("https://as2.example")))
        c.now = c.now.plusSeconds(61) // 120 s lifetime, reused until 60 s before expiry
        assertNotEquals(a, creds.subjectToken(context(AS)))
        val header = Jwt.decodeHeader(a)
        val claims = Jwt.decodeClaims(a)
        assertEquals(listOf("EdDSA", "https://id.example/alice#key-1"), listOf(header.str("alg"), header.str("kid")))
        assertEquals(listOf("https://id.example/alice", "120"), listOf(claims.str("sub"), (claims.str("exp").toLong() - claims.str("iat").toLong()).toString()))
        assertTrue(Jwt.verify(a, creds.publicKey))
        assertEquals("EdDSA", creds.algorithm)
        assertEquals(TokenType.JWT, creds.tokenType)
        assertFalse(key.jwk().str("d") in creds.toString())
        assertFailsWith<IllegalArgumentException> { SelfSignedCredentials.didKey(SigningKey.generate("ES384")) }
    }

    private companion object {
        const val ORIGIN = "https://storage.example"
        const val STORAGE = "$ORIGIN/"
        const val STORAGE_B = "$ORIGIN/b/"
        const val SERVICES_B = "$ORIGIN/services/"
        const val AS = "https://as.example"
    }
}
