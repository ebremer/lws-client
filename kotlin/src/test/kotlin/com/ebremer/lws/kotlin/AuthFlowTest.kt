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
import java.net.URLDecoder
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

/** The authorization flow: 401 → metadata → token exchange → retry, and its checks. */
class AuthFlowTest {
    private val exchanges = mutableListOf<Map<String, String>>()
    private var issued = 0

    /** The token each realm accepts. */
    private val valid = mutableMapOf<String, String>()
    private val clock = MutableClock(Instant.ofEpochSecond(1_800_000_000))
    private lateinit var metadata: JsonObject
    private var challengeRealm = STORAGE
    private var asUri = AS
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

    private fun form(body: String): Map<String, String> =
        body.split('&').associate { p -> p.substringBefore('=') to URLDecoder.decode(p.substringAfter('='), Charsets.UTF_8) }

    private suspend fun handle(r: HttpRequest): HttpResponse {
        override?.invoke(r)?.let { return it }
        val u = r.url.toString()
        if (u == "$AS/.well-known/lws-configuration") return response(r, 200, "Content-Type" to "application/json", body = metadata)
        if (u == "$AS/token") {
            delay(10)
            val f = form(r.text!!)
            exchanges.add(f)
            val token = "tok-" + ++issued
            valid[f.getValue("resource")] = token
            return response(r, 200, "Content-Type" to "application/json", body = json("""{"access_token":"$token","token_type":"Bearer","expires_in":3600}"""))
        }
        if (u.startsWith("https://other.example/")) return response(r, 200, body = r.headers["authorization"] ?: "anonymous")
        val expected = valid[STORAGE]
        if (expected != null && r.headers["authorization"] == "Bearer $expected") {
            return if (r.method == "POST") response(r, 201, "Location" to "/c/new", body = "secret") else response(r, 200, body = "secret")
        }
        return response(r, 401, "WWW-Authenticate" to "Bearer as_uri=\"$asUri\", realm=\"$challengeRealm\", error=\"invalid_token\"")
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
                "GET https://as.example/.well-known/lws-configuration",
                "POST https://as.example/token",
                "GET https://storage.example/notes/a.txt",
            ),
            log,
        )
        val f = exchanges.single()
        assertEquals(listOf(Vocabulary.GRANT_TYPE_TOKEN_EXCHANGE, STORAGE, TokenType.JWT), listOf(f["grant_type"], f["resource"], f["subject_token_type"]))
        assertEquals("application/x-www-form-urlencoded", transport.requests[2].headers["content-type"])
        assertEquals("Bearer tok-1", transport.requests[3].headers["authorization"])
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
        // Proactive: the next request inside the realm carries the token at once; the metadata is cached.
        transport.requests.clear()
        client.read(URI(STORAGE + "other/b.txt"))
        assertEquals(listOf("GET https://storage.example/other/b.txt"), log)
        assertEquals("Bearer tok-1", transport.last.headers["authorization"])
        assertEquals("tok-1", auth.accessToken(AS, STORAGE).value)
        // Never outside the realm.
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
        override = { r ->
            if (r.url.toString().startsWith(STORAGE)) response(r, 401, "WWW-Authenticate" to "Bearer as_uri=\"https://as.example\", realm=\"https://storage.example/\"") else null
        }
        val e = assertFailsWith<UnauthorizedException> { client.read(URI(STORAGE + "a")) }
        assertEquals("https://as.example", e.challenges[0].asUri)
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
        // A resource whose 401 names a realm that does not contain it.
        override = { r ->
            if (r.url == URI(STORAGE + "decoy")) response(r, 401, "WWW-Authenticate" to "Bearer as_uri=\"https://evil.example\", realm=\"https://evil.example/\"") else null
        }
        assertFailsWith<AuthenticationException> { client.read(URI(STORAGE + "decoy")) }
        client.read(URI(STORAGE + "a"))
        assertEquals("Bearer tok-1", transport.last.headers["authorization"])
        assertEquals(1, exchanges.size)
    }

    @Test
    fun authorizationServerMustUseHttps() = runTest {
        asUri = "http://as.example"
        val e = assertFailsWith<AuthenticationException> { client().read(URI(STORAGE + "a")) }
        assertTrue("insecure" in e.message!!)
        // allowInsecureHttp, and loopback hosts, may use http (the metadata then fails here, past the check).
        for ((allow, a) in listOf(true to "http://as.example", false to "http://127.0.0.1:9")) {
            asUri = a
            val x = assertFailsWith<AuthenticationException> { client(allowInsecureHttp = allow).read(URI(STORAGE + "a")) }
            assertFalse("insecure" in x.message!!)
            assertTrue("lws-configuration" in transport.last.url.toString())
        }
        // An https issuer with an http token endpoint.
        asUri = AS
        metadata = JsonObject(metadata + ("token_endpoint" to JsonPrimitive("http://as.example/token")))
        assertFailsWith<AuthenticationException> { client().read(URI(STORAGE + "a")) }
    }

    @Test
    fun authorizationServerFilter() = runTest {
        var seen: List<String> = emptyList()
        val client = client(filter = { a, realm ->
            seen = listOf(a, realm)
            false
        })
        assertFailsWith<AuthenticationException> { client.read(URI(STORAGE + "a")) }
        assertEquals(listOf(AS, STORAGE), seen)
        assertEquals(1, transport.requests.size)
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
            seen = listOf(c.issuer, c.realm, c.metadata.issuer)
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
        const val STORAGE = "https://storage.example/"
        const val AS = "https://as.example"
    }
}
