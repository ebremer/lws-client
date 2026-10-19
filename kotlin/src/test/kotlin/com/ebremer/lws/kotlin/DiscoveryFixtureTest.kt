// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.FakeTransport.Companion.response
import com.ebremer.lws.kotlin.auth.SelfSignedCredentials
import com.ebremer.lws.kotlin.auth.SigningKey
import com.ebremer.lws.kotlin.auth.TokenExchangeAuthenticator
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import java.net.URI
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.fail

/** conformance/fixtures/discovery.json, through the TokenExchangeAuthenticator against an in-process transport. */
class DiscoveryFixtureTest {
    /** {A} and {B}: two https origins, and two loopback origins on one port (plain HTTP, as loopback hosts may). */
    private val origins = listOf("https://storage.example" to "https://other.example", "http://127.0.0.1:8787" to "http://localhost:8787")

    private fun expand(e: JsonElement, a: String, b: String): JsonElement = when (e) {
        is JsonObject -> JsonObject(e.entries.associate { (k, v) -> k.replace("{A}", a).replace("{B}", b) to expand(v, a, b) })
        is JsonArray -> JsonArray(e.map { expand(it, a, b) })
        is JsonPrimitive -> if (e.isString) JsonPrimitive(e.content.replace("{A}", a).replace("{B}", b)) else e
    }

    @TestFactory
    fun discoveryFixture(): List<DynamicTest> {
        val fixture = Fixtures.load("discovery.json")
        return origins.flatMap { (a, b) ->
            fixture.arr("cases").map { c ->
                val case = expand(c, a, b).jsonObject
                DynamicTest.dynamicTest("${case.str("name")} ($a)") { runTest { run(case, a, fixture.obj("tokenResponse")) } }
            }
        }
    }

    private suspend fun run(case: JsonObject, a: String, tokenResponse: JsonObject) {
        val request = case.str("request")
        val challenge = case.obj("challenge").entries.map { it.key to it.value.str }.toTypedArray()
        val documents = case.obj("documents")
        val expected = case.obj("expected")
        val then = (expected["then"] as? JsonArray)?.map { it.jsonObject } ?: emptyList()
        var later = false
        val transport = FakeTransport { r ->
            val u = r.url.toString()
            val document = documents[u] as? JsonObject
            when {
                r.method == "POST" && u == "$a/as/token" -> response(r, 200, "Content-Type" to "application/json", body = tokenResponse)
                u == request && r.headers["authorization"] == "Bearer token-1" -> response(r, 200, "Content-Type" to "text/plain", body = "ok")
                u == request -> response(r, 401, *challenge)
                later && then.any { it.str("request") == u } -> response(r, 200, "Content-Type" to "text/plain", body = "ok")
                r.method == "GET" && document != null -> response(
                    r, document.str("status").toInt(), *document.obj("headers").entries.map { it.key to it.value.str }.toTypedArray(),
                    body = document["body"]?.takeIf { it != JsonNull },
                )
                else -> response(r, 404)
            }
        }
        val auth = TokenExchangeAuthenticator(SelfSignedCredentials.didKey(SigningKey.generateP256()), transport = transport)
        val client = LwsClient(authenticator = auth, transport = transport)
        when (val outcome = expected.str("outcome")) {
            "ok" -> {
                assertEquals("ok", client.read(URI(request)).text())
                assertEquals(listOf(null, "Bearer token-1"), transport.requests.filter { it.url == URI(request) }.map { it.headers["authorization"] }, "retried once")
            }
            "AuthenticationError" -> assertFailsWith<AuthenticationException> { client.read(URI(request)) }
            "UnauthorizedError" -> assertFailsWith<UnauthorizedException> { client.read(URI(request)) }
            else -> fail("unknown outcome $outcome")
        }
        val tokenRequests = transport.requests.filter { it.method == "POST" }
        val tokenRequest = expected["tokenRequest"] as? JsonObject
        if (tokenRequest == null) {
            assertEquals(emptyList(), tokenRequests.map { it.url }, "no token request")
        } else {
            val made = tokenRequests.single()
            assertEquals(tokenRequest.str("endpoint"), made.url.toString())
            assertEquals(tokenRequest.str("resource"), made.form["resource"])
        }
        val fetched = transport.requests.map { it.url.toString() }.toSet()
        for (u in expected.strings("notFetched")) assertFalse(u in fetched, "$u was fetched")
        later = true
        for (t in then) {
            assertEquals("ok", client.read(URI(t.str("request"))).text())
            assertEquals(if (t.flag("sendsToken")) "Bearer token-1" else null, transport.last.headers["authorization"], t.str("request"))
        }
    }
}
