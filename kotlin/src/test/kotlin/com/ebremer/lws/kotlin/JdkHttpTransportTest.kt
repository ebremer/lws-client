// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.http.Headers
import com.ebremer.lws.kotlin.http.HttpRequest
import com.ebremer.lws.kotlin.http.JdkHttpTransport
import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.URI
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** [JdkHttpTransport] against a local server: any method with a body, headers, no redirects, failures. */
class JdkHttpTransportTest {
    private lateinit var server: HttpServer
    private lateinit var base: String

    @BeforeEach
    fun start() {
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/echo") { x ->
            val body = x.requestBody.readAllBytes()
            val answer = "${x.requestMethod} ${x.requestHeaders.getFirst("X-Test")} ${x.requestHeaders.getFirst("Content-Type")} ${String(body)}".toByteArray()
            x.responseHeaders.add("Link", "<a>; rel=\"next\"")
            x.responseHeaders.add("Link", "<b>; rel=\"prev\"")
            if (x.requestMethod == "HEAD") {
                x.sendResponseHeaders(200, -1)
            } else {
                x.sendResponseHeaders(200, answer.size.toLong())
                x.responseBody.write(answer)
            }
            x.close()
        }
        server.createContext("/redirect") { x ->
            x.responseHeaders.add("Location", "/echo")
            x.sendResponseHeaders(302, -1)
            x.close()
        }
        server.start()
        base = "http://127.0.0.1:${server.address.port}"
    }

    @AfterEach
    fun stop() = server.stop(0)

    @Test
    fun methodsBodiesAndHeaders() = runBlocking {
        val t = JdkHttpTransport()
        for (method in listOf("QUERY", "PATCH", "POST", "PUT")) {
            val r = t.send(HttpRequest(method, URI("$base/echo"), Headers.of("X-Test" to "yes", "Content-Type" to "text/plain"), "body".toByteArray()))
            assertEquals(200, r.status)
            assertEquals("$method yes text/plain body", String(r.body))
            assertEquals(listOf("<a>; rel=\"next\"", "<b>; rel=\"prev\""), r.headers.all("link"))
        }
        val head = t.send(HttpRequest("HEAD", URI("$base/echo")))
        assertEquals(listOf(200, 0), listOf(head.status, head.body.size))
        assertEquals("GET null null ", String(t.send(HttpRequest("GET", URI("$base/echo"))).body))
        // A header the JDK sets itself is the caller's mistake.
        assertFailsWith<IllegalArgumentException> { LwsClient().head(URI("$base/echo"), headers = mapOf("Host" to "elsewhere")) }
    }

    @Test
    fun redirectsAreNotFollowed() = runBlocking {
        val r = JdkHttpTransport().send(HttpRequest("GET", URI("$base/redirect")))
        assertEquals(302, r.status)
        assertEquals("/echo", r.headers["location"])
        assertEquals(URI("$base/redirect"), r.url)
        // Through the client, the redirect is followed (by the client).
        assertEquals("GET null null ", LwsClient().read(URI("$base/redirect")).text())
    }

    @Test
    fun refusedConnectionIsATransportError() = runBlocking {
        val port = ServerSocket(0).use { it.localPort }
        val e = assertFailsWith<TransportException> { JdkHttpTransport().send(HttpRequest("GET", URI("http://127.0.0.1:$port/"))) }
        assertFalse(e.isTimeout)
    }

    @Test
    fun timeoutIsReported() = runBlocking {
        ServerSocket(0).use { silent ->
            val e = assertFailsWith<TransportException> {
                JdkHttpTransport().send(HttpRequest("QUERY", URI("http://127.0.0.1:${silent.localPort}/"), Headers.EMPTY, "{}".toByteArray(), 300.milliseconds))
            }
            assertTrue(e.isTimeout, e.message)
            // Through the client, its timeout applies.
            val c = assertFailsWith<TransportException> { LwsClient(timeout = 0.3.seconds).head(URI("http://127.0.0.1:${silent.localPort}/")) }
            assertTrue(c.isTimeout)
        }
    }
}
