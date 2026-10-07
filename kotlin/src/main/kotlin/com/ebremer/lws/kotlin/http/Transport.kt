// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin.http

import com.ebremer.lws.kotlin.TransportException
import kotlinx.coroutines.future.await
import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpTimeoutException
import java.util.concurrent.CompletionException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration
import java.net.http.HttpRequest as JdkRequest
import java.net.http.HttpResponse as JdkResponse

/**
 * A request for an [HttpTransport].
 *
 * @property method the method (`GET`, `QUERY`, …)
 * @property url the absolute target URL
 * @property body the body bytes, or null for none (an empty array is an empty body, `Content-Length: 0`)
 * @property timeout the time limit of the whole exchange, or null for the transport's own
 */
public class HttpRequest(
    public val method: String,
    public val url: URI,
    public val headers: Headers = Headers.EMPTY,
    public val body: ByteArray? = null,
    public val timeout: Duration? = null,
) {
    public fun withHeaders(headers: Headers): HttpRequest = HttpRequest(method, url, headers, body, timeout)

    public fun withTimeout(timeout: Duration?): HttpRequest = HttpRequest(method, url, headers, body, timeout)

    override fun toString(): String = "$method $url"
}

/**
 * A response from an [HttpTransport].
 *
 * @property url the URL that answered (the request URL: transports do not follow redirects)
 */
public class HttpResponse(
    public val url: URI,
    public val status: Int,
    public val headers: Headers = Headers.EMPTY,
    public val body: ByteArray = ByteArray(0),
) {
    override fun toString(): String = "$status $url"
}

/**
 * The HTTP engine of a client: sends one request and returns the response as it came, without following
 * redirects (the client follows them itself, authorizing every hop). Failures without a response are
 * [TransportException]s. Implementations must be safe to call from several coroutines at once.
 *
 * The default is [JdkHttpTransport]; another engine (OkHttp, Ktor, a test double) needs only this one function.
 */
public fun interface HttpTransport {
    public suspend fun send(request: HttpRequest): HttpResponse
}

/**
 * An [HttpTransport] on `java.net.http.HttpClient`, which supports any method (`PATCH`, `QUERY`) and cancels the
 * exchange when the calling coroutine is cancelled.
 *
 * @param client the JDK client; it must not follow redirects (`HttpClient.Redirect.NEVER`, the default of
 *     [defaultClient])
 */
public class JdkHttpTransport(private val client: HttpClient = defaultClient()) : HttpTransport {

    override suspend fun send(request: HttpRequest): HttpResponse {
        val publisher = request.body?.let { JdkRequest.BodyPublishers.ofByteArray(it) } ?: JdkRequest.BodyPublishers.noBody()
        // The JDK refuses some requests the caller asked for (a header it sets itself, such as Host or
        // Content-Length): those are IllegalArgumentExceptions, as for any unusable argument.
        val builder = try {
            JdkRequest.newBuilder(request.url).method(request.method, publisher)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Cannot send ${request.method} ${request.url}: ${e.message}", e)
        }
        request.timeout?.let { builder.timeout(it.toJavaDuration()) }
        for ((name, value) in request.headers) {
            try {
                builder.header(name, value)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("Cannot send header $name: ${e.message}", e)
            }
        }
        val response = try {
            client.sendAsync(builder.build(), JdkResponse.BodyHandlers.ofByteArray()).await()
        } catch (e: HttpTimeoutException) {
            throw TransportException("${request.method} ${request.url} timed out", isTimeout = true, cause = e)
        } catch (e: IOException) {
            throw TransportException("${request.method} ${request.url} failed: ${e.message ?: e.javaClass.simpleName}", cause = e)
        } catch (e: CompletionException) {
            val cause = e.cause ?: e
            throw TransportException("${request.method} ${request.url} failed: ${cause.message ?: cause.javaClass.simpleName}",
                isTimeout = cause is HttpTimeoutException, cause = cause)
        }
        val headers = Headers.of(
            response.headers().map().entries
                .filter { !it.key.startsWith(":") }
                .flatMap { e -> e.value.map { e.key to it } }
                .filter { (n, v) -> Headers.isToken(n) && v.none { c -> c == '\r' || c == '\n' || c == '\u0000' } },
        )
        return HttpResponse(request.url, response.statusCode(), headers, response.body() ?: ByteArray(0))
    }

    public companion object {
        /** A JDK client that follows no redirects and connects within 30 seconds. */
        public fun defaultClient(connectTimeout: Duration = 30.seconds): HttpClient = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(connectTimeout.toJavaDuration())
            .build()
    }
}
