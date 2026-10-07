// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.http.Headers
import com.ebremer.lws.kotlin.http.HttpRequest
import com.ebremer.lws.kotlin.http.HttpResponse
import com.ebremer.lws.kotlin.http.HttpTransport
import com.ebremer.lws.kotlin.internal.JsonAccess
import kotlinx.serialization.json.JsonElement
import java.util.Collections

/** A transport that answers with a handler and records every request. */
class FakeTransport(private val handler: suspend (HttpRequest) -> HttpResponse) : HttpTransport {
    val requests: MutableList<HttpRequest> = Collections.synchronizedList(mutableListOf())

    override suspend fun send(request: HttpRequest): HttpResponse {
        requests.add(request)
        return handler(request)
    }

    val last: HttpRequest get() = requests.last()

    val methods: List<String> get() = requests.map { it.method }

    companion object {
        /** A response; a body that is not a string or bytes is serialized as JSON. */
        fun response(request: HttpRequest, status: Int = 200, vararg headers: Pair<String, String>, body: Any? = null): HttpResponse {
            val bytes = when (body) {
                null -> ByteArray(0)
                is ByteArray -> body
                is String -> body.toByteArray()
                is JsonElement -> JsonAccess.encode(body).toByteArray()
                else -> throw IllegalArgumentException("body")
            }
            return HttpResponse(request.url, status, Headers.of(*headers), bytes)
        }
    }
}

/** The body of a recorded request as text. */
val HttpRequest.text: String? get() = body?.toString(Charsets.UTF_8)
