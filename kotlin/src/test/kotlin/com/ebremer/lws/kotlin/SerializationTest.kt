// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.http.Headers
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import org.junit.jupiter.api.Test
import java.net.URI
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** Bodies read into, and written from, @Serializable classes. */
class SerializationTest {
    @Serializable
    data class Todo(val task: String, val done: Boolean = false)

    private val lenient = Json { ignoreUnknownKeys = true }
    private val withDefaults = Json { encodeDefaults = true }

    @Test
    fun decodeAndEncode() {
        val r = Resource(ResourceMetadata(URI("https://s.example/t.json"), 200, Headers.of("Content-Type" to "application/json")), """{"task":"write docs","done":true,"extra":1}""".toByteArray())
        assertEquals(Todo("write docs", true), r.decode<Todo>(lenient))
        assertFailsWith<SerializationException> { r.decode<Todo>() }
        assertEquals(json("""{"task":"x","done":false}"""), withDefaults.encodeToJsonElement(Todo("x")))
    }
}
