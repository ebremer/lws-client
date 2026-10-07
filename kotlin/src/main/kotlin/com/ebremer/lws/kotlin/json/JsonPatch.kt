// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin.json

import com.ebremer.lws.kotlin.MediaType
import com.ebremer.lws.kotlin.internal.JsonAccess
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * A JSON Patch (RFC 6902), the baseline `PATCH` format of LWS (`application/json-patch+json`).
 *
 * ```kotlin
 * val patch = jsonPatch {
 *     replace("/done", true)
 *     add("/tags/-", "urgent")
 * }
 * client.patch(url, patch, ifMatch = etag)
 * ```
 *
 * The builder methods add an operation and return the patch, for chaining. A patch is not thread-safe while it is
 * being built; the client serializes it when it sends it.
 */
public class JsonPatch(operations: Iterable<JsonElement> = emptyList()) : Iterable<JsonObject> {
    private val ops = operations.mapTo(mutableListOf(), ::validate)

    public fun add(path: String, value: JsonElement): JsonPatch = op("add", "path" to JsonPrimitive(path), "value" to value)

    public fun add(path: String, value: String): JsonPatch = add(path, JsonPrimitive(value))

    public fun add(path: String, value: Number): JsonPatch = add(path, JsonPrimitive(value))

    public fun add(path: String, value: Boolean): JsonPatch = add(path, JsonPrimitive(value))

    public fun remove(path: String): JsonPatch = op("remove", "path" to JsonPrimitive(path))

    public fun replace(path: String, value: JsonElement): JsonPatch = op("replace", "path" to JsonPrimitive(path), "value" to value)

    public fun replace(path: String, value: String): JsonPatch = replace(path, JsonPrimitive(value))

    public fun replace(path: String, value: Number): JsonPatch = replace(path, JsonPrimitive(value))

    public fun replace(path: String, value: Boolean): JsonPatch = replace(path, JsonPrimitive(value))

    public fun move(from: String, path: String): JsonPatch = op("move", "from" to JsonPrimitive(from), "path" to JsonPrimitive(path))

    public fun copy(from: String, path: String): JsonPatch = op("copy", "from" to JsonPrimitive(from), "path" to JsonPrimitive(path))

    public fun test(path: String, value: JsonElement): JsonPatch = op("test", "path" to JsonPrimitive(path), "value" to value)

    public fun test(path: String, value: String): JsonPatch = test(path, JsonPrimitive(value))

    public fun test(path: String, value: Number): JsonPatch = test(path, JsonPrimitive(value))

    public fun test(path: String, value: Boolean): JsonPatch = test(path, JsonPrimitive(value))

    private fun op(name: String, vararg members: Pair<String, JsonElement>): JsonPatch {
        ops.add(JsonObject(mapOf("op" to JsonPrimitive(name)) + members))
        return this
    }

    /** The operations so far, as JSON objects. */
    public val operations: List<JsonObject> get() = ops.toList()

    /** The number of operations. */
    public val size: Int get() = ops.size

    override fun iterator(): Iterator<JsonObject> = operations.iterator()

    /** The patch as a JSON array. */
    public fun toJson(): JsonArray = JsonArray(ops.toList())

    /** The serialized patch. */
    public fun encode(): String = JsonAccess.encode(toJson())

    override fun toString(): String = encode()

    public companion object {
        public const val MEDIA_TYPE: String = MediaType.JSON_PATCH

        /**
         * A patch from its JSON text.
         *
         * @throws IllegalArgumentException when it is not an array of valid operations
         */
        public fun fromJson(json: String): JsonPatch {
            val value = try {
                JsonAccess.decode(json.toByteArray(Charsets.UTF_8))
            } catch (e: SerializationException) {
                throw IllegalArgumentException("A JSON Patch is not valid JSON: ${e.message}", e)
            }
            return fromJson(value)
        }

        /**
         * A patch from a JSON array of operations.
         *
         * @throws IllegalArgumentException when it is not an array of valid operations
         */
        public fun fromJson(json: JsonElement): JsonPatch {
            require(json is JsonArray) { "A JSON Patch must be an array of operations" }
            return JsonPatch(json)
        }

        private fun validate(op: JsonElement): JsonObject {
            val o = op as? JsonObject
            val name = o?.let { JsonAccess.str(it, "op") }
            val path = o?.let { JsonAccess.str(it, "path") }
            require(o != null && name != null && path != null) { "A JSON Patch operation needs string \"op\" and \"path\" members" }
            fun pointer(p: String) = require(p.isEmpty() || p.startsWith("/")) { "Not a JSON Pointer: $p" }
            pointer(path)
            return when (name) {
                "add", "replace", "test" -> {
                    val value = o["value"]
                    requireNotNull(value) { "A JSON Patch '$name' operation needs a value" }
                    JsonObject(mapOf("op" to JsonPrimitive(name), "path" to JsonPrimitive(path), "value" to value))
                }
                "remove" -> JsonObject(mapOf("op" to JsonPrimitive(name), "path" to JsonPrimitive(path)))
                "move", "copy" -> {
                    val from = JsonAccess.str(o, "from")
                    requireNotNull(from) { "A JSON Patch '$name' operation needs a string 'from'" }
                    pointer(from)
                    JsonObject(mapOf("op" to JsonPrimitive(name), "from" to JsonPrimitive(from), "path" to JsonPrimitive(path)))
                }
                else -> throw IllegalArgumentException("Unknown JSON Patch operation: $name")
            }
        }
    }
}

/** Builds a [JsonPatch]: `jsonPatch { replace("/done", true) }`. */
public fun jsonPatch(build: JsonPatch.() -> Unit): JsonPatch = JsonPatch().apply(build)

/**
 * JSON Pointer (RFC 6901) escaping, needed for linkset relation keys that are URIs:
 * `JsonPointer.fromSegments("linkset", "0", "https://example.org/rel", "-")` is
 * `/linkset/0/https:~1~1example.org~1rel/-`.
 */
public object JsonPointer {
    /** Escapes one reference token (`~` → `~0`, `/` → `~1`). */
    public fun escape(segment: String): String = segment.replace("~", "~0").replace("/", "~1")

    /** Unescapes one reference token. */
    public fun unescape(token: String): String = token.replace("~1", "/").replace("~0", "~")

    /** Builds a pointer from unescaped segments (none: the whole document, `""`). */
    public fun fromSegments(vararg segments: Any): String = fromSegments(segments.map { it.toString() })

    /** Builds a pointer from unescaped segments. */
    public fun fromSegments(segments: List<String>): String = segments.joinToString("") { "/" + escape(it) }

    /**
     * Splits a pointer into unescaped segments.
     *
     * @throws IllegalArgumentException when it is neither empty nor starts with `/`
     */
    public fun segments(pointer: String): List<String> {
        if (pointer.isEmpty()) return emptyList()
        require(pointer.startsWith("/")) { "A JSON Pointer must start with '/': $pointer" }
        return pointer.substring(1).split('/').map(::unescape)
    }
}
