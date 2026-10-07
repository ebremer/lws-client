// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin.internal

import com.ebremer.lws.kotlin.ProtocolException
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.Charset
import java.nio.charset.CodingErrorAction
import java.time.DateTimeException
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.LocalTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.Locale
import kotlin.math.abs
import kotlin.math.floor

/** Reading JSON documents of responses, leniently: members of the wrong type count as absent. */
internal object JsonAccess {
    /** Parses JSON text (UTF-8, a byte order mark allowed). */
    fun decode(bytes: ByteArray): JsonElement {
        val text = utf8(bytes) ?: throw SerializationException("the text is not UTF-8")
        return Json.parseToJsonElement(text.removePrefix("﻿"))
    }

    /** Parses a response body; [ProtocolException] when it is not JSON. */
    fun parse(body: ByteArray, what: String): JsonElement = try {
        decode(body)
    } catch (e: SerializationException) {
        throw ProtocolException("$what is not valid JSON: ${e.message}", e)
    } catch (e: IllegalArgumentException) {
        throw ProtocolException("$what is not valid JSON: ${e.message}", e)
    }

    /** Serialises a JSON value compactly. */
    fun encode(value: JsonElement): String = Json.encodeToString(JsonElement.serializer(), value)

    /** A JSON value that must be an object; [ProtocolException] otherwise. */
    fun obj(value: JsonElement?, what: String): JsonObject =
        value as? JsonObject ?: throw ProtocolException("$what is not a JSON object")

    fun str(o: JsonObject, key: String): String? = (o[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

    /** A member that is a string or a list of strings, as a list (other values are skipped). */
    fun strings(o: JsonObject, key: String): List<String> = strings(o[key])

    fun strings(v: JsonElement?): List<String> = when (v) {
        is JsonPrimitive -> if (v.isString) listOf(v.content) else emptyList()
        is JsonArray -> v.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
        else -> emptyList()
    }

    /** An integer member (a number with no fraction), or null. */
    fun long(o: JsonObject, key: String): Long? = long(o[key])

    fun long(v: JsonElement?): Long? {
        val p = v as? JsonPrimitive ?: return null
        if (p.isString || p.content == "null" || p.content == "true" || p.content == "false") return null
        p.content.toLongOrNull()?.let { return it }
        val d = p.content.toDoubleOrNull() ?: return null
        return if (floor(d) == d && abs(d) < 9.0e18) d.toLong() else null
    }

    fun bool(o: JsonObject, key: String): Boolean? {
        val p = o[key] as? JsonPrimitive ?: return null
        if (p.isString) return null
        return when (p.content) {
            "true" -> true
            "false" -> false
            else -> null
        }
    }

    /** A string member resolved against a base URL (null when absent or not resolvable). */
    fun url(o: JsonObject, key: String, base: URI?): URI? =
        str(o, key)?.let { Urls.resolve(it, base?.toString()) }?.let(Urls::toUri)

    /** The `type` (or `@type`) values, a single string normalised to a list. */
    fun types(o: JsonObject): List<String> = if ("type" in o) strings(o, "type") else strings(o, "@type")

    /** A member that is an object or a list of objects, as a list of objects. */
    fun objects(o: JsonObject, key: String): List<JsonObject> = when (val v = o[key]) {
        is JsonObject -> listOf(v)
        is JsonArray -> v.filterIsInstance<JsonObject>()
        else -> emptyList()
    }

    /** Strictly decoded UTF-8, or null for malformed bytes. */
    fun utf8(bytes: ByteArray): String? = try {
        Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
    } catch (_: CharacterCodingException) {
        null
    }
}

/** RFC 3339 and HTTP dates. */
internal object Dates {
    private val RFC3339 = Regex("""^(\d{4})-(\d{2})-(\d{2})(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?([Zz]|[+-]\d{2}:?\d{2})?)?$""")
    private val HTTP_DATE: DateTimeFormatter =
        DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US).withZone(ZoneOffset.UTC)

    /** Parses an RFC 3339 date-time (or a plain date), or returns null when it is not one. */
    fun parseRfc3339(text: String?): Instant? {
        val m = text?.let { RFC3339.matchEntire(it.trim(' ', '\t')) } ?: return null
        val g = m.groupValues
        return try {
            val date = LocalDate.of(g[1].toInt(), g[2].toInt(), g[3].toInt())
            val nanos = if (g[7].isEmpty()) 0 else g[7].padEnd(9, '0').substring(0, 9).toInt()
            val time = LocalTime.of(
                g[4].ifEmpty { "0" }.toInt(), g[5].ifEmpty { "0" }.toInt(),
                minOf(g[6].ifEmpty { "0" }.toInt(), 59), nanos,
            )
            val zone = g[8]
            val offset = if (zone.isEmpty() || zone == "Z" || zone == "z") {
                ZoneOffset.UTC
            } else {
                val digits = zone.substring(1).replace(":", "")
                ZoneOffset.of(zone[0] + digits.substring(0, 2) + ":" + digits.substring(2, 4))
            }
            LocalDateTime.of(date, time).toInstant(offset)
        } catch (_: DateTimeException) {
            null
        }
    }

    /** Formats an instant as RFC 3339 in UTC (`2026-10-07T12:00:00Z`, fractional seconds only when present). */
    fun formatRfc3339(instant: Instant): String = DateTimeFormatter.ISO_INSTANT.format(instant)

    /** Formats an instant as an HTTP date (`Tue, 06 Oct 2026 12:00:00 GMT`). */
    fun formatHttpDate(instant: Instant): String = HTTP_DATE.format(instant)

    /** Parses an HTTP date (IMF-fixdate), or returns null. */
    fun parseHttpDate(text: String?): Instant? = try {
        text?.let { Instant.from(HTTP_DATE.parse(it.trim())) }
    } catch (_: DateTimeException) {
        null
    }
}

/** Comma-separated header lists and media types. */
internal object HeaderLists {
    /** Splits field values at commas outside quoted strings; members are trimmed and empty ones dropped. */
    fun split(values: Iterable<String>): List<String> {
        val out = mutableListOf<String>()
        fun add(cur: CharSequence) {
            val s = cur.trim { it == ' ' || it == '\t' }
            if (s.isNotEmpty()) out.add(s.toString())
        }
        for (v in values) {
            val cur = StringBuilder()
            var quoted = false
            var escaped = false
            for (c in v) {
                if (quoted) {
                    cur.append(c)
                    when {
                        escaped -> escaped = false
                        c == '\\' -> escaped = true
                        c == '"' -> quoted = false
                    }
                } else if (c == '"') {
                    quoted = true
                    cur.append(c)
                } else if (c == ',') {
                    add(cur)
                    cur.setLength(0)
                } else {
                    cur.append(c)
                }
            }
            add(cur)
        }
        return out
    }

    /** The media type without parameters, lower-cased, or null. */
    fun essence(contentType: String?): String? {
        val s = contentType?.substringBefore(';')?.trim(' ', '\t')?.trim('"') ?: return null
        return s.ifEmpty { null }?.lowercase()
    }

    /** Whether a media type is JSON (`application/json` or a `+json` suffix). */
    fun isJson(contentType: String?): Boolean {
        val e = essence(contentType) ?: return false
        return e == "application/json" || e.endsWith("+json")
    }

    /** The `charset` parameter, or null. */
    fun charset(contentType: String?): String? {
        val parts = contentType?.split(';')?.drop(1) ?: return null
        for (part in parts) {
            val p = part.trim(' ', '\t')
            if (p.length >= 8 && p.substring(0, 8).equals("charset=", ignoreCase = true)) {
                return p.substring(8).trim(' ', '\t').trim('"').ifEmpty { null }
            }
        }
        return null
    }

    /** Decodes a body to text by the charset of its content type (UTF-8 by default; a byte order mark is dropped). */
    fun decode(bytes: ByteArray, contentType: String?): String {
        val charset = charset(contentType)?.let {
            try {
                Charset.forName(it)
            } catch (_: IllegalArgumentException) {
                null
            }
        } ?: Charsets.UTF_8
        return String(bytes, charset).removePrefix("﻿")
    }

    /** Removes one pair of surrounding double quotes. */
    fun unquote(s: String): String = if (s.length >= 2 && s.first() == '"' && s.last() == '"') s.substring(1, s.length - 1) else s
}

/** base64url without padding (RFC 4648 section 5), as JOSE uses it. */
internal object Base64Url {
    private val ALPHABET = Regex("^[A-Za-z0-9_-]*$")

    fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    /** Decodes base64url (padding optional), or returns null for other characters. */
    fun decode(text: String): ByteArray? {
        val t = text.trimEnd('=')
        if (!ALPHABET.matches(t) || t.length % 4 == 1) return null
        return try {
            Base64.getUrlDecoder().decode(t)
        } catch (_: IllegalArgumentException) {
            null
        }
    }
}
