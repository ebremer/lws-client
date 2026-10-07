// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin.http

import java.math.BigDecimal
import java.math.RoundingMode
import java.util.Base64

/** A bare item of a structured field (RFC 9651 section 3.3). */
public sealed interface SfBareItem

/** An integer (at most 15 digits). */
public data class SfInteger(val value: Long) : SfBareItem

/** A decimal (at most 12 integer and 3 fractional digits). */
public data class SfDecimal(val value: BigDecimal) : SfBareItem

/** A string of printable ASCII. */
public data class SfString(val value: String) : SfBareItem

/** A token, such as `sha-256` or `tok/en`. */
public data class SfToken(val value: String) : SfBareItem

/** A byte sequence (`:base64:`). */
public class SfBytes(bytes: ByteArray) : SfBareItem {
    private val data = bytes.copyOf()

    /** A copy of the bytes. */
    public val bytes: ByteArray get() = data.copyOf()

    override fun equals(other: Any?): Boolean = other is SfBytes && other.data.contentEquals(data)

    override fun hashCode(): Int = data.contentHashCode()

    override fun toString(): String = "SfBytes(" + Base64.getEncoder().encodeToString(data) + ")"
}

/** A boolean (`?1`, `?0`). */
public data class SfBoolean(val value: Boolean) : SfBareItem

/** A date (`@1659578233`), in seconds since the epoch. */
public data class SfDate(val seconds: Long) : SfBareItem

/** A display string (`%"…"`), Unicode text. */
public data class SfDisplayString(val value: String) : SfBareItem

/** A member of a dictionary or list: an item or an inner list, each with parameters. */
public sealed interface SfMember {
    public val params: Map<String, SfBareItem>
}

/** An item with its parameters. */
public data class SfItem(val value: SfBareItem, override val params: Map<String, SfBareItem> = emptyMap()) : SfMember

/** An inner list (`("a" "b");p=1`) with its parameters. */
public data class SfInnerList(val items: List<SfItem>, override val params: Map<String, SfBareItem> = emptyMap()) : SfMember

/** A structured field value that does not parse, or a value that cannot be serialized. */
public class StructuredFieldException(message: String) : IllegalArgumentException(message)

/**
 * Structured Field Values (RFC 9651): the dictionaries of `Signature-Input`, `Signature` and `Content-Digest`,
 * lists and items, and their canonical serialization, from which `@signature-params` is reproduced.
 */
public object StructuredFields {
    private const val TCHAR = "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val KEY_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789_-.*"
    private const val BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    private val TOKEN = Regex("^[A-Za-z*][!#$%&'*+\\-.^_`|~0-9A-Za-z:/]*$")
    private val KEY = Regex("^[a-z*][a-z0-9_\\-.*]*$")
    private val MAX_DECIMAL = BigDecimal("1000000000000")

    /** Parses a dictionary; a key given twice keeps its first position and its last value. */
    public fun parseDictionary(input: String): Map<String, SfMember> {
        val p = Parser(input)
        p.skipSp()
        val out = LinkedHashMap<String, SfMember>()
        while (!p.atEnd()) {
            val key = p.key()
            if (p.peek() == '=') {
                p.i++
                out[key] = p.itemOrInnerList()
            } else {
                out[key] = SfItem(SfBoolean(true), p.parameters())
            }
            p.skipOws()
            if (p.atEnd()) break
            p.expect(',')
            p.skipOws()
            if (p.atEnd()) throw StructuredFieldException("Trailing comma in a dictionary")
        }
        return out
    }

    /** Parses a list. */
    public fun parseList(input: String): List<SfMember> {
        val p = Parser(input)
        p.skipSp()
        val out = mutableListOf<SfMember>()
        while (!p.atEnd()) {
            out.add(p.itemOrInnerList())
            p.skipOws()
            if (p.atEnd()) break
            p.expect(',')
            p.skipOws()
            if (p.atEnd()) throw StructuredFieldException("Trailing comma in a list")
        }
        return out
    }

    /** Parses an item. */
    public fun parseItem(input: String): SfItem {
        val p = Parser(input)
        p.skipSp()
        val item = p.item()
        p.skipSp()
        if (!p.atEnd()) throw StructuredFieldException("Unexpected characters after an item")
        return item
    }

    private class Parser(val s: String) {
        var i = 0

        /** Trailing spaces are discarded at the top level. */
        fun atEnd(): Boolean = (i until s.length).all { s[it] == ' ' }

        fun peek(): Char = if (i < s.length) s[i] else '\u0000'

        fun expect(c: Char) {
            if (peek() != c) throw StructuredFieldException("Expected '$c' at position $i")
            i++
        }

        fun skipSp() {
            while (i < s.length && s[i] == ' ') i++
        }

        fun skipOws() {
            while (i < s.length && (s[i] == ' ' || s[i] == '\t')) i++
        }

        fun key(): String {
            val c = peek()
            if (!(c == '*' || c in 'a'..'z')) throw StructuredFieldException("A key must start with a lower-case letter or '*' at position $i")
            val start = i
            while (i < s.length && s[i] in KEY_CHARS) i++
            return s.substring(start, i)
        }

        fun itemOrInnerList(): SfMember = if (peek() == '(') innerList() else item()

        fun innerList(): SfInnerList {
            expect('(')
            val items = mutableListOf<SfItem>()
            while (i < s.length) {
                skipSp()
                if (peek() == ')') {
                    i++
                    return SfInnerList(items, parameters())
                }
                items.add(item())
                val c = peek()
                if (c != ' ' && c != ')') throw StructuredFieldException("Expected ' ' or ')' in an inner list at position $i")
            }
            throw StructuredFieldException("Unterminated inner list")
        }

        fun item(): SfItem = SfItem(bareItem(), parameters())

        fun parameters(): Map<String, SfBareItem> {
            val params = LinkedHashMap<String, SfBareItem>()
            while (peek() == ';') {
                i++
                skipSp()
                val key = key()
                var value: SfBareItem = SfBoolean(true)
                if (peek() == '=') {
                    i++
                    value = bareItem()
                }
                params[key] = value
            }
            return params
        }

        fun bareItem(): SfBareItem {
            val c = peek()
            return when {
                c == '-' || c in '0'..'9' -> number()
                c == '"' -> string()
                c == '*' || c in 'a'..'z' || c in 'A'..'Z' -> token()
                c == ':' -> bytes()
                c == '?' -> boolean()
                c == '@' -> date()
                c == '%' -> displayString()
                else -> throw StructuredFieldException("Unexpected character '$c' at position $i")
            }
        }

        fun number(): SfBareItem {
            val start = i
            val negative = peek() == '-'
            if (negative) i++
            if (peek() !in '0'..'9') throw StructuredFieldException("Expected a digit at position $i")
            val intStart = i
            while (i < s.length && s[i] in '0'..'9') i++
            val intPart = s.substring(intStart, i)
            if (peek() != '.') {
                if (intPart.length > 15) throw StructuredFieldException("Integer too long at position $start")
                val v = intPart.toLong()
                return SfInteger(if (negative) -v else v)
            }
            if (intPart.length > 12) throw StructuredFieldException("Decimal too long at position $start")
            i++
            val fracStart = i
            while (i < s.length && s[i] in '0'..'9') i++
            val frac = s.substring(fracStart, i)
            if (frac.isEmpty() || frac.length > 3) throw StructuredFieldException("A decimal needs 1 to 3 fractional digits at position $start")
            val v = BigDecimal("$intPart.$frac")
            return SfDecimal(if (negative) v.negate() else v)
        }

        fun string(): SfString {
            expect('"')
            val out = StringBuilder()
            while (i < s.length) {
                val c = s[i++]
                when {
                    c == '\\' -> {
                        val next = peek()
                        if (next != '"' && next != '\\') throw StructuredFieldException("Invalid escape in a string")
                        out.append(next)
                        i++
                    }
                    c == '"' -> return SfString(out.toString())
                    c.code < 0x20 || c.code > 0x7e -> throw StructuredFieldException("Invalid character in a string")
                    else -> out.append(c)
                }
            }
            throw StructuredFieldException("Unterminated string")
        }

        fun token(): SfToken {
            val start = i
            i++
            while (i < s.length && (s[i] in TCHAR || s[i] == ':' || s[i] == '/')) i++
            return SfToken(s.substring(start, i))
        }

        fun bytes(): SfBytes {
            expect(':')
            val start = i
            while (i < s.length && s[i] in BASE64) i++
            val b64 = s.substring(start, i)
            expect(':')
            if (b64.length % 4 != 0) throw StructuredFieldException("Invalid base64 in a byte sequence")
            return try {
                SfBytes(Base64.getDecoder().decode(b64))
            } catch (_: IllegalArgumentException) {
                throw StructuredFieldException("Invalid base64 in a byte sequence")
            }
        }

        fun boolean(): SfBoolean {
            expect('?')
            val c = peek()
            if (c != '0' && c != '1') throw StructuredFieldException("Expected ?0 or ?1 at position $i")
            i++
            return SfBoolean(c == '1')
        }

        fun date(): SfDate {
            expect('@')
            val v = number() as? SfInteger ?: throw StructuredFieldException("A date must be an integer")
            return SfDate(v.value)
        }

        fun displayString(): SfDisplayString {
            expect('%')
            expect('"')
            val out = java.io.ByteArrayOutputStream()
            while (i < s.length) {
                val c = s[i++]
                when {
                    c == '%' -> {
                        val hex = s.substring(i, minOf(i + 2, s.length))
                        if (hex.length != 2 || !hex.all { it in '0'..'9' || it in 'a'..'f' }) {
                            throw StructuredFieldException("Invalid percent-encoding in a display string")
                        }
                        out.write(hex.toInt(16))
                        i += 2
                    }
                    c == '"' -> {
                        val text = com.ebremer.lws.kotlin.internal.JsonAccess.utf8(out.toByteArray())
                            ?: throw StructuredFieldException("A display string is not valid UTF-8")
                        return SfDisplayString(text)
                    }
                    c.code < 0x20 || c.code > 0x7e -> throw StructuredFieldException("Invalid character in a display string")
                    else -> out.write(c.code)
                }
            }
            throw StructuredFieldException("Unterminated display string")
        }
    }

    /** Serializes a dictionary. */
    public fun serializeDictionary(dictionary: Map<String, SfMember>): String =
        dictionary.entries.joinToString(", ") { (key, member) ->
            val k = serializeKey(key)
            if (member is SfItem && member.value == SfBoolean(true)) k + serializeParams(member.params) else k + "=" + serializeMember(member)
        }

    /** Serializes a list. */
    public fun serializeList(list: List<SfMember>): String = list.joinToString(", ") { serializeMember(it) }

    /** Serializes an item or inner list (a dictionary member's value). */
    public fun serializeMember(member: SfMember): String = when (member) {
        is SfInnerList -> serializeInnerList(member)
        is SfItem -> serializeItem(member)
    }

    /** Serializes an item with its parameters. */
    public fun serializeItem(item: SfItem): String = serializeBareItem(item.value) + serializeParams(item.params)

    /** Serializes an inner list canonically: `("a" "b");created=1;keyid="x"`. */
    public fun serializeInnerList(list: SfInnerList): String =
        list.items.joinToString(" ", "(", ")") { serializeItem(it) } + serializeParams(list.params)

    /** Serializes parameters: `;name=value`, with `;name` for true. */
    public fun serializeParams(params: Map<String, SfBareItem>): String {
        val s = StringBuilder()
        for ((key, value) in params) {
            s.append(';').append(serializeKey(key))
            if (value != SfBoolean(true)) s.append('=').append(serializeBareItem(value))
        }
        return s.toString()
    }

    /** Serializes a bare item. */
    public fun serializeBareItem(value: SfBareItem): String = when (value) {
        is SfBoolean -> if (value.value) "?1" else "?0"
        is SfInteger -> {
            if (value.value > 999_999_999_999_999 || value.value < -999_999_999_999_999) throw StructuredFieldException("Integer out of range")
            value.value.toString()
        }
        is SfDecimal -> serializeDecimal(value.value)
        is SfString -> {
            if (value.value.any { it.code < 0x20 || it.code > 0x7e }) throw StructuredFieldException("A string may hold printable ASCII only")
            "\"" + value.value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
        }
        is SfToken -> {
            if (!TOKEN.matches(value.value)) throw StructuredFieldException("Invalid token: ${value.value}")
            value.value
        }
        is SfBytes -> ":" + Base64.getEncoder().encodeToString(value.bytes) + ":"
        is SfDate -> "@" + value.seconds
        is SfDisplayString -> {
            val out = StringBuilder("%\"")
            for (b in value.value.toByteArray(Charsets.UTF_8)) {
                val o = b.toInt() and 0xff
                if (o == '%'.code || o == '"'.code || o < 0x20 || o > 0x7e) out.append('%').append("%02x".format(o)) else out.append(o.toChar())
            }
            out.append('"').toString()
        }
    }

    private fun serializeDecimal(value: BigDecimal): String {
        val rounded = value.setScale(3, RoundingMode.HALF_EVEN)
        if (rounded.abs() >= MAX_DECIMAL) throw StructuredFieldException("Decimal out of range")
        var s = rounded.toPlainString().trimEnd('0')
        if (s.endsWith(".")) s += "0"
        return if (s == "-0.0") "0.0" else s
    }

    private fun serializeKey(key: String): String {
        if (!KEY.matches(key)) throw StructuredFieldException("Invalid key: $key")
        return key
    }
}
