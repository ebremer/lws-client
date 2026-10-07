// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin.http

import com.ebremer.lws.kotlin.LinkRelation
import com.ebremer.lws.kotlin.internal.Urls
import java.net.URI

/**
 * A web link (RFC 8288): a target, one relation type and the target attributes.
 *
 * @property href the target, an absolute URI where it came from a response
 * @property rel one relation type (registered names lower-cased, extension relations kept as they are)
 * @property params target attributes; names are lower-cased, the first of a name wins
 */
public class Link(public val href: URI, rel: String, params: Map<String, String> = emptyMap()) {
    public val rel: String = LinkHeader.normalizeRel(rel)
    public val params: Map<String, String> = LinkedHashMap<String, String>().also { p ->
        for ((k, v) in params) p.putIfAbsent(k.lowercase(), v)
    }

    /** The `type` attribute (the target's media type hint), or null. */
    public val type: String? get() = params["type"]

    /** The `anchor` attribute, or null. */
    public val anchor: String? get() = params["anchor"]

    /** The `title`, decoded from `title*` (RFC 8187) when that is present, or null. */
    public val title: String?
        get() = params["title*"]?.let(LinkHeader::decodeExtValue) ?: params["title"]

    /** An attribute by name (case-insensitive), or null. */
    public fun param(name: String): String? = params[name.lowercase()]

    /** A copy with one more attribute. */
    public fun withParam(name: String, value: String): Link = Link(href, rel, params + (name.lowercase() to value))

    /** Whether the relation type matches (registered names case-insensitively, extension relations exactly). */
    public fun hasRel(rel: String): Boolean = this.rel == LinkHeader.normalizeRel(rel)

    /** Whether the target is an absolute URI. */
    public val isAbsolute: Boolean get() = href.isAbsolute

    override fun equals(other: Any?): Boolean =
        other is Link && other.href == href && other.rel == rel && other.params == params

    override fun hashCode(): Int = 31 * (31 * href.hashCode() + rel.hashCode()) + params.hashCode()

    /** The link as a `Link` header value: `<href>; rel="rel"; name="value"`. */
    override fun toString(): String = LinkHeader.format(this)

    public companion object {
        /** A `rel="type"` link to a type IRI, as sent when creating a resource. */
        public fun typeLink(typeIri: URI): Link = Link(typeIri, LinkRelation.TYPE)

        /** The first link with a relation type, or null. */
        public fun first(links: Iterable<Link>, rel: String): Link? = links.firstOrNull { it.hasRel(rel) }

        /** The links with a relation type. */
        public fun all(links: Iterable<Link>, rel: String): List<Link> = links.filter { it.hasRel(rel) }
    }
}

/** Parsing and formatting of `Link` header fields (RFC 8288). */
public object LinkHeader {
    private const val TOKEN = "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private val EXT_VALUE = Regex("^([A-Za-z0-9!#$%&+\\-^_`{}~]+)'([A-Za-z0-9\\-]*)'(.*)$", RegexOption.DOT_MATCHES_ALL)

    /**
     * Parses `Link` field values: several field lines, each possibly holding several link-values. Targets are
     * resolved against [base], the URL the response came from; a link without `rel`, or whose target does not
     * resolve to a URI, is skipped. A `rel` with several relation types gives one link per type.
     */
    public fun parse(fieldValues: Iterable<String>, base: URI? = null): List<Link> {
        val out = mutableListOf<Link>()
        for (v in fieldValues) parseLine(v, base?.toString(), out)
        return out
    }

    /** Parses one `Link` field value. */
    public fun parse(fieldValue: String, base: URI? = null): List<Link> = parse(listOf(fieldValue), base)

    private fun parseLine(s: String, base: String?, out: MutableList<Link>) {
        val n = s.length
        var i = 0
        while (i < n) {
            while (i < n && (isWs(s[i]) || s[i] == ',')) i++
            if (i >= n) break
            if (s[i] != '<') {
                i = skipToNextLinkValue(s, i)
                continue
            }
            val close = s.indexOf('>', i + 1)
            if (close < 0) break
            val target = s.substring(i + 1, close).trim(' ', '\t')
            i = close + 1
            val params = LinkedHashMap<String, String>()
            var rel: String? = null
            while (true) {
                while (i < n && isWs(s[i])) i++
                if (i >= n || s[i] == ',') break
                if (s[i] != ';') {
                    i = skipToNextLinkValue(s, i)
                    break
                }
                i++
                while (i < n && isWs(s[i])) i++
                val nameStart = i
                while (i < n && s[i] in TOKEN) i++
                val name = s.substring(nameStart, i).lowercase()
                while (i < n && isWs(s[i])) i++
                var value = ""
                if (i < n && s[i] == '=') {
                    i++
                    while (i < n && isWs(s[i])) i++
                    if (i < n && s[i] == '"') {
                        val (v, next) = quoted(s, i)
                        value = v
                        i = next
                    } else {
                        val vs = i
                        while (i < n && s[i] != ';' && s[i] != ',' && !isWs(s[i])) i++
                        value = s.substring(vs, i)
                    }
                }
                if (name.isEmpty()) continue
                if (name == "rel") {
                    if (rel == null) rel = value
                } else {
                    params.putIfAbsent(name, value)
                }
            }
            val href = Urls.resolve(target, base)?.let(Urls::toUri) ?: continue
            if (rel == null) continue
            for (r in rel.split(' ', '\t').filter { it.isNotEmpty() }) out.add(Link(href, r, params))
        }
    }

    /** Reads a quoted string starting at [start] (the opening quote): the unescaped value and the index after it. */
    internal fun quoted(s: String, start: Int): Pair<String, Int> {
        val n = s.length
        val v = StringBuilder()
        var i = start + 1
        while (i < n && s[i] != '"') {
            if (s[i] == '\\' && i + 1 < n) {
                v.append(s[i + 1])
                i += 2
            } else {
                v.append(s[i])
                i++
            }
        }
        return v.toString() to if (i < n) i + 1 else i
    }

    private fun skipToNextLinkValue(s: String, start: Int): Int {
        var quoted = false
        var angle = false
        var i = start
        while (i < s.length) {
            val c = s[i]
            when {
                quoted -> if (c == '\\') i++ else if (c == '"') quoted = false
                angle -> if (c == '>') angle = false
                c == '"' -> quoted = true
                c == '<' -> angle = true
                c == ',' -> return i + 1
            }
            i++
        }
        return i
    }

    internal fun isWs(c: Char): Boolean = c == ' ' || c == '\t' || c == '\r' || c == '\n'

    /** Lower-cases a registered relation name; extension relation URIs (with a `:`) are kept as they are. */
    public fun normalizeRel(rel: String): String = if (':' in rel) rel else rel.lowercase()

    /** Formats a link as a `Link` header value: `<href>; rel="rel"; name="value"`. */
    public fun format(link: Link): String = format(link.href.toString(), link.rel, link.params)

    /** Formats a target, relation and attributes as a `Link` header value. */
    public fun format(href: String, rel: String, params: Map<String, String> = emptyMap()): String {
        val s = StringBuilder("<").append(href).append(">; rel=").append(quote(rel))
        for ((k, v) in params) {
            s.append("; ").append(k)
            if (v.isNotEmpty()) s.append('=').append(quote(v))
        }
        return s.toString()
    }

    /** Formats several links as one `Link` header value. */
    public fun formatAll(links: Iterable<Link>): String = links.joinToString(", ") { format(it) }

    private fun quote(v: String): String = "\"" + v.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

    /** Decodes an RFC 8187 ext-value (`UTF-8''n%C3%A4me`), or returns null when it is not one. */
    public fun decodeExtValue(value: String): String? {
        val m = EXT_VALUE.matchEntire(value) ?: return null
        val charset = m.groupValues[1].lowercase()
        val encoded = m.groupValues[3]
        val bytes = java.io.ByteArrayOutputStream()
        var i = 0
        while (i < encoded.length) {
            val c = encoded[i]
            if (c == '%') {
                val hex = encoded.substring(i + 1, minOf(i + 3, encoded.length))
                if (hex.length != 2 || !hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) return null
                bytes.write(hex.toInt(16))
                i += 3
            } else {
                if (c.code > 0x7f) return null
                bytes.write(c.code)
                i++
            }
        }
        val raw = bytes.toByteArray()
        return when (charset) {
            "utf-8" -> {
                val decoder = Charsets.UTF_8.newDecoder()
                try {
                    decoder.decode(java.nio.ByteBuffer.wrap(raw)).toString()
                } catch (_: java.nio.charset.CharacterCodingException) {
                    null
                }
            }
            "iso-8859-1" -> String(raw, Charsets.ISO_8859_1)
            else -> null
        }
    }
}
