// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin.http

import com.ebremer.lws.kotlin.MediaType
import com.ebremer.lws.kotlin.internal.HeaderLists
import com.ebremer.lws.kotlin.internal.JsonAccess
import kotlinx.serialization.json.JsonObject

/**
 * One authentication challenge of a `WWW-Authenticate` field.
 *
 * @property scheme the authentication scheme (compare it with [isScheme], case-insensitively)
 * @property params the parameters; names are lower-cased, the first of a name wins
 * @property token68 the token68 form, for challenges that have one instead of parameters
 */
public class AuthChallenge(public val scheme: String, params: Map<String, String> = emptyMap(), public val token68: String? = null) {
    public val params: Map<String, String> = LinkedHashMap<String, String>().also { p ->
        for ((k, v) in params) p.putIfAbsent(k.lowercase(), v)
    }

    /** Whether the scheme is [scheme], ignoring case. */
    public fun isScheme(scheme: String): Boolean = this.scheme.equals(scheme, ignoreCase = true)

    /** A parameter by name (case-insensitive), or null. */
    public fun param(name: String): String? = params[name.lowercase()]

    /** The LWS `as_uri` parameter: the authorization server to obtain a token from. */
    public val asUri: String? get() = params["as_uri"]

    /** The `realm` parameter: the protection space the token is for. */
    public val realm: String? get() = params["realm"]

    /** The `error` parameter (`invalid_token`, …). */
    public val error: String? get() = params["error"]

    /** The `error_description` parameter. */
    public val errorDescription: String? get() = params["error_description"]

    override fun equals(other: Any?): Boolean =
        other is AuthChallenge && other.scheme == scheme && other.params == params && other.token68 == token68

    override fun hashCode(): Int = 31 * (31 * scheme.hashCode() + params.hashCode()) + token68.hashCode()

    override fun toString(): String = "AuthChallenge($scheme, $params" + (token68?.let { ", $it" } ?: "") + ")"
}

/**
 * Parses `WWW-Authenticate` fields (RFC 9110 section 11.6.1), including several challenges in one field value
 * (`Bearer as_uri="…", realm="…", DPoP algs="ES256"`).
 */
public object WwwAuthenticate {
    private const val TOKEN = "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val TOKEN68 = "-._~+/0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

    /** Parses several field lines. */
    public fun parse(fieldValues: Iterable<String>): List<AuthChallenge> {
        val out = mutableListOf<AuthChallenge>()
        for (v in fieldValues) Parser(v).challenges(out)
        return out
    }

    /** Parses one field value. */
    public fun parse(fieldValue: String): List<AuthChallenge> = parse(listOf(fieldValue))

    private class Parser(val s: String) {
        var i = 0
        val n = s.length

        fun challenges(out: MutableList<AuthChallenge>) {
            while (true) {
                while (i < n && (LinkHeader.isWs(s[i]) || s[i] == ',')) i++
                if (i >= n) return
                val scheme = token()
                if (scheme.isEmpty()) {
                    i++
                    continue
                }
                skipWs()
                val afterScheme = i
                var j = i
                while (j < n && s[j] in TOKEN68) j++
                if (j > i) {
                    while (j < n && s[j] == '=') j++
                    val t68 = s.substring(i, j)
                    var k = j
                    while (k < n && LinkHeader.isWs(s[k])) k++
                    if (k >= n || s[k] == ',') {
                        out.add(AuthChallenge(scheme, emptyMap(), t68))
                        i = k
                        continue
                    }
                }
                i = afterScheme
                out.add(AuthChallenge(scheme, params()))
            }
        }

        fun params(): Map<String, String> {
            val params = LinkedHashMap<String, String>()
            while (true) {
                skipWs()
                val save = i
                val name = token()
                if (name.isEmpty()) {
                    i = save
                    return params
                }
                skipWs()
                if (i >= n || s[i] != '=') {
                    i = save
                    return params
                }
                i++
                skipWs()
                val value = if (i < n && s[i] == '"') {
                    val (v, next) = LinkHeader.quoted(s, i)
                    i = next
                    v
                } else {
                    token()
                }
                params.putIfAbsent(name.lowercase(), value)
                skipWs()
                if (i >= n || s[i] != ',') return params
                i++
                skipWs()
                while (i < n && s[i] == ',') {
                    i++
                    skipWs()
                }
                val look = i
                val next = token()
                skipWs()
                val isParam = next.isNotEmpty() && i < n && s[i] == '='
                i = look
                if (!isParam) return params
            }
        }

        fun token(): String {
            val start = i
            while (i < n && s[i] in TOKEN) i++
            return s.substring(start, i)
        }

        fun skipWs() {
            while (i < n && LinkHeader.isWs(s[i])) i++
        }
    }
}

/**
 * RFC 9457 problem details from an error response, extension members preserved.
 *
 * @property raw the problem object
 */
public class ProblemDetails(public val raw: JsonObject) {
    public val type: String? = JsonAccess.str(raw, "type")
    public val title: String? = JsonAccess.str(raw, "title")
    public val status: Int? = JsonAccess.long(raw, "status")?.takeIf { it in Int.MIN_VALUE..Int.MAX_VALUE }?.toInt()
    public val detail: String? = JsonAccess.str(raw, "detail")
    public val instance: String? = JsonAccess.str(raw, "instance")

    /** The members other than the five standard ones. */
    public val extensions: JsonObject = JsonObject(raw.filterKeys { it !in STANDARD })

    override fun toString(): String = JsonAccess.encode(raw)

    public companion object {
        private val STANDARD = setOf("type", "title", "status", "detail", "instance")

        /**
         * Parses an error response body: a JSON object with a problem media type, or a `+json` one with at least
         * a `type`, `title` or `detail`. Returns null otherwise.
         */
        public fun parse(contentType: String?, body: ByteArray): ProblemDetails? {
            if (!HeaderLists.isJson(contentType)) return null
            val members = try {
                JsonAccess.decode(body) as? JsonObject
            } catch (_: Exception) {
                null
            } ?: return null
            val problemType = HeaderLists.essence(contentType) == MediaType.PROBLEM_JSON
            if (!problemType && "type" !in members && "title" !in members && "detail" !in members) return null
            return ProblemDetails(members)
        }
    }
}

/**
 * The identity hint of a create, sent as the `Slug` header (RFC 5023 section 9.7, as in the Solid Protocol).
 * Non-ASCII, control and `%` characters are percent-encoded as UTF-8.
 */
public object Slug {
    public const val HEADER: String = "Slug"

    public fun encode(slug: String): String {
        val out = StringBuilder()
        for (b in slug.toByteArray(Charsets.UTF_8)) {
            val c = b.toInt() and 0xff
            if (c in 0x20 until 0x7f && c != 0x25) out.append(c.toChar()) else out.append('%').append("%02X".format(c))
        }
        return out.toString()
    }
}
