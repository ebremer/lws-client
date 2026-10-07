// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin.internal

import java.net.URI
import java.net.URISyntaxException

/**
 * RFC 3986 URI references, on strings: `java.net.URI` follows RFC 2396, whose resolution differs (`?q`, empty
 * references) and whose parser gives up on hosts such as `my_host`. Results become [URI]s at the edges.
 */
internal object Urls {
    private val PATTERN = Regex("""^(?:([A-Za-z][A-Za-z0-9+.\-]*):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$""", RegexOption.DOT_MATCHES_ALL)
    private val SCHEME = Regex("""^[A-Za-z][A-Za-z0-9+.\-]*:""")
    private val CONTROL_OR_SPACE = Regex("[\\x00-\\x20\\x7f]")

    class Parts(val scheme: String?, val authority: String?, val path: String, val query: String?, val fragment: String?)

    /** Splits a URI reference into its five components (RFC 3986 appendix B); absent components are null. */
    fun parse(reference: String): Parts {
        val m = PATTERN.find(reference) ?: return Parts(null, null, reference, null, null)
        fun g(i: Int) = m.groups[i]?.value
        return Parts(g(1), g(2), g(3) ?: "", g(4), g(5))
    }

    /** Whether a reference starts with a scheme. */
    fun hasScheme(reference: String): Boolean = SCHEME.containsMatchIn(reference)

    /**
     * Resolves a URI reference against a base (RFC 3986 section 5.2), or returns null when it is malformed (spaces
     * or control characters) or relative without an absolute base.
     */
    fun resolve(reference: String, base: String?): String? {
        val r = reference.trim(' ', '\t')
        if (CONTROL_OR_SPACE.containsMatchIn(r)) return null
        val ref = parse(r)
        if (ref.scheme != null) {
            return compose(ref.scheme, ref.authority, removeDotSegments(ref.path), ref.query, ref.fragment)
        }
        if (base == null || !hasScheme(base)) return null
        val b = parse(base)
        if (ref.authority != null) {
            return compose(b.scheme, ref.authority, removeDotSegments(ref.path), ref.query, ref.fragment)
        }
        val path: String
        val query: String?
        if (ref.path.isEmpty()) {
            path = b.path
            query = ref.query ?: b.query
        } else {
            path = when {
                ref.path.startsWith("/") -> removeDotSegments(ref.path)
                b.authority != null && b.path.isEmpty() -> removeDotSegments("/" + ref.path)
                else -> {
                    val i = b.path.lastIndexOf('/')
                    removeDotSegments((if (i < 0) "" else b.path.substring(0, i + 1)) + ref.path)
                }
            }
            query = ref.query
        }
        return compose(b.scheme, b.authority, path, query, ref.fragment)
    }

    /** Resolves a reference against a base URL and makes it a [URI]; null when either step fails. */
    fun resolveUri(reference: String, base: URI): URI? = resolve(reference, base.toString())?.let(::toUri)

    /** A string as a [URI], or null when `java.net.URI` rejects it. */
    fun toUri(s: String): URI? = try {
        URI(s)
    } catch (_: URISyntaxException) {
        null
    }

    /** RFC 3986 section 5.2.4. */
    fun removeDotSegments(path: String): String {
        if ('.' !in path) return path
        var input = path
        val out = StringBuilder()
        fun dropLast() {
            val i = out.lastIndexOf("/")
            out.setLength(if (i < 0) 0 else i)
        }
        while (input.isNotEmpty()) {
            when {
                input.startsWith("../") -> input = input.substring(3)
                input.startsWith("./") -> input = input.substring(2)
                input.startsWith("/./") -> input = input.substring(2)
                input == "/." -> input = "/"
                input.startsWith("/../") -> {
                    input = input.substring(3)
                    dropLast()
                }
                input == "/.." -> {
                    input = "/"
                    dropLast()
                }
                input == "." || input == ".." -> input = ""
                else -> {
                    val start = if (input.startsWith("/")) 1 else 0
                    val next = input.indexOf('/', start)
                    out.append(if (next < 0) input else input.substring(0, next))
                    input = if (next < 0) "" else input.substring(next)
                }
            }
        }
        return out.toString()
    }

    private fun compose(scheme: String?, authority: String?, path: String, query: String?, fragment: String?): String {
        val s = StringBuilder()
        if (scheme != null) s.append(scheme).append(':')
        if (authority != null) s.append("//").append(authority)
        s.append(path)
        if (query != null) s.append('?').append(query)
        if (fragment != null) s.append('#').append(fragment)
        return s.toString()
    }

    /** Whether a string is an absolute http(s) URL with a host. */
    fun isHttp(url: String): Boolean {
        val c = parse(url)
        val scheme = c.scheme?.lowercase()
        return (scheme == "http" || scheme == "https") && c.authority != null && host(url).isNotEmpty() &&
            !CONTROL_OR_SPACE.containsMatchIn(url)
    }

    /** Requires an absolute http(s) URL as a request target. */
    fun requireHttp(url: URI, what: String): URI {
        require(isHttp(url.toString())) { "$what is not an absolute http(s) URL: $url" }
        return url
    }

    /** The scheme, lower-cased ("" when there is none). */
    fun scheme(url: String): String = parse(url).scheme?.lowercase() ?: ""

    /** The host, lower-cased, without IPv6 brackets ("" when there is none). */
    fun host(url: String): String = splitAuthority(parse(url).authority ?: "").first

    /** The explicit port, or null. */
    fun port(url: String): Int? = splitAuthority(parse(url).authority ?: "").second

    /** The explicit port or the scheme's default (80, 443). */
    fun effectivePort(url: String): Int? = port(url) ?: defaultPort(scheme(url))

    private fun defaultPort(scheme: String): Int? = when (scheme) {
        "http" -> 80
        "https" -> 443
        else -> null
    }

    /** The lower-cased host and the explicit port. */
    private fun splitAuthority(authority: String): Pair<String, Int?> {
        val at = authority.lastIndexOf('@')
        val hostPort = if (at < 0) authority else authority.substring(at + 1)
        val host: String
        val rest: String
        if (hostPort.startsWith("[")) {
            val close = hostPort.indexOf(']')
            if (close < 0) return hostPort.lowercase() to null
            host = hostPort.substring(1, close)
            rest = hostPort.substring(close + 1)
        } else {
            val colon = hostPort.lastIndexOf(':')
            host = if (colon < 0) hostPort else hostPort.substring(0, colon)
            rest = if (colon < 0) "" else hostPort.substring(colon)
        }
        val digits = rest.removePrefix(":")
        val port = if (rest.startsWith(":") && digits.isNotEmpty() && digits.all { it in '0'..'9' }) digits.toIntOrNull() else null
        return host.lowercase() to port
    }

    /** Whether two URLs share scheme, host and effective port. */
    fun sameOrigin(a: String, b: String): Boolean =
        scheme(a) == scheme(b) && host(a) == host(b) && effectivePort(a) == effectivePort(b)

    /** The path as it appears in the URL (percent-encoded), `/` when empty. */
    fun path(url: String): String = parse(url).path.ifEmpty { "/" }

    /** The query including its `?`, or the empty string. */
    fun query(url: String): String = parse(url).query?.let { "?$it" } ?: ""

    /**
     * Whether [url] is logically contained in [realm]: same origin, and the path equals the realm path or lies
     * beneath it (the realm path is treated as a directory).
     */
    fun contains(realm: String, url: String): Boolean {
        if (!sameOrigin(realm, url)) return false
        val rp = parse(realm).path
        val up = path(url)
        if (rp.isEmpty() || rp == "/" || up == rp) return true
        val dir = if (rp.endsWith("/")) rp else "$rp/"
        return up.startsWith(dir) || "$up/" == dir
    }

    /** Loopback hosts, which may use plain HTTP for authorization servers. */
    fun isLoopback(url: String): Boolean {
        val h = host(url)
        return h == "localhost" || h == "127.0.0.1" || h == "::1" || h.endsWith(".localhost")
    }

    /** The string without its fragment. */
    fun withoutFragment(s: String): String = s.substringBefore('#')

    /** The URL without its fragment. */
    fun withoutFragment(u: URI): URI = if (u.rawFragment == null) u else toUri(withoutFragment(u.toString())) ?: u

    /** The fragment (without `#`), or null. */
    fun fragment(s: String): String? = if ('#' in s) s.substringAfter('#') else null

    /** A URL as compared for identity: scheme and host lower-cased, the default port dropped, no fragment. */
    fun canonical(url: String): String {
        val c = parse(url)
        if (c.scheme == null || c.authority == null) return withoutFragment(url)
        val scheme = c.scheme.lowercase()
        val (host, port) = splitAuthority(c.authority)
        val at = c.authority.lastIndexOf('@')
        val userInfo = if (at < 0) "" else c.authority.substring(0, at + 1)
        var authority = userInfo + if (':' in host) "[$host]" else host
        if (port != null && port != defaultPort(scheme)) authority += ":$port"
        return scheme + "://" + authority + c.path.ifEmpty { "/" } + (c.query?.let { "?$it" } ?: "")
    }

    /** Compares two URI strings, ignoring one trailing slash on each. */
    fun equalsIgnoringTrailingSlash(a: String, b: String): Boolean = a.removeSuffix("/") == b.removeSuffix("/")
}
