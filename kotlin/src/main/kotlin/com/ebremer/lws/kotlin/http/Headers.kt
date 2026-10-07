// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin.http

/**
 * An immutable list of HTTP header fields, with names compared case-insensitively. A name may occur several
 * times (`Link`, `WWW-Authenticate`); [get] gives the first value and [all] every value, in order.
 *
 * ```kotlin
 * val h = Headers.of("Accept" to "text/plain", "Link" to "<a>; rel=\"x\"")
 * h["accept"]            // "text/plain"
 * h.with("Accept", null) // without Accept
 * ```
 */
public class Headers private constructor(private val fields: List<Pair<String, String>>) : Iterable<Pair<String, String>> {

    /** The number of field lines. */
    public val size: Int get() = fields.size

    /** The first value of a field, or null. */
    public operator fun get(name: String): String? = fields.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second

    /** Every value of a field, in order. */
    public fun all(name: String): List<String> = fields.filter { it.first.equals(name, ignoreCase = true) }.map { it.second }

    /** Whether a field is present. */
    public operator fun contains(name: String): Boolean = fields.any { it.first.equals(name, ignoreCase = true) }

    /** The distinct field names, as first seen. */
    public val names: List<String>
        get() = fields.map { it.first }.distinctBy { it.lowercase() }

    /** A copy with the field set to a value, replacing any present; a null value removes it. */
    public fun with(name: String, value: String?): Headers = with(name, listOfNotNull(value))

    /** A copy with the field set to values, replacing any present; no values remove it. */
    public fun with(name: String, values: List<String>): Headers =
        Headers(fields.filterNot { it.first.equals(name, ignoreCase = true) } + values.map { field(name, it) })

    /** A copy with one more value of a field. */
    public fun withAdded(name: String, value: String): Headers = Headers(fields + field(name, value))

    /** A copy without a field. */
    public fun without(name: String): Headers = with(name, emptyList())

    /** A copy in which every field of [other] replaces the fields of that name. */
    public fun merge(other: Headers): Headers = other.names.fold(this) { h, name -> h.with(name, other.all(name)) }

    /** The fields as a map of lower-cased name to values. */
    public fun toMap(): Map<String, List<String>> {
        val out = LinkedHashMap<String, MutableList<String>>()
        for ((n, v) in fields) out.getOrPut(n.lowercase()) { mutableListOf() }.add(v)
        return out
    }

    /** The fields as `name to value` pairs, in order. */
    override fun iterator(): Iterator<Pair<String, String>> = fields.iterator()

    override fun equals(other: Any?): Boolean = other is Headers && other.fields == fields

    override fun hashCode(): Int = fields.hashCode()

    override fun toString(): String = fields.joinToString(", ", "Headers(", ")") { "${it.first}: ${it.second}" }

    public companion object {
        private val TOKEN = Regex("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")

        /** No fields. */
        public val EMPTY: Headers = Headers(emptyList())

        /**
         * Headers from `name to value` pairs.
         *
         * @throws IllegalArgumentException for a name that is not a token or a value with a line break
         */
        public fun of(vararg fields: Pair<String, String>): Headers = of(fields.asList())

        /** Headers from `name to value` pairs. */
        public fun of(fields: Iterable<Pair<String, String>>): Headers = Headers(fields.map { field(it.first, it.second) })

        /** Headers from a map of name to value. */
        public fun of(fields: Map<String, String>): Headers = of(fields.entries.map { it.key to it.value })

        /** Headers from a map of name to values, as HTTP stacks report them. */
        public fun ofLists(fields: Map<String, List<String>>): Headers =
            of(fields.entries.flatMap { e -> e.value.map { e.key to it } })

        /** Whether a string is an HTTP token (a valid field name or method). */
        internal fun isToken(s: String): Boolean = TOKEN.matches(s)

        private fun field(name: String, value: String): Pair<String, String> {
            require(isToken(name)) { "Invalid header name: $name" }
            require(value.none { it == '\r' || it == '\n' || it == '\u0000' }) { "The value of header $name contains a line break" }
            return name to value.trim(' ', '\t')
        }
    }
}
