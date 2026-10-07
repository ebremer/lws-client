// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.internal.JsonAccess
import com.ebremer.lws.kotlin.internal.Urls
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * A type search filter (`application/lws-query+json`), in conjunctive normal form: each key (`type`, or an indexed
 * relation) holds AND groups, each an OR group of IRIs.
 *
 * ```kotlin
 * val query = TypeQuery()
 *     .anyOf("https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person") // one OR group
 *     .allOf(ResourceType.DATA_RESOURCE)                                     // and this type
 * client.searchAll(service, query).collect { println(it.id) }
 * ```
 *
 * IRIs are validated as they are added (absolute, no spaces); the empty query matches everything. A query is not
 * thread-safe while it is being built.
 */
public class TypeQuery {
    private val filters = LinkedHashMap<String, MutableList<List<String>>>()

    /**
     * Adds each IRI as its own AND group on `type`.
     *
     * @throws IllegalArgumentException for an IRI that is not absolute
     */
    public fun allOf(vararg iris: String): TypeQuery = allOfKey(TYPE_KEY, iris.asList())

    /**
     * Adds one OR group of IRIs on `type`.
     *
     * @throws IllegalArgumentException for an IRI that is not absolute, or no IRI
     */
    public fun anyOf(vararg iris: String): TypeQuery = anyOfKey(TYPE_KEY, iris.asList())

    /**
     * The clause for an indexed descriptive relation (same grammar, under the relation's key).
     *
     * @throws IllegalArgumentException for an empty key or one starting with `@`
     */
    public fun relation(relation: String): Relation {
        require(relation.isNotEmpty() && !relation.startsWith("@")) { "Invalid filter key: $relation" }
        return Relation(this, relation)
    }

    /** The filters of a [TypeQuery] on one relation: `query.relation("describedby").anyOf(…)`. */
    public class Relation internal constructor(private val query: TypeQuery, public val key: String) {
        /** Adds each IRI as its own AND group; returns the query. */
        public fun allOf(vararg iris: String): TypeQuery = query.allOfKey(key, iris.asList())

        /** Adds one OR group; returns the query. */
        public fun anyOf(vararg iris: String): TypeQuery = query.anyOfKey(key, iris.asList())
    }

    private fun allOfKey(key: String, iris: List<String>): TypeQuery = addGroups(key, iris.map { listOf(validate(it)) })

    private fun anyOfKey(key: String, iris: List<String>): TypeQuery {
        require(iris.isNotEmpty()) { "An OR group must not be empty" }
        return addGroups(key, listOf(iris.map(::validate)))
    }

    private fun addGroups(key: String, groups: List<List<String>>): TypeQuery {
        val list = filters.getOrPut(key) { mutableListOf() }
        for (g in groups) if (g !in list) list.add(g)
        return this
    }

    /** Whether the query has no filter (and matches everything). */
    public val isEmpty: Boolean get() = filters.isEmpty()

    /** The query document (a one-IRI group as a plain string). */
    public fun toJson(): JsonObject = JsonObject(
        filters.mapValues { (_, groups) ->
            JsonArray(groups.map { g -> if (g.size == 1) JsonPrimitive(g[0]) else JsonArray(g.map(::JsonPrimitive)) })
        },
    )

    /** The serialized query. */
    public fun encode(): String = JsonAccess.encode(toJson())

    /** A copy of this query. */
    public fun copy(): TypeQuery = TypeQuery().also { q -> for ((k, v) in filters) q.filters[k] = v.toMutableList() }

    override fun equals(other: Any?): Boolean = other is TypeQuery && other.filters == filters

    override fun hashCode(): Int = filters.hashCode()

    override fun toString(): String = encode()

    public companion object {
        public const val MEDIA_TYPE: String = MediaType.LWS_QUERY_JSON
        public const val TYPE_KEY: String = "type"

        private val FORBIDDEN = Regex("[\\s<>\"{}|\\\\^`]")

        private fun validate(iri: String): String {
            require(isAbsoluteIri(iri)) { "Not an absolute IRI: $iri" }
            return iri
        }

        /** Whether a value is an absolute IRI: a scheme and something after it, no spaces or `<>"{}|\^``. */
        public fun isAbsoluteIri(iri: String): Boolean {
            if (!Urls.hasScheme(iri)) return false
            val rest = iri.substringAfter(':')
            return rest.isNotEmpty() && !FORBIDDEN.containsMatchIn(rest)
        }

        /**
         * Rebuilds a query from its JSON: each key holds a list of groups, a group an IRI (AND) or a list of IRIs
         * (OR).
         *
         * @throws IllegalArgumentException when it is not a valid query document
         */
        public fun fromJson(json: JsonElement): TypeQuery {
            require(json is JsonObject) { "A type query must be a JSON object" }
            val q = TypeQuery()
            for ((key, groups) in json) {
                require(groups is JsonArray) { "Query member '$key' must be a list of groups" }
                val clause = q.relation(key)
                for (g in groups) {
                    when {
                        g is JsonPrimitive && g.isString -> clause.allOf(g.content)
                        g is JsonArray && g.all { it is JsonPrimitive && it.isString } ->
                            clause.anyOf(*g.map { (it as JsonPrimitive).content }.toTypedArray())
                        else -> throw IllegalArgumentException("A group of query member '$key' must be an IRI or a list of IRIs")
                    }
                }
            }
            return q
        }

        /**
         * Rebuilds a query from its JSON text.
         *
         * @throws IllegalArgumentException when it is not a valid query document
         */
        public fun fromJson(json: String): TypeQuery = fromJson(
            try {
                JsonAccess.decode(json.toByteArray(Charsets.UTF_8))
            } catch (e: SerializationException) {
                throw IllegalArgumentException("A type query is not valid JSON: ${e.message}", e)
            },
        )
    }
}
