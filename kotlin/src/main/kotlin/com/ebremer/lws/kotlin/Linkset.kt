// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.http.Link
import com.ebremer.lws.kotlin.internal.JsonAccess
import com.ebremer.lws.kotlin.internal.Urls
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.URI

/**
 * A linkset (RFC 9264, `application/linkset+json`): `{"linkset": [{"anchor": "…", "<rel>": [{"href": "…", …}]}]}`.
 * Unknown members round-trip.
 *
 * ```kotlin
 * val doc = client.readLinkset(resource)
 * doc.linkset.add(null, "https://schema.org/author", "https://alice.example/#me")
 * client.updateLinkset(doc.url, doc.linkset, ifMatch = doc.etag)
 * ```
 *
 * A linkset is mutable ([add], [remove]) and not thread-safe while it changes.
 */
public class Linkset(contexts: List<LinkContext> = emptyList()) : Iterable<LinkContext> {
    private val ctx = contexts.toMutableList()

    /** The link contexts, in order. */
    public val contexts: List<LinkContext> get() = ctx.toList()

    /**
     * Every link, flattened, with targets resolved against their anchors (the anchor as an `anchor` parameter,
     * string attributes as parameters).
     */
    public fun links(): List<Link> = ctx.flatMap { c ->
        val anchor = c.anchor?.let { Urls.resolve(it, null) }
        c.relations.flatMap { (rel, targets) ->
            targets.mapNotNull { t ->
                val href = Urls.resolve(t.href, anchor)?.let(Urls::toUri) ?: return@mapNotNull null
                val params = LinkedHashMap<String, String>()
                if (c.anchor != null) params["anchor"] = c.anchor
                for ((k, v) in t.attributes) if (v is JsonPrimitive && v.isString) params[k] = v.content
                Link(href, rel, params)
            }
        }
    }

    /** The targets of a relation type, in every context. */
    public fun targets(rel: String): List<LinkTarget> = ctx.flatMap { it.targets(rel) }

    /** The targets of a relation type in the context of an anchor (null: the context without anchor). */
    public fun targetsOf(anchor: String?, rel: String): List<LinkTarget> = context(anchor)?.targets(rel) ?: emptyList()

    /** The target URLs (as written) of a relation type, in every context. */
    public fun hrefs(rel: String): List<String> = targets(rel).map { it.href }

    /** The target URLs (as written) of a relation type in the context of an anchor. */
    public fun hrefs(rel: String, anchor: String?): List<String> = targetsOf(anchor, rel).map { it.href }

    /** The context of an anchor (null: the context without anchor), or null. */
    public fun context(anchor: String?): LinkContext? = ctx.firstOrNull { it.anchor == anchor }

    /** Adds a link target, creating the context of the anchor when there is none. */
    public fun add(anchor: String?, rel: String, href: String, attributes: Map<String, JsonElement> = emptyMap()): Linkset {
        val target = LinkTarget(href, attributes)
        val c = context(anchor)
        if (c == null) ctx.add(LinkContext(anchor, mapOf(rel to listOf(target)))) else c.addTarget(rel, target)
        return this
    }

    /**
     * Removes the targets of a relation type in the context of an anchor (only those with [href], when given); a
     * relation left without targets is dropped. Returns how many targets were removed.
     */
    public fun remove(anchor: String?, rel: String, href: String? = null): Int = context(anchor)?.removeTargets(rel, href) ?: 0

    /** The document. */
    public fun toJson(): JsonObject = JsonObject(mapOf("linkset" to JsonArray(ctx.map { it.toJson() })))

    /** The serialized document. */
    public fun encode(): String = JsonAccess.encode(toJson())

    /** The number of link targets. */
    public val size: Int get() = ctx.sumOf { c -> c.relations.values.sumOf { it.size } }

    override fun iterator(): Iterator<LinkContext> = contexts.iterator()

    override fun toString(): String = encode()

    public companion object {
        /**
         * Parses a linkset document.
         *
         * @throws ProtocolException when it has no `linkset` array of objects
         */
        public fun parse(json: JsonElement): Linkset {
            val o = JsonAccess.obj(json, "The linkset document")
            val list = o["linkset"] as? JsonArray ?: throw ProtocolException("The linkset document has no 'linkset' array")
            return Linkset(list.map { LinkContext.fromJson(it) ?: throw ProtocolException("A linkset context is not an object") })
        }

        /**
         * Parses a linkset document from its JSON text.
         *
         * @throws ProtocolException when it is not JSON or not a linkset document
         */
        public fun parse(json: String): Linkset = parse(
            try {
                JsonAccess.decode(json.toByteArray(Charsets.UTF_8))
            } catch (e: SerializationException) {
                throw ProtocolException("The linkset is not valid JSON: ${e.message}", e)
            },
        )
    }
}

/**
 * One link context of a linkset: an anchor and its relations (relation type → targets, in order). Members that are
 * neither the anchor nor arrays of targets are kept in [extra], so that the context round-trips.
 */
public class LinkContext(
    public val anchor: String? = null,
    relations: Map<String, List<LinkTarget>> = emptyMap(),
    public val extra: JsonObject = JsonObject(emptyMap()),
) {
    private val rels = LinkedHashMap<String, MutableList<LinkTarget>>().also { m ->
        for ((k, v) in relations) m[k] = v.toMutableList()
    }

    /** The relations, relation type → targets. */
    public val relations: Map<String, List<LinkTarget>> get() = rels.mapValues { it.value.toList() }

    /** The targets of a relation type. */
    public fun targets(rel: String): List<LinkTarget> = rels[rel]?.toList() ?: emptyList()

    internal fun addTarget(rel: String, target: LinkTarget) {
        rels.getOrPut(rel) { mutableListOf() }.add(target)
    }

    internal fun removeTargets(rel: String, href: String?): Int {
        val targets = rels[rel] ?: return 0
        val before = targets.size
        val kept = if (href == null) emptyList() else targets.filter { it.href != href }
        if (kept.isEmpty()) rels.remove(rel) else rels[rel] = kept.toMutableList()
        return before - kept.size
    }

    /** The context object. */
    public fun toJson(): JsonObject {
        val o = LinkedHashMap<String, JsonElement>()
        if (anchor != null) o["anchor"] = JsonPrimitive(anchor)
        for ((rel, targets) in rels) o[rel] = JsonArray(targets.map { it.toJson() })
        o.putAll(extra)
        return JsonObject(o)
    }

    internal companion object {
        fun fromJson(json: JsonElement): LinkContext? {
            val o = json as? JsonObject ?: return null
            var anchor: String? = null
            val relations = LinkedHashMap<String, List<LinkTarget>>()
            val extra = LinkedHashMap<String, JsonElement>()
            for ((key, value) in o) {
                if (key == "anchor" && value is JsonPrimitive && value.isString) {
                    anchor = value.content
                    continue
                }
                if (value is JsonArray) {
                    val targets = value.map(LinkTarget::fromJson)
                    if (targets.all { it != null }) {
                        relations[key] = targets.filterNotNull()
                        continue
                    }
                }
                extra[key] = value
            }
            return LinkContext(anchor, relations, JsonObject(extra))
        }
    }
}

/**
 * A link target of a linkset: `href` (as written) and its target attributes (JSON values: `type`, `title`,
 * `hreflang`, `title*`, …).
 */
public class LinkTarget(public val href: String, attributes: Map<String, JsonElement> = emptyMap()) {
    public val attributes: JsonObject = JsonObject(attributes.filterKeys { it != "href" })

    /** An attribute that is a string, or null. */
    public fun attribute(name: String): String? = JsonAccess.str(attributes, name)

    /** The target object. */
    public fun toJson(): JsonObject = JsonObject(mapOf("href" to JsonPrimitive(href)) + attributes)

    override fun toString(): String = href

    internal companion object {
        fun fromJson(json: JsonElement): LinkTarget? {
            val o = json as? JsonObject ?: return null
            return JsonAccess.str(o, "href")?.let { LinkTarget(it, o) }
        }
    }
}

/**
 * A linkset as read from its linkset resource: the resource URL, the linkset, its ETag and allowed methods.
 *
 * @property url the linkset resource
 */
public class LinksetDocument(public val url: URI, public val linkset: Linkset, public val metadata: ResourceMetadata) {
    public val etag: String? get() = metadata.etag
    public val allow: List<String> get() = metadata.allow
    public val acceptPatch: List<String> get() = metadata.acceptPatch

    /** Whether the linkset resource allows `PUT` (else update it with `PATCH`). */
    public val supportsPut: Boolean get() = allow.any { it.equals("PUT", ignoreCase = true) }
}
