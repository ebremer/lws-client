// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.internal.Dates
import com.ebremer.lws.kotlin.internal.JsonAccess
import com.ebremer.lws.kotlin.internal.Urls
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.URI
import java.time.Instant

/**
 * A member of a container listing (or a type search result).
 *
 * @property id the resource (absolute)
 * @property types the `type` values as received
 * @property format the media type (present for data resources)
 * @property size the size in bytes
 * @property modifiedRaw the `modified` value as received
 * @property raw the item object
 */
public class ContainedResource(
    public val id: URI,
    public val types: List<String> = emptyList(),
    public val format: String? = null,
    public val size: Long? = null,
    public val modifiedRaw: String? = null,
    public val raw: JsonObject = JsonObject(emptyMap()),
) {
    /** When [modifiedRaw] is a date-time (an unparseable value is null here, not an error). */
    public val modified: Instant? = Dates.parseRfc3339(modifiedRaw)

    public val isContainer: Boolean get() = hasType(ResourceType.CONTAINER)

    public val isDataResource: Boolean get() = hasType(ResourceType.DATA_RESOURCE)

    public fun hasType(type: String): Boolean = Vocabulary.hasType(types, type)

    override fun toString(): String = id.toString()

    public companion object {
        /**
         * Parses an item object; its `id` is resolved against [base].
         *
         * @throws ProtocolException without a usable `id`
         */
        public fun parse(json: JsonElement, base: URI?): ContainedResource {
            val o = JsonAccess.obj(json, "A contained resource description")
            val idText = JsonAccess.str(o, "id") ?: throw ProtocolException("A contained resource description has no id")
            val id = Urls.resolve(idText, base?.toString())?.let(Urls::toUri)
                ?: throw ProtocolException("Invalid contained resource id: $idText")
            return ContainedResource(id, JsonAccess.types(o), JsonAccess.str(o, "format"), JsonAccess.long(o, "size"), JsonAccess.str(o, "modified"), o)
        }
    }
}

/**
 * One page of a container listing (`application/lws+json`), or of type search results. Pagination links come from
 * the `Link` headers; every URL is absolute.
 *
 * @property id the container (or the page URL when the body has no `id`)
 * @property totalItems the number of members (may be approximate)
 * @property raw the page object
 */
public class ContainerPage(
    public val id: URI,
    public val types: List<String>,
    public val totalItems: Long?,
    public val items: List<ContainedResource>,
    public val metadata: ResourceMetadata,
    public val raw: JsonObject = JsonObject(emptyMap()),
) {
    public val first: URI? = metadata.link(LinkRelation.FIRST)?.href
    public val next: URI? = metadata.link(LinkRelation.NEXT)?.href
    public val prev: URI? = metadata.link(LinkRelation.PREV)?.href
    public val last: URI? = metadata.link(LinkRelation.LAST)?.href
    public val etag: String? get() = metadata.etag

    /** Whether the body or the `rel="type"` links say this is a container. */
    public val isContainer: Boolean get() = hasType(ResourceType.CONTAINER) || metadata.isContainer

    public fun hasType(type: String): Boolean = Vocabulary.hasType(types, type)

    override fun toString(): String = "$id (${items.size} items)"

    public companion object {
        /**
         * Parses a page body; ids resolve against the response URL.
         *
         * @throws ProtocolException when it is not a page object
         */
        public fun parse(json: JsonElement, metadata: ResourceMetadata): ContainerPage {
            val o = JsonAccess.obj(json, "The container representation")
            val base = metadata.url
            val idText = JsonAccess.str(o, "id")
            val id = if (idText == null) base else Urls.resolveUri(idText, base) ?: throw ProtocolException("Invalid container id: $idText")
            val items = when (val raw = o["items"]) {
                null, JsonNull -> emptyList()
                is JsonArray -> raw.map { ContainedResource.parse(it, base) }
                else -> throw ProtocolException("The container's items are not an array")
            }
            return ContainerPage(id, JsonAccess.types(o), JsonAccess.long(o, "totalItems"), items, metadata, o)
        }
    }
}

/** One page of a type index: the type IRIs in use, with pagination links. */
public class TypeIndexPage(
    public val totalItems: Long?,
    public val types: List<String>,
    public val metadata: ResourceMetadata,
    public val raw: JsonObject = JsonObject(emptyMap()),
) {
    public val first: URI? = metadata.link(LinkRelation.FIRST)?.href
    public val next: URI? = metadata.link(LinkRelation.NEXT)?.href
    public val prev: URI? = metadata.link(LinkRelation.PREV)?.href
    public val last: URI? = metadata.link(LinkRelation.LAST)?.href

    override fun toString(): String = "${metadata.url} (${types.size} types)"

    public companion object {
        /**
         * Parses a type index page: `items` holds IRIs, or objects with an `id`.
         *
         * @throws ProtocolException when it is not a page object
         */
        public fun parse(json: JsonElement, metadata: ResourceMetadata): TypeIndexPage {
            val o = JsonAccess.obj(json, "The type index")
            val types = when (val items = o["items"]) {
                null, JsonNull -> emptyList()
                is JsonArray -> items.mapNotNull { item ->
                    when (item) {
                        is JsonPrimitive -> item.takeIf { it.isString }?.content
                        is JsonObject -> JsonAccess.str(item, "id")
                        else -> null
                    }
                }
                else -> throw ProtocolException("The type index's items are not an array")
            }
            return TypeIndexPage(JsonAccess.long(o, "totalItems"), types, metadata, o)
        }
    }
}
