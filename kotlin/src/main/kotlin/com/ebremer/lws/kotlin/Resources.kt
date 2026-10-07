// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.http.Headers
import com.ebremer.lws.kotlin.http.Link
import com.ebremer.lws.kotlin.http.LinkHeader
import com.ebremer.lws.kotlin.internal.Dates
import com.ebremer.lws.kotlin.internal.HeaderLists
import com.ebremer.lws.kotlin.internal.JsonAccess
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.serializer
import java.net.URI
import java.time.Instant

/**
 * A resource's metadata: the parsed headers of a response.
 *
 * @property url the URL that answered (after redirects)
 * @property status the status code
 * @property headers the response headers
 */
public class ResourceMetadata(public val url: URI, public val status: Int, public val headers: Headers) {
    /** The ETag verbatim, quotes and `W/` included: send it back as is in `If-Match`. */
    public val etag: String? = headers["etag"]

    /** The `Last-Modified` header as received (see [lastModifiedTime]). */
    public val lastModified: String? = headers["last-modified"]

    public val contentType: String? = headers["content-type"]

    public val contentLength: Long? = headers["content-length"]?.takeIf { s -> s.isNotEmpty() && s.all { it in '0'..'9' } }?.toLongOrNull()

    /** Every link of the `Link` headers, one per relation type, targets resolved. */
    public val links: List<Link> = LinkHeader.parse(headers.all("link"), url)

    /** The linkset resource (`rel="linkset"`). */
    public val linkset: URI? = Link.first(links, LinkRelation.LINKSET)?.href

    /** The parent container (`rel="up"`). */
    public val parent: URI? = Link.first(links, LinkRelation.UP)?.href

    /** The storage (`rel="https://www.w3.org/ns/lws#storage"`). */
    public val storage: URI? = Link.first(links, LinkRelation.STORAGE)?.href

    /** The targets of the `rel="type"` links. */
    public val types: List<String> = Link.all(links, LinkRelation.TYPE).map { it.href.toString() }

    /** The methods of `Allow`. */
    public val allow: List<String> = HeaderLists.split(headers.all("allow"))

    /** The patch formats of `Accept-Patch`. */
    public val acceptPatch: List<String> = HeaderLists.split(headers.all("accept-patch"))

    /** `Last-Modified` as an instant, or null when absent or not an HTTP date. */
    public val lastModifiedTime: Instant? get() = Dates.parseHttpDate(lastModified)

    public val isContainer: Boolean get() = hasType(ResourceType.CONTAINER)

    public val isDataResource: Boolean get() = hasType(ResourceType.DATA_RESOURCE)

    /** Whether a `rel="type"` link names the type (short terms, `lws:` and full IRIs are equal). */
    public fun hasType(type: String): Boolean = Vocabulary.hasType(types, type)

    /** The first link with a relation type, or null. */
    public fun link(rel: String): Link? = Link.first(links, rel)

    /** The links with a relation type. */
    public fun links(rel: String): List<Link> = Link.all(links, rel)

    /** The first value of a response header, or null. */
    public fun header(name: String): String? = headers[name]

    override fun toString(): String = "$status $url"
}

/**
 * A resource as read: its metadata and content. A conditional read answered `304 Not Modified` is a result too,
 * whose [notModified] is true and whose body is empty.
 *
 * @property metadata the response's metadata
 * @property notModified whether a conditional read found the resource unchanged
 */
public class Resource(public val metadata: ResourceMetadata, body: ByteArray = ByteArray(0), public val notModified: Boolean = false) {
    private val content = body

    public val url: URI get() = metadata.url
    public val status: Int get() = metadata.status
    public val etag: String? get() = metadata.etag
    public val contentType: String? get() = metadata.contentType

    /** The `Content-Range` of a `206 Partial Content`. */
    public val contentRange: String? get() = metadata.header("content-range")

    /** A copy of the content bytes. */
    public val bytes: ByteArray get() = content.copyOf()

    /** The length of the content, in bytes. */
    public val size: Int get() = content.size

    /** The content as text, decoded by the charset of its content type (UTF-8 by default). */
    public fun text(): String = HeaderLists.decode(content, contentType)

    /**
     * The content parsed as JSON.
     *
     * @throws ProtocolException when it is not JSON
     */
    public fun json(): JsonElement = JsonAccess.parse(content, "The content of $url")

    /**
     * The content decoded with a kotlinx.serialization deserializer.
     *
     * @throws ProtocolException when it is not JSON
     * @throws kotlinx.serialization.SerializationException when it does not fit the type
     */
    public fun <T> decode(deserializer: DeserializationStrategy<T>, json: Json = Json): T = json.decodeFromJsonElement(deserializer, json())

    /** The content decoded as a `@Serializable` type: `resource.decode<Todo>()`. */
    public inline fun <reified T> decode(json: Json = Json): T = decode(json.serializersModule.serializer<T>(), json)

    override fun toString(): String = "$url ($status, ${content.size} bytes)"
}

/**
 * The result of a create: the new resource's URL and the metadata of the `201` response.
 *
 * @property location the new resource (absolute)
 */
public class CreateResult(public val location: URI, public val metadata: ResourceMetadata, body: ByteArray = ByteArray(0)) {
    private val content = body

    public val etag: String? get() = metadata.etag
    public val linkset: URI? get() = metadata.linkset

    /** A copy of the response body, if the server sent one. */
    public val body: ByteArray get() = content.copyOf()

    override fun toString(): String = location.toString()
}

/** The result of a PUT or PATCH: the status (200 or 204), the new ETag and the response metadata. */
public class UpdateResult(public val status: Int, public val metadata: ResourceMetadata, body: ByteArray = ByteArray(0)) {
    private val content = body

    public val etag: String? get() = metadata.etag

    /** A copy of the response body, if the server sent one. */
    public val body: ByteArray get() = content.copyOf()

    override fun toString(): String = "${metadata.url} ($status)"
}

/** A byte range to read (`Range: bytes=…`): `ByteRange.of(0, 1023)`, `ByteRange.from(1024)`, `ByteRange.last(500)`. */
public class ByteRange private constructor(public val start: Long?, public val end: Long?, public val suffixLength: Long?) {
    /** The `Range` header value. */
    public val headerValue: String
        get() = if (suffixLength != null) "bytes=-$suffixLength" else "bytes=$start-" + (end?.toString() ?: "")

    override fun equals(other: Any?): Boolean = other is ByteRange && other.headerValue == headerValue

    override fun hashCode(): Int = headerValue.hashCode()

    override fun toString(): String = headerValue

    public companion object {
        /**
         * The bytes from [start] to [end], both included (`end` null: to the end).
         *
         * @throws IllegalArgumentException for negative offsets or `end < start`
         */
        public fun of(start: Long, end: Long? = null): ByteRange {
            require(start >= 0 && (end == null || end >= start)) { "Invalid byte range $start-" + (end ?: "") }
            return ByteRange(start, end, null)
        }

        /** The bytes from [start] to the end. */
        public fun from(start: Long): ByteRange = of(start)

        /**
         * The last [length] bytes.
         *
         * @throws IllegalArgumentException when `length` is not positive
         */
        public fun last(length: Long): ByteRange {
            require(length > 0) { "Invalid suffix length $length" }
            return ByteRange(null, null, length)
        }
    }
}
