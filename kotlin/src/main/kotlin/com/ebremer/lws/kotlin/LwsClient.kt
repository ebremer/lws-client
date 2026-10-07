// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.access.AccessGrant
import com.ebremer.lws.kotlin.access.AccessRequest
import com.ebremer.lws.kotlin.auth.AuthRequest
import com.ebremer.lws.kotlin.auth.AuthResponse
import com.ebremer.lws.kotlin.auth.Authenticator
import com.ebremer.lws.kotlin.http.Headers
import com.ebremer.lws.kotlin.http.HttpRequest
import com.ebremer.lws.kotlin.http.HttpResponse
import com.ebremer.lws.kotlin.http.HttpTransport
import com.ebremer.lws.kotlin.http.JdkHttpTransport
import com.ebremer.lws.kotlin.http.Link
import com.ebremer.lws.kotlin.http.LinkHeader
import com.ebremer.lws.kotlin.http.Slug
import com.ebremer.lws.kotlin.internal.Dates
import com.ebremer.lws.kotlin.internal.HeaderLists
import com.ebremer.lws.kotlin.internal.JsonAccess
import com.ebremer.lws.kotlin.internal.Urls
import com.ebremer.lws.kotlin.json.JsonPatch
import com.ebremer.lws.kotlin.notify.Subscription
import com.ebremer.lws.kotlin.notify.WebhookSubscriptionRequest
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.URI
import java.time.Instant
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Client for the W3C Linked Web Storage (LWS) Protocol 1.0.
 *
 * ```kotlin
 * val me = SelfSignedCredentials.didKey(SigningKey.generateP256())
 * val client = LwsClient(authenticator = TokenExchangeAuthenticator(me))
 * val storage = client.discoverStorage(URI("https://storage.example/root/"))
 * val note = client.createText(storage.storageRoot(), "Hello", slug = "hello.txt")
 * client.listContainer(storage.storageRoot()).collect { println(it.id) }
 * ```
 *
 * Operations are `suspend` functions, cancelled with the coroutine that calls them; listings are cold [Flow]s that
 * fetch page after page as they are collected. Every operation takes, besides its own options, `headers` (extra
 * request headers) and `timeout` (overriding the client's). Errors are [LwsException]s: [NotFoundException],
 * [PreconditionFailedException], [ConflictException], … for error statuses, [AuthenticationException],
 * [ProtocolException] and [TransportException]. Arguments that are not absolute http(s) URLs raise
 * [IllegalArgumentException] before any request is sent.
 *
 * Redirects are followed by the client itself (at most [maxRedirects]), authorizing every hop afresh for its own
 * URL, so that an access token never leaves its realm. `POST` is never sent twice, except for the single retry after
 * a `401` that the authenticator handled (when nothing was created). Instances are immutable and safe to share.
 *
 * @param authenticator how requests are authenticated (null: anonymous)
 * @param transport the HTTP engine; it must not follow redirects
 * @param userAgent the `User-Agent` (null: the transport's own)
 * @param defaultHeaders headers sent with every request
 * @param timeout the time limit of each request (null: the transport's)
 * @param maxRedirects how many redirects a request may follow
 */
public class LwsClient(
    public val authenticator: Authenticator? = null,
    public val transport: HttpTransport = JdkHttpTransport(),
    public val userAgent: String? = DEFAULT_USER_AGENT,
    defaultHeaders: Map<String, String> = emptyMap(),
    public val timeout: Duration? = 30.seconds,
    public val maxRedirects: Int = 10,
) {
    private val defaultHeaderMap: Map<String, String> = defaultHeaders.toMap()

    /** The headers sent with every request. */
    public val defaultHeaders: Headers = Headers.of(defaultHeaderMap)

    init {
        require(maxRedirects >= 0) { "maxRedirects must not be negative" }
    }

    /** A client with another authenticator, sharing this client's transport and options. */
    public fun withAuthenticator(authenticator: Authenticator?): LwsClient =
        LwsClient(authenticator, transport, userAgent, defaultHeaderMap, timeout, maxRedirects)

    // ------------------------------------------------------------------------------------------------
    // Discovery

    /**
     * Finds the storage a resource belongs to (its `rel="https://www.w3.org/ns/lws#storage"` link, from a `HEAD`, or
     * a `GET` when `HEAD` is answered 405 or 501) and retrieves the storage description.
     *
     * @throws ProtocolException when the response has no storage link or the description is invalid
     */
    public suspend fun discoverStorage(resourceUrl: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): StorageDescription {
        val url = Urls.requireHttp(resourceUrl, "resourceUrl")
        var r = call("HEAD", url, null, Headers.EMPTY, headers, timeout)
        if (r.status == 405 || r.status == 501) r = call("GET", url, null, Headers.EMPTY, headers, timeout)
        val storage = metadata(r).storage
        // A 401 SHOULD carry the storage link too, so that anonymous discovery works.
        if (storage == null || !(r.status / 100 == 2 || r.status == 401)) {
            check(r)
            throw ProtocolException("The response for $url has no storage link (rel=\"${LinkRelation.STORAGE}\")")
        }
        return getStorageDescription(storage, headers, timeout)
    }

    /**
     * Retrieves and parses a storage description (`application/lws+cid`).
     *
     * @throws ProtocolException when the document is not a storage description
     */
    public suspend fun getStorageDescription(storageUrl: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): StorageDescription {
        val url = Urls.requireHttp(storageUrl, "storageUrl")
        val r = call("GET", url, null, Headers.of("Accept" to ACCEPT_DESCRIPTION), headers, timeout)
        check(r)
        val ct = r.headers["content-type"]
        if (ct != null && !HeaderLists.isJson(ct) && HeaderLists.essence(ct) != MediaType.LWS_CID) {
            throw ProtocolException("The storage description has the unexpected media type $ct")
        }
        return StorageDescription.parse(JsonAccess.parse(r.body, "The storage description"), r.url)
    }

    // ------------------------------------------------------------------------------------------------
    // Reading

    /** Retrieves a resource's metadata (`HEAD`). */
    public suspend fun head(url: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): ResourceMetadata {
        val r = call("HEAD", Urls.requireHttp(url, "url"), null, Headers.EMPTY, headers, timeout)
        check(r)
        return metadata(r)
    }

    /**
     * Reads a resource (`GET`). A conditional read answered `304` returns a result whose [Resource.notModified] is
     * true instead of throwing; `206` is a normal result.
     *
     * @param accept the `Accept` header
     * @param range the bytes to read
     * @param ifNoneMatch an ETag: read only when it changed
     * @param ifModifiedSince read only when modified since
     * @param prefer the `Prefer` header
     */
    public suspend fun read(
        url: URI,
        accept: String? = null,
        range: ByteRange? = null,
        ifNoneMatch: String? = null,
        ifModifiedSince: Instant? = null,
        prefer: String? = null,
        headers: Map<String, String> = emptyMap(),
        timeout: Duration? = null,
    ): Resource {
        val h = Headers.EMPTY.with("Accept", accept).with("Range", range?.headerValue).with("If-None-Match", ifNoneMatch)
            .with("If-Modified-Since", ifModifiedSince?.let(Dates::formatHttpDate)).with("Prefer", prefer)
        return resource(call("GET", Urls.requireHttp(url, "url"), null, h, headers, timeout))
    }

    /**
     * Reads one page of a container listing (`Accept: application/lws+json`); also takes opaque page URLs.
     *
     * @throws ProtocolException when the response is not an LWS container representation
     */
    public suspend fun readContainer(url: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): ContainerPage {
        val r = call("GET", Urls.requireHttp(url, "url"), null, Headers.of("Accept" to MediaType.LWS_JSON), headers, timeout)
        val page = page(r)
        if (!page.isContainer) throw ProtocolException("${r.url} is not a container (type [${page.types.joinToString(", ")}])")
        return page
    }

    /** Every member of a container, fetched lazily page by page (following `rel="next"`) as the flow is collected. */
    public fun listContainer(url: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): Flow<ContainedResource> {
        Urls.requireHttp(url, "url")
        Headers.of(headers)
        val page: suspend (URI) -> Pair<List<ContainedResource>, URI?> = { u -> readContainer(u, headers, timeout).let { it.items to it.next } }
        return paged(url, { page(url) }, page)
    }

    // ------------------------------------------------------------------------------------------------
    // Creating

    /**
     * Creates a data resource in a container (`POST`); the server assigns its URL ([CreateResult.location]).
     *
     * @param body the content bytes
     * @param slug the identity hint (sent as `Slug`)
     * @param types extra resource types (`Link: <type>; rel="type"`)
     * @param links extra links
     * @throws ProtocolException when the response has no `Location`
     */
    public suspend fun create(
        containerUrl: URI,
        body: ByteArray,
        contentType: String,
        slug: String? = null,
        types: List<URI> = emptyList(),
        links: List<Link> = emptyList(),
        headers: Map<String, String> = emptyMap(),
        timeout: Duration? = null,
    ): CreateResult {
        val u = Urls.requireHttp(containerUrl, "containerUrl")
        val h = createHeaders(slug, types, links, null).with("Content-Type", contentType)
        return created(call("POST", u, body, h, headers, timeout))
    }

    /** Creates a text data resource (UTF-8). */
    public suspend fun createText(
        containerUrl: URI,
        text: String,
        contentType: String = "text/plain",
        slug: String? = null,
        types: List<URI> = emptyList(),
        links: List<Link> = emptyList(),
        headers: Map<String, String> = emptyMap(),
        timeout: Duration? = null,
    ): CreateResult = create(containerUrl, text.toByteArray(Charsets.UTF_8), contentType, slug, types, links, headers, timeout)

    /** Creates a JSON data resource (`application/json` by default). */
    public suspend fun createJson(
        containerUrl: URI,
        value: JsonElement,
        slug: String? = null,
        types: List<URI> = emptyList(),
        links: List<Link> = emptyList(),
        contentType: String = MediaType.JSON,
        headers: Map<String, String> = emptyMap(),
        timeout: Duration? = null,
    ): CreateResult = create(containerUrl, JsonAccess.encode(value).toByteArray(Charsets.UTF_8), contentType, slug, types, links, headers, timeout)

    /** Creates a sub-container (`POST` with `Link: <https://www.w3.org/ns/lws#Container>; rel="type"`, empty body). */
    public suspend fun createContainer(
        parentUrl: URI,
        slug: String? = null,
        types: List<URI> = emptyList(),
        links: List<Link> = emptyList(),
        headers: Map<String, String> = emptyMap(),
        timeout: Duration? = null,
    ): CreateResult {
        val u = Urls.requireHttp(parentUrl, "parentUrl")
        return created(call("POST", u, ByteArray(0), createHeaders(slug, types, links, ResourceType.CONTAINER), headers, timeout))
    }

    // ------------------------------------------------------------------------------------------------
    // Updating and deleting

    /**
     * Replaces a resource's content (`PUT`); pass [ifMatch] to avoid lost updates.
     *
     * @param ifMatch the ETag the resource must still have
     * @param ifNoneMatch `*` to create only when absent
     * @param links links to send (with [setLinkset], the resource's new links)
     * @param setLinkset send `Prefer: set-linkset`
     */
    public suspend fun update(
        url: URI,
        body: ByteArray,
        contentType: String,
        ifMatch: String? = null,
        ifNoneMatch: String? = null,
        links: List<Link> = emptyList(),
        setLinkset: Boolean = false,
        headers: Map<String, String> = emptyMap(),
        timeout: Duration? = null,
    ): UpdateResult = updateCore("PUT", url, body, contentType, ifMatch, ifNoneMatch, links, setLinkset, headers, timeout)

    /** Replaces a resource's content with text (UTF-8). */
    public suspend fun updateText(
        url: URI,
        text: String,
        contentType: String = "text/plain",
        ifMatch: String? = null,
        ifNoneMatch: String? = null,
        links: List<Link> = emptyList(),
        setLinkset: Boolean = false,
        headers: Map<String, String> = emptyMap(),
        timeout: Duration? = null,
    ): UpdateResult = update(url, text.toByteArray(Charsets.UTF_8), contentType, ifMatch, ifNoneMatch, links, setLinkset, headers, timeout)

    /** Replaces a resource's content with JSON (`application/json` by default). */
    public suspend fun updateJson(
        url: URI,
        value: JsonElement,
        contentType: String = MediaType.JSON,
        ifMatch: String? = null,
        ifNoneMatch: String? = null,
        links: List<Link> = emptyList(),
        setLinkset: Boolean = false,
        headers: Map<String, String> = emptyMap(),
        timeout: Duration? = null,
    ): UpdateResult = update(url, JsonAccess.encode(value).toByteArray(Charsets.UTF_8), contentType, ifMatch, ifNoneMatch, links, setLinkset, headers, timeout)

    /** Patches a resource with a [JsonPatch] (`PATCH`, `application/json-patch+json`, the LWS baseline). */
    public suspend fun patch(
        url: URI,
        patch: JsonPatch,
        ifMatch: String? = null,
        links: List<Link> = emptyList(),
        setLinkset: Boolean = false,
        headers: Map<String, String> = emptyMap(),
        timeout: Duration? = null,
    ): UpdateResult = updateCore("PATCH", url, patch.encode().toByteArray(Charsets.UTF_8), MediaType.JSON_PATCH, ifMatch, null, links, setLinkset, headers, timeout)

    /** Patches a resource with bytes in a format the server advertises in `Accept-Patch`. */
    public suspend fun patch(
        url: URI,
        patch: ByteArray,
        contentType: String,
        ifMatch: String? = null,
        links: List<Link> = emptyList(),
        setLinkset: Boolean = false,
        headers: Map<String, String> = emptyMap(),
        timeout: Duration? = null,
    ): UpdateResult = updateCore("PATCH", url, patch, contentType, ifMatch, null, links, setLinkset, headers, timeout)

    private suspend fun updateCore(
        method: String,
        url: URI,
        body: ByteArray,
        contentType: String,
        ifMatch: String?,
        ifNoneMatch: String?,
        links: List<Link>,
        setLinkset: Boolean,
        headers: Map<String, String>,
        timeout: Duration?,
    ): UpdateResult {
        val u = Urls.requireHttp(url, "url")
        var h = Headers.of("Content-Type" to contentType).with("If-Match", ifMatch).with("If-None-Match", ifNoneMatch)
        for (l in links) h = h.withAdded("Link", LinkHeader.format(l))
        if (setLinkset) h = h.with("Prefer", Prefer.SET_LINKSET)
        val r = call(method, u, body, h, headers, timeout)
        check(r)
        return UpdateResult(r.status, metadata(r), r.body)
    }

    /** Deletes a resource; a non-empty container needs [recursive] (else [ConflictException]). */
    public suspend fun delete(
        url: URI,
        ifMatch: String? = null,
        recursive: Boolean = false,
        headers: Map<String, String> = emptyMap(),
        timeout: Duration? = null,
    ) {
        val h = Headers.EMPTY.with("If-Match", ifMatch).with("Depth", if (recursive) "infinity" else null)
        check(call("DELETE", Urls.requireHttp(url, "url"), null, h, headers, timeout))
    }

    // ------------------------------------------------------------------------------------------------
    // Metadata (linksets)

    /**
     * The linkset resource of a resource (`HEAD`, `rel="linkset"`).
     *
     * @throws ProtocolException when the resource has no linkset link
     */
    public suspend fun linksetUrl(resourceUrl: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): URI {
        val m = head(resourceUrl, headers, timeout)
        return m.linkset ?: throw ProtocolException("${m.url} has no linkset link")
    }

    /** Discovers and reads a resource's linkset (`application/linkset+json`). */
    public suspend fun readLinkset(resourceUrl: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): LinksetDocument =
        readLinksetResource(linksetUrl(resourceUrl, headers, timeout), headers, timeout)

    /** Reads a linkset resource at a known URL. */
    public suspend fun readLinksetResource(linksetUrl: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): LinksetDocument {
        val r = call("GET", Urls.requireHttp(linksetUrl, "linksetUrl"), null, Headers.of("Accept" to ACCEPT_LINKSET), headers, timeout)
        check(r)
        return LinksetDocument(r.url, Linkset.parse(JsonAccess.parse(r.body, "The linkset")), metadata(r))
    }

    /** Replaces a linkset (`PUT`; only when the server allows it, else [MethodNotAllowedException]). */
    public suspend fun updateLinkset(
        linksetUrl: URI,
        linkset: Linkset,
        ifMatch: String? = null,
        headers: Map<String, String> = emptyMap(),
        timeout: Duration? = null,
    ): UpdateResult = updateCore("PUT", linksetUrl, linkset.encode().toByteArray(Charsets.UTF_8), MediaType.LINKSET_JSON, ifMatch, null, emptyList(), false, headers, timeout)

    /** Patches a linkset with JSON Patch; [com.ebremer.lws.kotlin.json.JsonPointer] escapes relation keys that are URIs. */
    public suspend fun patchLinkset(
        linksetUrl: URI,
        patch: JsonPatch,
        ifMatch: String? = null,
        headers: Map<String, String> = emptyMap(),
        timeout: Duration? = null,
    ): UpdateResult = patch(linksetUrl, patch, ifMatch, headers = headers, timeout = timeout)

    // ------------------------------------------------------------------------------------------------
    // Notifications

    /**
     * Creates a webhook subscription at a notification service endpoint.
     *
     * @throws ProtocolException when the response has neither a subscription URL nor a `Location`
     */
    public suspend fun subscribe(
        serviceUrl: URI,
        request: WebhookSubscriptionRequest,
        headers: Map<String, String> = emptyMap(),
        timeout: Duration? = null,
    ): Subscription {
        val u = Urls.requireHttp(serviceUrl, "serviceUrl")
        val r = call("POST", u, JsonAccess.encode(request.toJson()).toByteArray(Charsets.UTF_8), JSON_HEADERS, headers, timeout)
        check(r)
        val location = r.headers["location"]?.let { Urls.resolveUri(it, r.url) }
        if (r.body.isEmpty() || String(r.body, Charsets.UTF_8).isBlank()) {
            location ?: throw ProtocolException("The subscription response has neither a body nor a Location")
            return Subscription.parse(JsonObject(mapOf("type" to JsonPrimitive(SubscriptionType.WEBHOOK))), r.url, location)
        }
        return Subscription.parse(JsonAccess.parse(r.body, "The subscription"), r.url, location)
    }

    /**
     * Creates a webhook subscription at the notification service of a storage description, which must offer
     * `WebhookSubscription`.
     *
     * @throws ProtocolException when the service does not support webhooks
     */
    public suspend fun subscribe(
        service: Service,
        request: WebhookSubscriptionRequest,
        headers: Map<String, String> = emptyMap(),
        timeout: Duration? = null,
    ): Subscription {
        val types = service.subscriptionTypes
        if (types.isNotEmpty() && SubscriptionType.WEBHOOK !in types) {
            throw ProtocolException("The notification service ${service.serviceEndpoint} does not support ${SubscriptionType.WEBHOOK}")
        }
        return subscribe(service.serviceEndpoint, request, headers, timeout)
    }

    /** The subscriber's subscriptions: the container listing of the notification service. */
    public fun listSubscriptions(serviceUrl: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): Flow<ContainedResource> =
        listContainer(serviceUrl, headers, timeout)

    /** Retrieves a subscription's current state. */
    public suspend fun getSubscription(url: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): Subscription {
        val r = call("GET", Urls.requireHttp(url, "url"), null, Headers.of("Accept" to MediaType.LWS_JSON), headers, timeout)
        check(r)
        return Subscription.parse(JsonAccess.parse(r.body, "The subscription"), r.url, r.url)
    }

    /** Cancels a subscription (`DELETE`). */
    public suspend fun unsubscribe(url: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): Unit =
        delete(url, headers = headers, timeout = timeout)

    // ------------------------------------------------------------------------------------------------
    // Access requests and grants

    /** Submits an access request; returns its URL (`Location`). */
    public suspend fun requestAccess(serviceUrl: URI, request: AccessRequest, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): URI =
        postForLocation(serviceUrl, request.toJson(), headers, timeout)

    /** The access requests: the container listing of the service. */
    public fun listAccessRequests(serviceUrl: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): Flow<ContainedResource> =
        listContainer(serviceUrl, headers, timeout)

    /** Retrieves an access request (its [AccessRequest.raw] is the document as sent). */
    public suspend fun getAccessRequest(url: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): AccessRequest =
        AccessRequest.parse(getJson(url, headers, timeout))

    /** Cancels (deletes) an access request. */
    public suspend fun cancelAccessRequest(url: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): Unit =
        delete(url, headers = headers, timeout = timeout)

    /** Creates an access grant (as storage controller); returns its URL (`Location`). */
    public suspend fun grantAccess(serviceUrl: URI, grant: AccessGrant, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): URI =
        postForLocation(serviceUrl, grant.toJson(), headers, timeout)

    /** The access grants: the container listing of the service. */
    public fun listAccessGrants(serviceUrl: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): Flow<ContainedResource> =
        listContainer(serviceUrl, headers, timeout)

    /** Retrieves an access grant (its [AccessGrant.raw] is the document as sent). */
    public suspend fun getAccessGrant(url: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): AccessGrant =
        AccessGrant.parse(getJson(url, headers, timeout))

    /** Revokes (deletes) an access grant. */
    public suspend fun revokeAccessGrant(url: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): Unit =
        delete(url, headers = headers, timeout = timeout)

    // ------------------------------------------------------------------------------------------------
    // Type index and type search

    /** Reads a type index page (the service endpoint, or an opaque page URL). */
    public suspend fun readTypeIndex(url: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): TypeIndexPage {
        val r = call("GET", Urls.requireHttp(url, "url"), null, Headers.of("Accept" to MediaType.LWS_JSON), headers, timeout)
        check(r)
        requireLwsJson(r)
        return TypeIndexPage.parse(JsonAccess.parse(r.body, "The type index"), metadata(r))
    }

    /** Every type IRI of a type index, fetched lazily page by page. */
    public fun listTypes(serviceUrl: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): Flow<String> {
        Urls.requireHttp(serviceUrl, "serviceUrl")
        Headers.of(headers)
        val page: suspend (URI) -> Pair<List<String>, URI?> = { u -> readTypeIndex(u, headers, timeout).let { it.types to it.next } }
        return paged(serviceUrl, { page(serviceUrl) }, page)
    }

    /**
     * Runs a type search (HTTP `QUERY`, RFC 10008, with an `application/lws-query+json` filter) and returns the first
     * page. The page's `id` is the page URL when the body has none.
     */
    public suspend fun searchTypes(serviceUrl: URI, query: TypeQuery, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): ContainerPage {
        val u = Urls.requireHttp(serviceUrl, "serviceUrl")
        val h = Headers.of("Content-Type" to MediaType.LWS_QUERY_JSON, "Accept" to MediaType.LWS_JSON)
        return page(call("QUERY", u, query.encode().toByteArray(Charsets.UTF_8), h, headers, timeout))
    }

    /** Every search result: the first page by `QUERY`, further pages by `GET` of the opaque `next` links. */
    public fun searchAll(serviceUrl: URI, query: TypeQuery, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): Flow<ContainedResource> {
        Urls.requireHttp(serviceUrl, "serviceUrl")
        Headers.of(headers)
        val q = query.copy()
        return paged(
            serviceUrl,
            { searchTypes(serviceUrl, q, headers, timeout).let { it.items to it.next } },
            { u ->
                page(call("GET", Urls.requireHttp(u, "url"), null, Headers.of("Accept" to MediaType.LWS_JSON), headers, timeout)).let { it.items to it.next }
            },
        )
    }

    /** The query formats a search service accepts (`OPTIONS`, `Accept-Query`). */
    public suspend fun acceptedQueryFormats(serviceUrl: URI, headers: Map<String, String> = emptyMap(), timeout: Duration? = null): List<String> {
        val r = call("OPTIONS", Urls.requireHttp(serviceUrl, "serviceUrl"), null, Headers.EMPTY, headers, timeout)
        check(r)
        return HeaderLists.split(r.headers.all("accept-query")).map(HeaderLists::unquote)
    }

    // ------------------------------------------------------------------------------------------------
    // Low-level access

    /**
     * Sends any request through the client's pipeline (authentication, redirects). An error status throws the
     * matching exception; `304` yields a not-modified result.
     */
    public suspend fun request(
        method: String,
        url: URI,
        body: ByteArray? = null,
        contentType: String? = null,
        headers: Map<String, String> = emptyMap(),
        timeout: Duration? = null,
    ): Resource {
        require(Headers.isToken(method)) { "Invalid method: $method" }
        return resource(call(method, Urls.requireHttp(url, "url"), body, Headers.EMPTY.with("Content-Type", contentType), headers, timeout))
    }

    // ------------------------------------------------------------------------------------------------
    // The request pipeline

    /** The final response of a call, with the method and URL of the hop that produced it. */
    private class Answer(val method: String, val url: URI, val status: Int, val headers: Headers, val body: ByteArray)

    /**
     * Sends a request: authenticating, retrying once after a handled 401, following redirects. The response carries
     * the URL of the hop that produced it.
     */
    private suspend fun call(
        method: String,
        url: URI,
        body: ByteArray?,
        headers: Headers,
        callHeaders: Map<String, String>,
        timeout: Duration?,
    ): Answer {
        var m = method
        var u = url
        var b = body
        var h = headers.merge(Headers.of(callHeaders))
        val limit = timeout ?: this.timeout
        var userAuth = "Authorization" in h || "Authorization" in defaultHeaders
        var hops = 0
        while (true) {
            var attempt = prepare(m, u, h, userAuth)
            var response = dispatch(attempt, b, limit)
            if (response.status == 401 && authenticator != null && authenticator.handleChallenge(attempt, AuthResponse(u, 401, response.headers))) {
                attempt = prepare(m, u, h, userAuth)
                response = dispatch(attempt, b, limit)
            }
            val answer = Answer(m, u, response.status, response.headers, response.body)
            val location = response.headers["location"]
            if (response.status !in REDIRECTS || location == null) return answer
            val targetText = Urls.resolve(location, u.toString())
            if (targetText == null || !Urls.isHttp(targetText)) return answer
            val target = Urls.toUri(Urls.withoutFragment(targetText)) ?: return answer
            val safe = m in SAFE_METHODS
            if (response.status == 303 && safe) {
                // See Other: retrieve the result with GET (HEAD stays HEAD), without a body.
                if (m != "HEAD") m = "GET"
                b = null
                for (name in h.names) if (name.lowercase().startsWith("content-")) h = h.without(name)
            } else if (!((safe && (response.status == 301 || response.status == 302)) || response.status == 307 || response.status == 308)) {
                return answer
            }
            if (++hops > maxRedirects) throw ProtocolException("Too many redirects (more than $maxRedirects) at $u")
            // An Authorization header the caller set explicitly survives same-origin redirects only; the
            // authenticator's tokens are evaluated afresh for the new URL.
            if (userAuth && !Urls.sameOrigin(u.toString(), targetText)) userAuth = false
            u = target
        }
    }

    private suspend fun prepare(method: String, url: URI, callHeaders: Headers, keepUserAuthorization: Boolean): AuthRequest {
        var h = defaultHeaders
        if (userAgent != null && "User-Agent" !in h && "User-Agent" !in callHeaders) h = h.with("User-Agent", userAgent)
        h = h.merge(callHeaders)
        if (!keepUserAuthorization) h = h.without("Authorization")
        val request = AuthRequest(method, url, h)
        return authenticator?.authorize(request) ?: request
    }

    private suspend fun dispatch(attempt: AuthRequest, body: ByteArray?, timeout: Duration?): HttpResponse =
        transport.send(HttpRequest(attempt.method, Urls.withoutFragment(attempt.url), attempt.headers, body, timeout))

    // ------------------------------------------------------------------------------------------------
    // Internals of the operations

    private fun check(r: Answer) {
        if (r.status / 100 != 2) throw HttpException.fromResponse(r.status, r.method, r.url, r.headers, r.body)
    }

    private fun metadata(r: Answer): ResourceMetadata = ResourceMetadata(r.url, r.status, r.headers)

    private fun resource(r: Answer): Resource {
        if (r.status == 304) return Resource(metadata(r), ByteArray(0), true)
        check(r)
        return Resource(metadata(r), r.body, false)
    }

    private fun page(r: Answer): ContainerPage {
        check(r)
        requireLwsJson(r)
        return ContainerPage.parse(JsonAccess.parse(r.body, "The container representation"), metadata(r))
    }

    private fun requireLwsJson(r: Answer) {
        val essence = HeaderLists.essence(r.headers["content-type"])
        if (essence != null && essence != MediaType.LWS_JSON && essence != MediaType.LD_JSON && essence != MediaType.JSON) {
            throw ProtocolException("Unexpected media type $essence for an LWS JSON representation at ${r.url}")
        }
    }

    private fun created(r: Answer): CreateResult {
        check(r)
        val location = r.headers["location"] ?: throw ProtocolException("The create response (HTTP ${r.status}) from ${r.url} has no Location header")
        val resolved = Urls.resolveUri(location, r.url) ?: throw ProtocolException("Invalid Location header: $location")
        return CreateResult(resolved, metadata(r), r.body)
    }

    private fun createHeaders(slug: String?, types: List<URI>, links: List<Link>, containerType: String?): Headers {
        var h = Headers.EMPTY
        if (containerType != null) h = h.withAdded("Link", LinkHeader.format(containerType, LinkRelation.TYPE))
        for (t in types) h = h.withAdded("Link", LinkHeader.format(t.toString(), LinkRelation.TYPE))
        for (l in links) h = h.withAdded("Link", LinkHeader.format(l))
        return if (slug == null) h else h.with(Slug.HEADER, Slug.encode(slug))
    }

    private suspend fun postForLocation(serviceUrl: URI, document: JsonObject, headers: Map<String, String>, timeout: Duration?): URI {
        val u = Urls.requireHttp(serviceUrl, "serviceUrl")
        return created(call("POST", u, JsonAccess.encode(document).toByteArray(Charsets.UTF_8), JSON_HEADERS, headers, timeout)).location
    }

    private suspend fun getJson(url: URI, headers: Map<String, String>, timeout: Duration?): JsonElement {
        val r = call("GET", Urls.requireHttp(url, "url"), null, Headers.of("Accept" to MediaType.LWS_JSON), headers, timeout)
        check(r)
        return JsonAccess.parse(r.body, "The response of ${r.url}")
    }

    /** A lazy listing: the elements of the first page, then of each `next` page (each page URL once). */
    private fun <T> paged(first: URI, load: suspend () -> Pair<List<T>, URI?>, fetch: suspend (URI) -> Pair<List<T>, URI?>): Flow<T> = flow {
        val seen = mutableSetOf(first.toString())
        var (elements, next) = load()
        while (true) {
            for (e in elements) emit(e)
            val n = next ?: return@flow
            if (!seen.add(n.toString())) return@flow
            val page = fetch(n)
            elements = page.first
            next = page.second
        }
    }

    override fun toString(): String = "LwsClient(authenticator=$authenticator, userAgent=$userAgent)"

    public companion object {
        public const val VERSION: String = "0.1.0"
        public const val DEFAULT_USER_AGENT: String = "lws-client-kotlin/$VERSION"

        private const val ACCEPT_DESCRIPTION = "${MediaType.LWS_CID}, ${MediaType.LD_JSON};q=0.9, ${MediaType.JSON};q=0.8"
        private const val ACCEPT_LINKSET = "${MediaType.LINKSET_JSON}, ${MediaType.JSON};q=0.5"
        private val REDIRECTS = setOf(301, 302, 303, 307, 308)
        private val SAFE_METHODS = setOf("GET", "HEAD", "OPTIONS", "QUERY")
        private val JSON_HEADERS = Headers.of("Content-Type" to MediaType.LWS_JSON, "Accept" to MediaType.LWS_JSON)
    }
}
