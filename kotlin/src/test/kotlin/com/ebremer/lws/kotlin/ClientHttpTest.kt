// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.FakeTransport.Companion.response
import com.ebremer.lws.kotlin.access.AccessGrant
import com.ebremer.lws.kotlin.access.AccessPolicy
import com.ebremer.lws.kotlin.access.AccessRequest
import com.ebremer.lws.kotlin.access.AccessTarget
import com.ebremer.lws.kotlin.http.HttpRequest
import com.ebremer.lws.kotlin.http.HttpResponse
import com.ebremer.lws.kotlin.http.Link
import com.ebremer.lws.kotlin.internal.JsonAccess
import com.ebremer.lws.kotlin.json.JsonPatch
import com.ebremer.lws.kotlin.json.JsonPointer
import com.ebremer.lws.kotlin.json.jsonPatch
import com.ebremer.lws.kotlin.notify.WebhookSubscriptionRequest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.junit.jupiter.api.Test
import java.net.URI
import java.time.Instant
import kotlin.reflect.KClass
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** Every operation against an in-process transport. */
class ClientHttpTest {
    private lateinit var t: FakeTransport

    private fun client(handler: suspend (HttpRequest) -> HttpResponse): LwsClient {
        t = FakeTransport(handler)
        return LwsClient(transport = t)
    }

    private fun s(path: String = ""): URI = URI(S + path)

    @Test
    fun discoverStorageWithHeadAndGetFallback() = runTest {
        val sd = Fixtures.load("responses/storage-description.json")
        for (headStatus in listOf(200, 405)) {
            val client = client { r ->
                if (r.url == s("alice/notes/")) {
                    val status = if (r.method == "HEAD") headStatus else 200
                    if (status == 200) response(r, status, "Link" to "</>; rel=\"https://www.w3.org/ns/lws#storage\"") else response(r, status)
                } else {
                    assertEquals("application/lws+cid, application/ld+json;q=0.9, application/json;q=0.8", r.headers["accept"])
                    response(r, 200, "Content-Type" to "application/lws+cid", body = sd.obj("body"))
                }
            }
            val storage = client.discoverStorage(s("alice/notes/"))
            assertEquals(sd.obj("expected").str("storageRoot"), storage.storageRoot().toString())
            assertEquals(if (headStatus == 200) listOf("HEAD", "GET") else listOf("HEAD", "GET", "GET"), t.methods)
            assertEquals("lws-client-kotlin/0.1.0", t.requests[0].headers["user-agent"])
        }
        // A 401 with a storage link still discovers (anonymous discovery).
        var client = client { r ->
            if (r.method == "HEAD") response(r, 401, "Link" to "</>; rel=\"https://www.w3.org/ns/lws#storage\"")
            else response(r, 200, "Content-Type" to "application/json", body = sd.obj("body"))
        }
        assertEquals(sd.obj("expected").str("id"), client.discoverStorage(s("x")).id.toString())
        // No storage link.
        client = client { r -> response(r, 200) }
        assertFailsWith<ProtocolException> { client.discoverStorage(s("x")) }
        // An error status without a storage link is that error.
        client = client { r -> response(r, 404) }
        assertFailsWith<NotFoundException> { client.discoverStorage(s("x")) }
    }

    @Test
    fun storageDescriptionMediaTypeIsChecked() = runTest {
        val client = client { r -> response(r, 200, "Content-Type" to "text/turtle", body = "<> a <x>.") }
        assertFailsWith<ProtocolException> { client.getStorageDescription(s()) }
    }

    @Test
    fun readConditionalRangeAndText() = runTest {
        val client = client { r ->
            when {
                r.headers["if-none-match"] == "\"1\"" -> response(r, 304, "ETag" to "\"1\"")
                r.headers["range"] == "bytes=0-3" -> response(r, 206, "Content-Range" to "bytes 0-3/11", "Content-Type" to "text/plain", body = "Hell")
                else -> response(
                    r, 200, "ETag" to "\"1\"", "Content-Type" to "text/plain; charset=iso-8859-1",
                    "Link" to "<a.txt.meta>; rel=\"linkset\"", "Link" to "<./>; rel=\"up\"", body = byteArrayOf(0x63, 0x61, 0x66, 0xe9.toByte()),
                )
            }
        }
        val r = client.read(s("c/a.txt"), accept = "text/plain", ifModifiedSince = Instant.parse("2026-10-06T12:00:00Z"), prefer = "return=minimal")
        assertEquals("\"1\"", r.etag)
        assertContentEquals(byteArrayOf(0x63, 0x61, 0x66, 0xe9.toByte()), r.bytes)
        assertEquals("café", r.text())
        assertEquals(s("c/a.txt.meta"), r.metadata.linkset)
        assertEquals(s("c/"), r.metadata.parent)
        assertEquals("Tue, 06 Oct 2026 12:00:00 GMT", t.last.headers["if-modified-since"])
        assertEquals("return=minimal", t.last.headers["prefer"])
        assertEquals("text/plain", t.last.headers["accept"])
        val nm = client.read(s("c/a.txt"), ifNoneMatch = "\"1\"")
        assertTrue(nm.notModified)
        assertEquals(0, nm.size)
        assertEquals(304, nm.status)
        val part = client.read(s("c/a.txt"), range = ByteRange.of(0, 3))
        assertEquals(listOf<Any?>(206, "Hell", "bytes 0-3/11"), listOf(part.status, part.text(), part.contentRange))
        assertEquals("bytes=-5", ByteRange.last(5).headerValue)
        assertEquals("bytes=7-", ByteRange.from(7).headerValue)
        assertFailsWith<IllegalArgumentException> { ByteRange.of(5, 2) }
    }

    /** A container of 12 items, 5 per page, linked by opaque page URLs. */
    private val pagedContainer: suspend (HttpRequest) -> HttpResponse = { r ->
        val page = Regex("\\?page=(\\d)$").find(r.url.toString())?.groupValues?.get(1)?.toInt() ?: 0
        val items = (page * 5 until minOf(12, page * 5 + 5)).map { i ->
            buildJsonObject {
                put("id", "item$i")
                put("type", "DataResource")
                put("format", "text/plain")
            }
        }
        val links = mutableListOf("Link" to "<https://www.w3.org/ns/lws#Container>; rel=\"type\"")
        if (page < 2) links.add("Link" to "<?page=${page + 1}>; rel=\"next\"")
        val body = buildJsonObject {
            put("id", "/c/")
            put("type", "Container")
            put("totalItems", 12)
            put("items", kotlinx.serialization.json.JsonArray(items))
        }
        response(r, 200, "Content-Type" to "application/lws+json", *links.toTypedArray(), body = body)
    }

    @Test
    fun listContainerFollowsNextLazily() = runTest {
        val client = client(pagedContainer)
        val page = client.readContainer(s("c/"))
        assertEquals(s("c/"), page.id)
        assertEquals(12L, page.totalItems)
        assertEquals(s("c/?page=1"), page.next)
        assertEquals("application/lws+json", t.last.headers["accept"])
        t.requests.clear()
        val listing = client.listContainer(s("c/"))
        assertEquals(0, t.requests.size, "nothing is fetched before collecting")
        val ids = listing.toList().map { it.id }
        assertEquals(12, ids.size)
        assertEquals(s("c/item0"), ids[0])
        assertEquals(s("c/item11"), ids[11])
        assertEquals(3, t.requests.size)
        t.requests.clear()
        assertEquals(3, listing.take(3).toList().size)
        assertEquals(1, t.requests.size, "take() stops after the page it needs")
        // Collecting again starts from the first page.
        assertEquals(12, listing.toList().size)
    }

    @Test
    fun listingStopsAtARepeatedPage() = runTest {
        val client = client { r ->
            response(r, 200, "Content-Type" to "application/lws+json", "Link" to "</c/>; rel=\"next\"", body = json("""{"type":"Container","items":[{"id":"x"}]}"""))
        }
        assertEquals(1, client.listContainer(s("c/")).toList().size)
    }

    @Test
    fun readContainerRejectsOtherRepresentations() = runTest {
        for ((type, body) in listOf("text/turtle" to """{"type":"Container","items":[]}""", "application/json" to """{"id":"/x","type":"DataResource"}""", "application/json" to "{not json")) {
            val client = client { r -> response(r, 200, "Content-Type" to type, body = body) }
            assertFailsWith<ProtocolException>(type) { client.readContainer(s("x")) }
        }
    }

    @Test
    fun createVariants() = runTest {
        var client = client { r ->
            response(r, 201, "Location" to "new-" + (r.headers["slug"] ?: "x").lowercase(), "Link" to "<x.meta>; rel=\"linkset\"")
        }
        val c = client.createText(s("c/"), "Hello", slug = "naïve.txt", types = listOf(URI("https://schema.org/Note")), links = listOf(Link(URI("https://example.org/s"), "describedby")))
        assertEquals(s("c/new-na%c3%afve.txt"), c.location)
        assertEquals(s("c/x.meta"), c.linkset)
        val r = t.last
        assertEquals(listOf("POST", "Hello", "text/plain", "na%C3%AFve.txt"), listOf(r.method, r.text, r.headers["content-type"], r.headers["slug"]))
        assertEquals(listOf("<https://schema.org/Note>; rel=\"type\"", "<https://example.org/s>; rel=\"describedby\""), r.headers.all("link"))
        client.createJson(s("c/"), json("""{"name":"Alice","tags":[],"meta":{}}"""))
        assertEquals(listOf("application/json", """{"name":"Alice","tags":[],"meta":{}}"""), listOf(t.last.headers["content-type"], t.last.text))
        client.createContainer(s("c/"), slug = "sub")
        assertEquals(listOf<String?>("", null), listOf(t.last.text, t.last.headers["content-type"]))
        assertEquals(listOf("<https://www.w3.org/ns/lws#Container>; rel=\"type\""), t.last.headers.all("link"))
        client.create(s("c/"), byteArrayOf(0, 1), "application/octet-stream", headers = mapOf("X-Extra" to "yes"))
        assertEquals("yes", t.last.headers["x-extra"])
        // 201 without Location.
        client = client { req -> response(req, 201) }
        assertFailsWith<ProtocolException> { client.createText(s("c/"), "x") }
        assertEquals(1, t.requests.size, "a POST is never repeated")
    }

    @Test
    fun updatePatchAndDelete() = runTest {
        var etag = "\"1\""
        val client = client { r ->
            val match = r.headers["if-match"]
            when {
                match != null && match != etag -> response(r, 412)
                r.method == "DELETE" -> if (r.headers["depth"] == "infinity") response(r, 204)
                else response(r, 409, "Content-Type" to "application/problem+json", body = json("""{"title":"Container not empty"}"""))
                else -> {
                    etag = "\"" + (etag.trim('"').toInt() + 1) + "\""
                    response(r, 204, "ETag" to etag)
                }
            }
        }
        val u = client.update(s("a.txt"), "Hello again".toByteArray(), "text/plain", ifMatch = "\"1\"")
        assertEquals(listOf<Any?>(204, "\"2\""), listOf(u.status, u.etag))
        val e = assertFailsWith<PreconditionFailedException> { client.updateText(s("a.txt"), "stale", ifMatch = "\"1\"") }
        assertEquals(412, e.status)
        assertEquals("PUT", e.method)
        val p = client.patch(s("p.json"), jsonPatch { replace("/age", 31); add("/city", "Boston") }, ifMatch = "\"2\"")
        assertEquals("\"3\"", p.etag)
        assertEquals(
            listOf("application/json-patch+json", """[{"op":"replace","path":"/age","value":31},{"op":"add","path":"/city","value":"Boston"}]"""),
            listOf(t.last.headers["content-type"], t.last.text),
        )
        client.patch(s("p.ttl"), "INSERT DATA {}".toByteArray(), "application/sparql-update")
        assertEquals("application/sparql-update", t.last.headers["content-type"])
        client.update(s("a.txt"), "x".toByteArray(), "text/plain", ifNoneMatch = "*", links = listOf(Link(URI("https://e.example/l"), "license")), setLinkset = true)
        assertEquals(listOf("*", "set-linkset", "<https://e.example/l>; rel=\"license\""), listOf(t.last.headers["if-none-match"], t.last.headers["prefer"], t.last.headers["link"]))
        client.updateJson(s("j.json"), json("""{"a":1}"""))
        assertEquals(listOf("application/json", """{"a":1}"""), listOf(t.last.headers["content-type"], t.last.text))
        val conflict = assertFailsWith<ConflictException> { client.delete(s("c/")) }
        assertEquals("Container not empty", conflict.problem?.title)
        client.delete(s("c/"), recursive = true)
        assertEquals(listOf("DELETE", "infinity"), listOf(t.last.method, t.last.headers["depth"]))
    }

    @Test
    fun linksets() = runTest {
        val fx = Fixtures.load("responses/linkset.json")
        val fxHeaders = fx.obj("headers").entries.map { it.key to it.value.str }.toTypedArray()
        var client = client { r ->
            when (r.method) {
                "HEAD" -> response(r, 200, "Link" to "<personalinfo.json.meta>; rel=\"linkset\"; type=\"application/linkset+json\"")
                "GET" -> response(r, 200, *fxHeaders, body = fx.obj("body"))
                "PUT" -> response(r, 405, "Allow" to "GET, HEAD, PATCH")
                else -> response(r, 204, "ETag" to "\"ls-8\"")
            }
        }
        assertEquals(fx.str("url"), client.linksetUrl(URI("https://storage.example/alice/personalinfo.json")).toString())
        val doc = client.readLinkset(URI("https://storage.example/alice/personalinfo.json"))
        assertEquals(listOf("HEAD", "GET"), t.methods.takeLast(2))
        assertEquals("application/linkset+json, application/json;q=0.5", t.last.headers["accept"])
        assertEquals(fx.str("url"), doc.url.toString())
        assertEquals("\"ls-7\"", doc.etag)
        val pointer = JsonPointer.fromSegments("linkset", "0", "describedby", "-")
        val updated = client.patchLinkset(doc.url, JsonPatch().add(pointer, json("""{"href":"https://example.org/shapes/person"}""")), ifMatch = doc.etag)
        assertEquals("\"ls-8\"", updated.etag)
        assertEquals(listOf("application/json-patch+json", "\"ls-7\""), listOf(t.last.headers["content-type"], t.last.headers["if-match"]))
        assertTrue("\"path\":\"/linkset/0/describedby/-\"" in t.last.text!!)
        val e = assertFailsWith<MethodNotAllowedException> { client.updateLinkset(doc.url, doc.linkset.add(null, "license", "https://example.org/l")) }
        assertEquals(listOf("GET", "HEAD", "PATCH"), e.allow)
        assertEquals("application/linkset+json", t.last.headers["content-type"])
        client = client { r -> response(r, 200) }
        assertFailsWith<ProtocolException> { client.linksetUrl(s("x")) }
    }

    @Test
    fun subscriptions() = runTest {
        val sd = Fixtures.load("responses/storage-description.json")
        val sub = Fixtures.load("responses/subscription.json")
        val subHeaders = sub.obj("response").obj("headers").entries.map { it.key to it.value.str }.toTypedArray()
        var client = client { r ->
            when (r.method) {
                "POST" -> response(r, 201, *subHeaders, body = sub.obj("response").obj("body"))
                "GET" -> response(r, 200, "Content-Type" to "application/lws+json", body = json("""{"type":"WebhookSubscription","expires":"2026-06-09T12:00:00Z"}"""))
                else -> response(r, 204)
            }
        }
        val storage = StorageDescription.parse(sd.obj("body"), URI(sd.str("url")))
        val service = storage.notificationService()!!
        val input = sub.obj("input")
        val request = WebhookSubscriptionRequest(input.strings("topics").map(::URI), URI(input.str("inbox")), Instant.parse(input.str("expires")))
        val created = client.subscribe(service, request)
        assertEquals(sub.obj("expected").str("subscription"), created.url.toString())
        assertEquals(JsonAccess.encode(sub.obj("expectedRequestBody")), t.last.text)
        assertEquals(listOf("application/lws+json", "application/lws+json"), listOf(t.last.headers["content-type"], t.last.headers["accept"]))
        val got = client.getSubscription(created.url)
        assertEquals(created.url, got.url)
        assertEquals("WebhookSubscription", got.type)
        client.unsubscribe(created.url)
        assertEquals("DELETE", t.last.method)
        // A body-less 201 with a Location.
        client = client { r -> response(r, 201, "Location" to "/subs/1") }
        assertEquals(s("subs/1"), client.subscribe(s("notifications/"), request).url)
        // A service without webhooks.
        val other = Service(null, listOf("NotificationService"), s("n/"), JsonObject(mapOf("subscriptionType" to json("""["StreamingSubscription"]"""))))
        assertFailsWith<ProtocolException> { client.subscribe(other, request) }
    }

    @Test
    fun accessRequestsAndGrants() = runTest {
        val fx = Fixtures.load("responses/access.json")
        val client = client { r ->
            when (r.method) {
                "POST" -> response(r, 201, "Location" to "r1")
                "GET" -> response(r, 200, "Content-Type" to "application/lws+json", body = if ("grants" in r.url.toString()) fx.obj("grant") else fx.obj("request"))
                else -> response(r, 204)
            }
        }
        val policy = AccessPolicy(listOf("read"), "did:key:zDnae", AccessTarget.containers(S + "c/"))
        val location = client.requestAccess(s("access/requests/"), AccessRequest(s(), listOf(policy)))
        assertEquals(s("access/requests/r1"), location)
        assertEquals(
            """{"@context":["https://www.w3.org/ns/lws/v1"],"type":["AccessRequest"],"storage":"https://storage.example/","access":[{"type":["AccessPolicy"],"action":["read"],"assignee":"did:key:zDnae","target":{"type":"Container","value":["https://storage.example/c/"]}}]}""",
            t.last.text,
        )
        assertEquals(fx.obj("request"), client.getAccessRequest(location).raw)
        assertEquals(s("access/grants/r1"), client.grantAccess(s("access/grants/"), AccessGrant(s(), listOf(policy))))
        assertEquals("AccessGrant", client.getAccessGrant(s("access/grants/r1")).types[0])
        client.revokeAccessGrant(s("access/grants/r1"))
        client.cancelAccessRequest(location)
        assertEquals(listOf("DELETE", "DELETE"), t.methods.takeLast(2))
    }

    @Test
    fun typeIndexAndSearch() = runTest {
        val client = client { r ->
            val u = r.url.toString()
            when {
                r.method == "OPTIONS" -> response(r, 204, "Accept-Query" to "\"application/lws-query+json\", application/sparql-query", "Allow" to "QUERY, OPTIONS")
                r.method == "QUERY" -> response(
                    r, 200, "Content-Type" to "application/lws+json", "Link" to "</types/search/p/2>; rel=\"next\"",
                    body = json("""{"type":"ContainerPage","items":[{"id":"/a","type":"DataResource"}]}"""),
                )
                "/search/p/2" in u -> response(r, 200, "Content-Type" to "application/lws+json", body = json("""{"type":"ContainerPage","items":[{"id":"/b"}]}"""))
                u.endsWith("/types/index") -> response(
                    r, 200, "Content-Type" to "application/lws+json", "Link" to "<index?p=2>; rel=\"next\"",
                    body = json("""{"type":"TypeIndex","totalItems":3,"items":["https://schema.org/Person",{"id":"https://schema.org/Event"}]}"""),
                )
                else -> response(r, 200, "Content-Type" to "application/lws+json", body = json("""{"type":"TypeIndex","items":["https://schema.org/Place"]}"""))
            }
        }
        val page = client.readTypeIndex(s("types/index"))
        assertEquals(listOf<Any?>(3L, listOf("https://schema.org/Person", "https://schema.org/Event"), s("types/index?p=2")), listOf(page.totalItems, page.types, page.next))
        assertEquals(listOf("https://schema.org/Person", "https://schema.org/Event", "https://schema.org/Place"), client.listTypes(s("types/index")).toList())
        val q = TypeQuery().allOf("https://schema.org/Person")
        val first = client.searchTypes(s("types/search"), q)
        assertEquals(s("types/search"), first.id, "the page URL stands in for a missing id")
        val r = t.last
        assertEquals(listOf("QUERY", "application/lws-query+json", "application/lws+json", """{"type":["https://schema.org/Person"]}"""), listOf(r.method, r.headers["content-type"], r.headers["accept"], r.text))
        t.requests.clear()
        assertEquals(listOf(s("a"), s("b")), client.searchAll(s("types/search"), q).toList().map { it.id })
        assertEquals(listOf("QUERY", "GET"), t.methods)
        assertEquals(listOf("application/lws-query+json", "application/sparql-query"), client.acceptedQueryFormats(s("types/search")))
    }

    @Test
    fun errorMapping() = runTest {
        val classes: Map<Int, KClass<out HttpException>> = mapOf(
            400 to BadRequestException::class, 401 to UnauthorizedException::class, 403 to ForbiddenException::class,
            404 to NotFoundException::class, 405 to MethodNotAllowedException::class, 406 to NotAcceptableException::class,
            409 to ConflictException::class, 410 to GoneException::class, 412 to PreconditionFailedException::class,
            415 to UnsupportedMediaTypeException::class, 422 to UnprocessableContentException::class, 501 to NotImplementedException::class,
            507 to InsufficientStorageException::class, 500 to HttpException::class, 418 to HttpException::class,
        )
        for ((status, kind) in classes) {
            val client = client { r ->
                response(
                    r, status, "Accept-Patch" to "application/json-patch+json", "Accept-Query" to "application/lws-query+json",
                    "WWW-Authenticate" to "Basic realm=\"x\"", "Content-Type" to "text/plain", body = "e".repeat(10000),
                )
            }
            val e = assertFailsWith<HttpException> { client.head(s("x")) }
            assertEquals(kind, e::class)
            assertEquals(status, e.status)
            assertEquals(HttpException.BODY_LIMIT, e.body.length)
            if (e is UnsupportedMediaTypeException) {
                assertEquals(listOf("application/json-patch+json"), e.acceptPatch)
                assertEquals(listOf("application/lws-query+json"), e.acceptQuery)
            }
            if (e is UnauthorizedException) assertTrue(e.challenges[0].isScheme("basic"))
        }
    }

    @Test
    fun redirectsAreFollowedByTheClient() = runTest {
        val client = client { r ->
            when (r.url.toString()) {
                S + "old" -> response(r, 301, "Location" to "/new")
                S + "new" -> response(r, 200, body = "moved")
                S + "post" -> response(r, 303, "Location" to "/result")
                S + "result" -> response(r, 200, body = r.method + " " + (r.text ?: "none") + " " + (r.headers["content-type"] ?: "none"))
                S + "temp" -> response(r, 307, "Location" to "https://other.example/put")
                "https://other.example/put" -> response(r, 204)
                S + "loop" -> response(r, 302, "Location" to "/loop")
                else -> response(r, 302, "Location" to "/new")
            }
        }
        val r = client.read(s("old"))
        assertEquals(listOf<Any>("moved", s("new")), listOf(r.text(), r.url))
        assertEquals("GET none none", client.request("QUERY", s("post"), "q".toByteArray(), "text/plain").text())
        // 307 keeps the method and body; a caller's Authorization does not cross origins.
        client.update(s("temp"), "body".toByteArray(), "text/plain", headers = mapOf("Authorization" to "Basic abc"))
        assertEquals(listOf<Any?>("PUT", "body", null), listOf(t.last.method, t.last.text, t.last.headers["authorization"]))
        assertEquals("Basic abc", t.requests[t.requests.size - 2].headers["authorization"])
        // A 302 answer to a POST is not followed.
        assertEquals(302, assertFailsWith<HttpException> { client.createText(s("elsewhere"), "x") }.status)
        assertFailsWith<ProtocolException> { client.head(s("loop")) }
    }

    @Test
    fun defaultHeadersUserAgentAndTimeout() = runTest {
        val transport = FakeTransport { r -> response(r, 200) }
        val client = LwsClient(transport = transport, userAgent = "my-app/1", defaultHeaders = mapOf("X-App" to "a", "Accept-Language" to "en"), timeout = 5.seconds)
        client.head(s(), headers = mapOf("Accept-Language" to "de"), timeout = 2.seconds)
        val r = transport.last
        assertEquals(listOf<Any?>("my-app/1", "a", "de", 2.seconds), listOf(r.headers["user-agent"], r.headers["x-app"], r.headers["accept-language"], r.timeout))
        client.head(s())
        assertEquals(5.seconds, transport.last.timeout)
        LwsClient(transport = transport, userAgent = null).head(s())
        assertNull(transport.last.headers["user-agent"])
        val again = client.withAuthenticator(null)
        assertEquals(client.transport, again.transport)
        assertEquals(client.defaultHeaders, again.defaultHeaders)
    }

    @Test
    fun invalidArguments() = runTest {
        val client = client { throw IllegalStateException("No request may be sent") }
        val bad: List<suspend () -> Any> = listOf(
            { client.read(URI("/relative")) },
            { client.head(URI("ftp://x.example/")) },
            { client.listContainer(URI("nope")) },
            { client.createText(URI("https:///no-host"), "x") },
            { client.request("BAD METHOD", s()) },
            { client.read(s(), headers = mapOf("X-Bad" to "a\r\nInjected: b")) },
            { client.read(s(), headers = mapOf("Bad Name" to "x")) },
            { client.searchAll(URI("/x"), TypeQuery()) },
        )
        for (b in bad) assertFailsWith<IllegalArgumentException> { b() }
        assertEquals(0, t.requests.size)
        assertEquals("x", client.listContainer(s()).let { "x" })
        assertFailsWith<IllegalStateException> { client.listContainer(s()).first() }
        assertEquals(JsonPrimitive(1), json("1"))
    }

    private companion object {
        const val S = "https://storage.example/"
    }
}
