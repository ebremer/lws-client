// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.access.AccessGrant
import com.ebremer.lws.kotlin.access.AccessPolicy
import com.ebremer.lws.kotlin.access.AccessRequest
import com.ebremer.lws.kotlin.access.AccessTarget
import com.ebremer.lws.kotlin.access.Constraint
import com.ebremer.lws.kotlin.auth.AccessToken
import com.ebremer.lws.kotlin.auth.AuthorizationServerMetadata
import com.ebremer.lws.kotlin.http.Headers
import com.ebremer.lws.kotlin.internal.JsonAccess
import com.ebremer.lws.kotlin.internal.Urls
import com.ebremer.lws.kotlin.notify.Notification
import com.ebremer.lws.kotlin.notify.Subscription
import com.ebremer.lws.kotlin.notify.WebhookSubscriptionRequest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.Test
import java.net.URI
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The shared response fixtures, parsed by the models. */
class ModelFixtureTest {
    private fun headers(o: JsonObject): Headers = Headers.of(
        o.entries.flatMap { (k, v) -> if (v is JsonArray) v.map { k to it.str } else listOf(k to v.str) },
    )

    private fun metadata(url: String, status: Int, headers: JsonObject): ResourceMetadata = ResourceMetadata(URI(url), status, headers(headers))

    private fun JsonObject.longOrNull(key: String): Long? = (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toLongOrNull()

    private fun JsonObject.bool(key: String): Boolean = this[key]!!.str == "true"

    @Test
    fun storageDescriptionFixture() {
        val f = Fixtures.load("responses/storage-description.json")
        val sd = StorageDescription.parse(f.obj("body"), URI(f.str("url")))
        val e = f.obj("expected")
        assertEquals(e.str("id"), sd.id.toString())
        assertEquals(e.strings("types"), sd.types)
        assertEquals(e.str("storageRoot"), sd.storageRoot().toString())
        assertEquals(e.str("notificationService"), sd.notificationService()?.serviceEndpoint.toString())
        assertEquals(e.strings("notificationSubscriptionTypes"), sd.notificationService()?.subscriptionTypes)
        assertEquals(e.str("typeIndexService"), sd.typeIndexService()?.serviceEndpoint.toString())
        assertEquals(e.str("typeSearchService"), sd.typeSearchService()?.serviceEndpoint.toString())
        assertEquals(e.str("accessRequestService"), sd.accessRequestService()?.serviceEndpoint.toString())
        assertEquals(e.str("accessGrantService"), sd.accessGrantService()?.serviceEndpoint.toString())
        assertEquals(e.longOrNull("serviceCount")?.toInt(), sd.services.size)
        assertEquals(e.strings("capabilityTypes"), sd.capabilities.map { it.types[0] })
        val c = e.obj("customService")
        val custom = assertNotNull(sd.service(c.str("type")))
        assertEquals(c.str("id"), custom.id.toString())
        assertEquals(c.str("serviceEndpoint"), custom.serviceEndpoint.toString())
        assertNotNull(sd.capability("https://feature.example/PatchSupport"))
        assertTrue(sd.hasType("https://www.w3.org/ns/lws#Storage"))
    }

    @Test
    fun storageDescriptionInvalid() {
        val invalid = Fixtures.load("responses/storage-description.json").obj("invalid")
        assertFailsWith<ProtocolException> { StorageDescription.parse(invalid.obj("notStorage")) }
        val sd = StorageDescription.parse(invalid.obj("noRoot"))
        assertFailsWith<ProtocolException> { sd.storageRoot() }
    }

    @Test
    fun containerPageFixture() {
        val f = Fixtures.load("responses/container-page.json")
        val page = ContainerPage.parse(f.obj("body"), metadata(f.str("url"), 200, f.obj("headers")))
        val e = f.obj("expected")
        assertEquals(e.str("id"), page.id.toString())
        assertEquals(e.bool("isContainer"), page.metadata.isContainer)
        assertEquals(e.longOrNull("totalItems"), page.totalItems)
        assertEquals(e.str("etag"), page.etag)
        assertEquals(e.str("linkset"), page.metadata.linkset.toString())
        assertEquals(e.str("parent"), page.metadata.parent.toString())
        assertEquals(e.str("storage"), page.metadata.storage.toString())
        assertEquals(listOf("first", "next", "prev", "last").map { e.strOrNull(it) }, listOf(page.first, page.next, page.prev, page.last).map { it?.toString() })
        val items = e.arr("items").map { it.jsonObject }
        assertEquals(items.size, page.items.size)
        items.forEachIndexed { i, x ->
            val item = page.items[i]
            assertEquals(x.str("id"), item.id.toString())
            assertEquals(x.bool("isContainer"), item.isContainer)
            assertEquals(x.bool("isDataResource"), item.isDataResource)
            assertEquals(x.strOrNull("format"), item.format)
            assertEquals(x.longOrNull("size"), item.size)
            assertEquals(x.strings("types"), item.types)
            if ("modified" in x) assertEquals(x.strOrNull("modified"), item.modified?.truncatedTo(ChronoUnit.SECONDS)?.toString())
            x.strOrNull("modifiedRaw")?.let { assertEquals(it, item.modifiedRaw) }
            x.strOrNull("hasType")?.let { assertTrue(item.hasType(it)) }
        }
        // A page body that is not a page.
        assertFailsWith<ProtocolException> { ContainerPage.parse(json("""{"items":"nope"}"""), metadata(f.str("url"), 200, JsonObject(emptyMap()))) }
        assertFailsWith<ProtocolException> { ContainerPage.parse(json("[]"), metadata(f.str("url"), 200, JsonObject(emptyMap()))) }
    }

    @Test
    fun containedResourceDates() {
        val item = ContainedResource.parse(json("""{"id":"x","modified":"2026-10-07T12:00:00.250+02:00","type":"Container"}"""), URI("https://s.example/"))
        assertEquals(URI("https://s.example/x"), item.id)
        assertEquals(Instant.parse("2026-10-07T10:00:00.250Z"), item.modified)
        assertEquals(listOf("Container"), item.types)
        assertTrue(item.isContainer)
        assertNull(ContainedResource.parse(json("""{"id":"y","modified":"2026-02-30T00:00:00Z"}"""), URI("https://s.example/")).modified)
        assertFailsWith<ProtocolException> { ContainedResource.parse(json("""{"type":"DataResource"}"""), URI("https://s.example/")) }
    }

    @Test
    fun linksetFixture() {
        val f = Fixtures.load("responses/linkset.json")
        val doc = LinksetDocument(URI(f.str("url")), Linkset.parse(f.obj("body")), metadata(f.str("url"), 200, f.obj("headers")))
        val e = f.obj("expected")
        assertEquals(e.str("url"), doc.url.toString())
        assertEquals(e.str("etag"), doc.etag)
        assertEquals(e.strings("allow"), doc.allow)
        assertEquals(e.strings("acceptPatch"), doc.acceptPatch)
        assertTrue(doc.supportsPut)
        assertEquals(e.longOrNull("contexts")?.toInt(), doc.linkset.contexts.size)
        assertEquals(e.str("anchor"), doc.linkset.contexts[0].anchor)
        assertEquals(e.longOrNull("linkCount")?.toInt(), doc.linkset.size)
        assertEquals(e.longOrNull("linkCount")?.toInt(), doc.linkset.links().size)
        for ((rel, targets) in e.obj("targets")) assertEquals((targets as JsonArray).map { it.str }, doc.linkset.hrefs(rel))
        // Lossless round trip, member order and the hreflang / title* members included.
        val original = JsonAccess.encode(f.obj("body"))
        assertEquals(original, doc.linkset.encode())
        val op = e.obj("afterAdd").obj("operation")
        doc.linkset.add(op.str("anchor"), op.str("rel"), op.str("href"))
        assertEquals(e.obj("afterAdd").strings("licenseTargets"), doc.linkset.hrefs("license", op.str("anchor")))
        assertEquals(1, doc.linkset.remove(op.str("anchor"), "license", op.str("href")))
        assertEquals(original, doc.linkset.encode())
        val links = doc.linkset.links()
        assertEquals(op.str("anchor"), links[0].anchor)
        assertEquals("application/schema+json", links[0].type)
        assertEquals("Bob", doc.linkset.targets("https://example.org/rel/reviewer")[0].attribute("title"))
        assertEquals(2, doc.linkset.remove(op.str("anchor"), "https://example.org/rel/reviewer"))
        assertEquals(emptyList(), doc.linkset.hrefs("https://example.org/rel/reviewer"))
        val fresh = Linkset().add("https://s.example/a", "describedby", "https://s.example/shape", mapOf("type" to JsonPrimitive("text/turtle")))
        assertEquals("""{"linkset":[{"anchor":"https://s.example/a","describedby":[{"href":"https://s.example/shape","type":"text/turtle"}]}]}""", fresh.encode())
        assertEquals(JsonObject(mapOf("href" to JsonPrimitive("x"), "type" to JsonPrimitive("t"))), LinkTarget("x", mapOf("href" to JsonPrimitive("ignored"), "type" to JsonPrimitive("t"))).toJson())
        assertFailsWith<ProtocolException> { Linkset.parse("""{"nolinkset": []}""") }
    }

    @Test
    fun notificationFixture() {
        val f = Fixtures.load("responses/notification.json")
        for (key in listOf("single", "batch")) {
            val n = Notification.parse(f.obj(key))
            val e = f.obj(key + "Expected")
            assertEquals(e.str("storage"), n.storage.toString())
            val activities = e.arr("activities").map { it.jsonObject }
            assertEquals(activities.size, n.activities.size)
            activities.forEachIndexed { i, x ->
                val a = n.activities[i]
                assertEquals(x.strOrNull("id"), a.id)
                assertEquals(x.strings("types"), a.types)
                assertEquals(x.str("objectId"), a.`object`.id.toString())
                if ("isCreate" in x) assertEquals(x.bool("isCreate"), a.isCreate)
                if ("isUpdate" in x) assertEquals(x.bool("isUpdate"), a.isUpdate)
                if ("isDelete" in x) assertEquals(x.bool("isDelete"), a.isDelete)
                if ("objectTypes" in x) assertEquals(x.strings("objectTypes"), a.`object`.types)
                x.strOrNull("origin")?.let { assertEquals(it, a.origin.toString()) }
                x.strOrNull("target")?.let { assertEquals(it, a.target.toString()) }
                x.strOrNull("actor")?.let { assertEquals(it, a.actor.toString()) }
                x.strOrNull("published")?.let {
                    assertEquals(it, a.publishedRaw)
                    assertNotNull(a.published)
                }
            }
        }
        assertEquals(0, Notification.parse("""{"type":"Notification","storage":"https://s.example/","activity":[]}""").activities.size)
        assertFailsWith<ProtocolException> { Notification.parse(f.obj("invalid")) }
    }

    @Test
    fun accessFixture() {
        val f = Fixtures.load("responses/access.json")
        val request = AccessRequest.parse(f.obj("request"))
        assertEquals(URI("https://storage.example/"), request.storage)
        assertEquals(listOf("read", "create"), request.access[0].actions)
        assertEquals(f.obj("request"), request.toJson())
        assertEquals(JsonAccess.encode(f.obj("request")), JsonAccess.encode(request.document()))
        val grant = AccessGrant.parse(JsonAccess.encode(f.obj("grant")))
        assertEquals(f.obj("grant"), grant.toJson())
        assertEquals(json("""["image/jpeg","image/png"]"""), grant.access[0].constraints[0].rightOperand)
        val built = AccessRequest(
            URI("https://storage.example/"),
            listOf(
                AccessPolicy(
                    listOf("read", "create"), "https://id.example/agent", AccessTarget.storageResources("https://storage.example/root/projects/"),
                    listOf(Constraint.purpose("https://purpose.example/collaboration"), Constraint.notAfter("2026-06-09T10:00:00Z")),
                ),
            ),
            URI("https://id.example/agent/inbox/"),
        )
        assertEquals(JsonAccess.encode(f.obj("request")), JsonAccess.encode(built.toJson()))
        assertNull(built.raw)
        val bad: List<() -> Any> = listOf(
            { AccessGrant.parse(f.obj("request")) },
            { AccessRequest.parse("""{"type":"AccessRequest","storage":"https://s.example/"}""") },
            { AccessRequest.parse("""{"type":"AccessRequest","storage":"https://s.example/","access":[{"action":["read"]}]}""") },
        )
        for (b in bad) assertFailsWith<ProtocolException> { b() }
        val invalid: List<() -> Any> = listOf(
            { AccessPolicy(emptyList(), "https://id.example/agent") },
            { AccessPolicy(listOf("read"), "agent") },
            { AccessRequest(URI("https://storage.example/"), emptyList()) },
            { AccessTarget("Container", emptyList()) },
        )
        for (b in invalid) assertFailsWith<IllegalArgumentException> { b() }
    }

    @Test
    fun constraintFactories() {
        assertEquals(
            json("""{"leftOperand":"dateTime","operator":"gteq","rightOperand":"2026-03-09T12:00:00Z"}"""),
            Constraint.notBefore(Instant.parse("2026-03-09T12:00:00Z")).toJson(),
        )
        assertEquals(json("""["image/png"]"""), Constraint.formatAnyOf("image/png").rightOperand)
        assertEquals("type", Constraint.type("https://type.example/Song").leftOperand)
        assertEquals("isAnyOf", Constraint.typeAnyOf("https://type.example/Song").operator)
        assertEquals("eq", Constraint.client("https://app.example/id").operator)
        assertEquals(json("""["a:1","b:2"]"""), Constraint.purposeAnyOf("a:1", "b:2").rightOperand)
        assertEquals(JsonPrimitive("image/png"), Constraint.format("image/png").rightOperand)
        assertFailsWith<IllegalArgumentException> { Constraint.notAfter("tomorrow") }
    }

    @Test
    fun typeIndexAndSearchFixture() {
        val f = Fixtures.load("responses/type-index.json")
        val ti = f.obj("typeIndex")
        val page = TypeIndexPage.parse(ti.obj("body"), metadata(ti.str("url"), 200, ti.obj("headers")))
        assertEquals(ti.obj("expected").longOrNull("totalItems"), page.totalItems)
        assertEquals(ti.obj("expected").strings("types"), page.types)
        assertEquals(ti.obj("expected").str("next"), page.next.toString())
        val se = f.obj("search")
        val sp = ContainerPage.parse(se.obj("body"), metadata(se.str("url"), 200, se.obj("headers")))
        assertEquals(se.obj("expected").longOrNull("totalItems"), sp.totalItems)
        assertEquals(se.obj("expected").strings("ids"), sp.items.map { it.id.toString() })
        assertEquals(se.obj("expected").str("next"), sp.next.toString())
        assertTrue(sp.items[2].isContainer)
        assertEquals(Urls.resolve(se.obj("body").strOrNull("id") ?: se.str("url"), se.str("url")), sp.id.toString())
    }

    @Test
    fun oauthFixture() {
        val f = Fixtures.load("responses/oauth.json")
        for (c in f.arr("metadataUrls").map { it.jsonObject }) assertEquals(c.str("url"), AuthorizationServerMetadata.metadataUrl(c.str("issuer")))
        for (c in f.arr("realmChecks").map { it.jsonObject }) assertEquals(c.bool("contained"), Urls.contains(c.str("realm"), c.str("url")), c.toString())
        val now = Instant.ofEpochSecond(1_700_000_000)
        val t = AccessToken.fromTokenResponse(f.obj("tokenResponse").obj("body"), now)
        assertEquals(now.plusSeconds(f.obj("tokenResponse").longOrNull("expectedExpiresIn")!!), t.expiresAt)
        assertTrue(t.isValid(now, kotlin.time.Duration.parse("30s")))
        assertEquals(
            Instant.ofEpochSecond(f.obj("tokenResponseNoExpiry").longOrNull("expectedExp")!!),
            AccessToken.fromTokenResponse(f.obj("tokenResponseNoExpiry").obj("body"), now).expiresAt,
        )
        assertEquals(now.plusSeconds(300), AccessToken.fromTokenResponse(json("""{"access_token":"opaque","token_type":"bearer"}""").jsonObject, now).expiresAt)
        assertFailsWith<AuthenticationException> { AccessToken.fromTokenResponse(json("""{"access_token":"x","token_type":"DPoP"}""").jsonObject, now) }
        val md = AuthorizationServerMetadata.parse(f.obj("metadata"), URI("https://authorization.example/.well-known/lws-configuration"))
        assertTrue(Urls.isHttp(md.tokenEndpoint.toString()))
        assertTrue(md.raw.isNotEmpty())
    }

    @Test
    fun problemDetailsFixture() {
        val f = Fixtures.load("responses/problem-details.json")
        val e = HttpException.fromResponse(409, "DELETE", URI("https://storage.example/alice/notes/"), headers(f.obj("headers")), JsonAccess.encode(f.obj("body")).toByteArray())
        assertIs<ConflictException>(e)
        assertEquals(409, e.status)
        val x = f.obj("expected")
        val problem = assertNotNull(e.problem)
        assertEquals(listOf(x.str("type"), x.str("title"), x.str("detail"), x.str("instance")), listOf(problem.type, problem.title, problem.detail, problem.instance))
        assertEquals(x.obj("extension"), problem.extensions)
        assertTrue("container is not empty" in e.message!!)
        assertTrue("DELETE https://storage.example/alice/notes/" in e.message!!)
    }

    @Test
    fun subscriptionFixture() {
        val f = Fixtures.load("responses/subscription.json")
        val input = f.obj("input")
        val request = WebhookSubscriptionRequest(input.strings("topics").map(::URI), URI(input.str("inbox")), Instant.parse(input.str("expires")))
        assertEquals(JsonAccess.encode(f.obj("expectedRequestBody")), JsonAccess.encode(request.toJson()))
        val sub = Subscription.parse(f.obj("response").obj("body"))
        val x = f.obj("expected")
        assertEquals(listOf(x.str("type"), x.str("subscription"), x.str("expires")), listOf(sub.type, sub.url.toString(), sub.expiresRaw))
        assertNotNull(sub.expires)
        assertFailsWith<IllegalArgumentException> { WebhookSubscriptionRequest(emptyList(), URI(input.str("inbox"))) }
        assertFailsWith<IllegalArgumentException> { WebhookSubscriptionRequest(listOf(URI("/relative")), URI(input.str("inbox"))) }
    }

    @Test
    fun resourceMetadata() {
        val m = ResourceMetadata(
            URI("https://s.example/c/a.txt"), 200,
            Headers.of(
                "ETag" to "W/\"3\"",
                "Last-Modified" to "Tue, 06 Oct 2026 12:00:00 GMT",
                "Content-Type" to "text/plain; charset=utf-8",
                "Content-Length" to "11",
                "Link" to "<a.txt.meta>; rel=\"linkset\"; type=\"application/linkset+json\"",
                "Link" to "<./>; rel=\"up\"",
                "Link" to "</>; rel=\"https://www.w3.org/ns/lws#storage\"",
                "Link" to "<https://www.w3.org/ns/lws#DataResource>; rel=\"type\"",
                "Allow" to "GET, HEAD, PUT",
                "Accept-Patch" to "application/json-patch+json",
            ),
        )
        assertEquals("W/\"3\"", m.etag)
        assertEquals(Instant.parse("2026-10-06T12:00:00Z"), m.lastModifiedTime)
        assertEquals(11L, m.contentLength)
        assertEquals(URI("https://s.example/c/a.txt.meta"), m.linkset)
        assertEquals(URI("https://s.example/c/"), m.parent)
        assertEquals(URI("https://s.example/"), m.storage)
        assertTrue(m.isDataResource)
        assertFalse(m.isContainer)
        assertEquals(listOf("GET", "HEAD", "PUT"), m.allow)
        assertEquals(listOf("application/json-patch+json"), m.acceptPatch)
        assertEquals("application/linkset+json", m.link("linkset")?.type)
        assertEquals(1, m.links("up").size)
    }

    @Test
    fun resourceBodies() {
        val m = ResourceMetadata(URI("https://s.example/a"), 200, Headers.of("Content-Type" to "text/plain; charset=ISO-8859-1"))
        val r = Resource(m, byteArrayOf(0x63, 0x61, 0x66, 0xe9.toByte()))
        assertEquals("café", r.text())
        assertEquals(4, r.size)
        val j = Resource(ResourceMetadata(URI("https://s.example/b"), 200, Headers.of("Content-Type" to "application/json")), """{"a":[1,2]}""".toByteArray())
        assertEquals<JsonElement>(json("""{"a":[1,2]}"""), j.json())
        assertFailsWith<ProtocolException> { r.json() }
    }
}
