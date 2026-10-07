// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.access.AccessGrant
import com.ebremer.lws.kotlin.access.AccessPolicy
import com.ebremer.lws.kotlin.access.AccessRequest
import com.ebremer.lws.kotlin.access.AccessTarget
import com.ebremer.lws.kotlin.access.Constraint
import com.ebremer.lws.kotlin.auth.SelfSignedCredentials
import com.ebremer.lws.kotlin.auth.SigningKey
import com.ebremer.lws.kotlin.auth.TokenExchangeAuthenticator
import com.ebremer.lws.kotlin.json.JsonPointer
import com.ebremer.lws.kotlin.json.jsonPatch
import com.ebremer.lws.kotlin.notify.WebhookSubscriptionRequest
import com.ebremer.lws.kotlin.notify.WebhookVerifier
import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.net.URI
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The scenario of conformance/scenario.md against the mock server, when LWS_TEST_SERVER is set. */
class InteropTest {
    private class Delivery(val method: String, val headers: Map<String, List<String>>, val body: ByteArray)

    @Test
    fun scenario() = runBlocking {
        val server = System.getenv("LWS_TEST_SERVER")
        assumeTrue(!server.isNullOrEmpty(), "LWS_TEST_SERVER is not set")
        val base = server!!.trimEnd('/')
        val person = "https://schema.org/Person"

        // 1. Authenticate and discover.
        val me = SelfSignedCredentials.didKey(SigningKey.generateP256())
        val client = LwsClient(authenticator = TokenExchangeAuthenticator(me))
        val storage = client.discoverStorage(URI("$base/root/"))
        assertEquals(URI("$base/root/"), storage.storageRoot())
        val notifications = assertNotNull(storage.notificationService())
        val requests = assertNotNull(storage.accessRequestService()).serviceEndpoint
        val grants = assertNotNull(storage.accessGrantService()).serviceEndpoint
        val typeIndex = assertNotNull(storage.typeIndexService()).serviceEndpoint
        val typeSearch = assertNotNull(storage.typeSearchService()).serviceEndpoint
        val root = storage.storageRoot()

        // 2. A container for this run.
        val c = client.createContainer(root, slug = "interop-kotlin-${System.currentTimeMillis()}").location

        // 3, 4. Create and read text.
        val h = client.createText(c, "Hello, LWS!", slug = "hello.txt").location
        val read = client.read(h)
        assertEquals("Hello, LWS!", read.text())
        val etag = assertNotNull(read.etag)
        assertTrue(read.metadata.isDataResource)
        assertEquals(c, read.metadata.parent)
        assertNotNull(read.metadata.linkset)
        assertEquals(URI("$base/"), read.metadata.storage)

        // 5. Conditional read.
        assertTrue(client.read(h, ifNoneMatch = etag).notModified)

        // 6. Update with If-Match; the old ETag then fails.
        client.updateText(h, "Hello again", ifMatch = etag)
        assertFailsWith<PreconditionFailedException> { client.updateText(h, "stale", ifMatch = etag) }

        // 7. Create JSON with a type, patch it.
        val p = client.createJson(c, json("""{"name":"Alice","age":30}"""), slug = "profile.json", types = listOf(URI(person))).location
        client.patch(p, jsonPatch { replace("/age", 31); add("/city", "Boston") })
        assertEquals(json("""{"name":"Alice","age":31,"city":"Boston"}"""), client.read(p).json())

        // 8. Linkset: add describedby to the first context.
        val doc = client.readLinkset(p)
        val shape = "https://example.org/shapes/person"
        client.patchLinkset(doc.url, jsonPatch { add(JsonPointer.fromSegments("linkset", "0", "describedby"), json("""[{"href":"$shape"}]""")) }, ifMatch = doc.etag)
        assertTrue(shape in client.readLinkset(p).linkset.hrefs("describedby"))

        // 9. Pagination: eight members.
        repeat(6) { i -> client.createText(c, "item $i", slug = "item-$i.txt") }
        val page = client.readContainer(c)
        assertEquals(8L, page.totalItems)
        assertNotNull(page.next)
        val ids = client.listContainer(c).map { it.id }.toList()
        assertEquals(8, ids.size)
        assertTrue(h in ids && p in ids)

        // 10. Type index and search.
        assertTrue(person in client.listTypes(typeIndex).toList())
        assertTrue(p in client.searchAll(typeSearch, TypeQuery().allOf(person)).map { it.id }.toList())
        assertTrue("application/lws-query+json" in client.acceptedQueryFormats(typeSearch))

        // 11. Notifications, with a local inbox.
        val delivery = CompletableDeferred<Delivery>()
        val inboxServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        inboxServer.createContext("/inbox") { exchange ->
            val body = exchange.requestBody.readAllBytes()
            delivery.complete(Delivery(exchange.requestMethod, exchange.requestHeaders.toMap(), body))
            exchange.sendResponseHeaders(204, -1)
            exchange.close()
        }
        inboxServer.start()
        try {
            val inbox = URI("http://127.0.0.1:${inboxServer.address.port}/inbox")
            val subscription = client.subscribe(notifications, WebhookSubscriptionRequest(listOf(c), inbox))
            client.updateText(h, "Hello, notifications")
            val d = withTimeout(5.seconds) { delivery.await() }
            val verified = WebhookVerifier(client, trustedStorages = listOf(URI("$base/"))).verify(d.method, inbox, d.headers, d.body)
            val update = verified.notification.activities.filter { it.isUpdate }
            assertTrue(update.isNotEmpty())
            assertEquals(h, update[0].`object`.id)
            assertTrue(subscription.url in client.listSubscriptions(notifications.serviceEndpoint).map { it.id }.toList())
            client.unsubscribe(subscription.url)
        } finally {
            inboxServer.stop(0)
        }

        // 12. Access requests and grants.
        val policy = AccessPolicy(listOf(AccessAction.READ), me.agent, AccessTarget.containers(c.toString()), listOf(Constraint.purpose("https://purpose.example/interop")))
        val requestUrl = client.requestAccess(requests, AccessRequest(URI("$base/"), listOf(policy)))
        val got = client.getAccessRequest(requestUrl)
        assertEquals(URI("$base/"), got.storage)
        assertEquals(me.agent, got.access[0].assignee)
        assertTrue(requestUrl in client.listAccessRequests(requests).map { it.id }.toList())
        val grantUrl = client.grantAccess(grants, AccessGrant(URI("$base/"), listOf(policy)))
        assertEquals(listOf("read"), client.getAccessGrant(grantUrl).access[0].actions)
        client.revokeAccessGrant(grantUrl)
        client.cancelAccessRequest(requestUrl)

        // 13. Delete.
        assertFailsWith<ConflictException> { client.delete(c) }
        client.delete(c, recursive = true)
        assertFailsWith<NotFoundException> { client.read(h) }
        Unit
    }
}
