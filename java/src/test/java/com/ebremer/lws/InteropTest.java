// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ebremer.lws.access.AccessGrant;
import com.ebremer.lws.access.AccessPolicy;
import com.ebremer.lws.access.AccessRequest;
import com.ebremer.lws.access.AccessTarget;
import com.ebremer.lws.access.Constraint;
import com.ebremer.lws.auth.KeyPairs;
import com.ebremer.lws.auth.SelfSignedCredentials;
import com.ebremer.lws.auth.TokenExchangeAuthenticator;
import com.ebremer.lws.index.TypeQuery;
import com.ebremer.lws.notify.Notification;
import com.ebremer.lws.notify.Subscription;
import com.ebremer.lws.notify.VerifiedNotification;
import com.ebremer.lws.notify.WebhookSubscriptionRequest;
import com.ebremer.lws.notify.WebhookVerifier;
import com.ebremer.lws.patch.JsonPatch;
import com.ebremer.lws.patch.JsonPointer;
import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

/** The cross-language interop scenario ({@code conformance/scenario.md}) against the LWS mock server. */
@EnabledIfEnvironmentVariable(named = "LWS_TEST_SERVER", matches = ".+")
class InteropTest {

    private record Delivery(String method, Map<String, List<String>> headers, byte[] body) {}

    @Test
    void scenario() throws Exception {
        String base = System.getenv("LWS_TEST_SERVER").replaceAll("/+$", "");
        SelfSignedCredentials creds = SelfSignedCredentials.didKey(KeyPairs.generateP256());
        LwsClient client = LwsClient.builder().authenticator(TokenExchangeAuthenticator.of(creds)).build();

        // 1. Authenticate + discover
        StorageDescription sd = client.discoverStorage(URI.create(base + "/root/"));
        assertEquals(URI.create(base + "/root/"), sd.storageRoot());
        URI notifications = sd.notificationService().orElseThrow().serviceEndpoint();
        URI requests = sd.accessRequestService().orElseThrow().serviceEndpoint();
        URI grants = sd.accessGrantService().orElseThrow().serviceEndpoint();
        URI typeIndex = sd.typeIndexService().orElseThrow().serviceEndpoint();
        URI typeSearch = sd.typeSearchService().orElseThrow().serviceEndpoint();
        // An Ed25519 (EdDSA) did:key agent authenticates as well.
        LwsClient ed = LwsClient.builder()
                .authenticator(TokenExchangeAuthenticator.of(SelfSignedCredentials.didKey(KeyPairs.generateEd25519())))
                .build();
        assertTrue(ed.head(sd.storageRoot()).isContainer());

        // 2. Container
        String name = "interop-java-" + System.currentTimeMillis();
        URI c = client.createContainer(sd.storageRoot(), CreateOptions.slug(name)).location();

        // 3-4. Text resource
        URI h = client.create(c, Body.of("Hello, LWS!"), "text/plain", CreateOptions.slug("hello.txt")).location();
        Resource r = client.read(h);
        assertEquals("Hello, LWS!", r.text());
        String etag = r.etag().orElseThrow();
        assertTrue(r.metadata().isDataResource());
        assertEquals(c, r.metadata().parent().orElseThrow());
        assertTrue(r.metadata().linkset().isPresent());
        assertEquals(URI.create(base + "/"), r.metadata().storage().orElseThrow());

        // 5. Conditional read
        assertTrue(client.read(h, ReadOptions.ifNoneMatch(etag)).notModified());

        // 6. Update + stale update
        client.update(h, Body.of("Hello again"), "text/plain", UpdateOptions.ifMatch(etag));
        assertThrows(PreconditionFailedException.class,
                () -> client.update(h, Body.of("stale"), "text/plain", UpdateOptions.ifMatch(etag)));

        // 7. JSON + patch
        URI p = client.createJson(c, Map.of("name", "Alice", "age", 30),
                CreateOptions.builder().slug("profile.json").type("https://schema.org/Person").build()).location();
        client.patch(p, JsonPatch.builder().replace("/age", 31).add("/city", "Boston").build());
        JsonNode profile = client.read(p).json();
        assertEquals(31, profile.get("age").asInt());
        assertEquals("Boston", profile.get("city").asText());
        assertEquals("Alice", profile.get("name").asText());

        // 8. Linkset
        LinksetDocument ls = client.readLinkset(p);
        client.patchLinkset(ls.url(), JsonPatch.builder()
                        .add(JsonPointer.of("linkset", "0", "describedby"), List.of(Map.of("href", "https://example.org/shapes/person")))
                        .build(),
                ls.etag().map(UpdateOptions::ifMatch).orElse(UpdateOptions.DEFAULT));
        assertTrue(client.readLinkset(p).linkset().targets("describedby").stream()
                .anyMatch(t -> t.href().equals("https://example.org/shapes/person")));

        // 9. Pagination
        for (int i = 0; i < 6; i++) client.create(c, Body.of("item " + i), "text/plain", CreateOptions.slug("item" + i + ".txt"));
        ContainerPage first = client.readContainer(c);
        assertEquals(8, first.totalItems().orElseThrow());
        assertTrue(first.next().isPresent());
        List<URI> members = client.listContainer(c).map(ContainedResource::id).toList();
        assertEquals(8, members.size());
        assertTrue(members.contains(h) && members.contains(p));

        // 10. Type index / search
        assertTrue(client.listTypes(typeIndex).anyMatch("https://schema.org/Person"::equals));
        assertTrue(client.searchAll(typeSearch, TypeQuery.allOf("https://schema.org/Person")).anyMatch(i -> i.id().equals(p)));
        assertTrue(client.acceptedQueryFormats(typeSearch).contains(Lws.MediaType.LWS_QUERY_JSON));

        // 11. Notifications
        BlockingQueue<Delivery> inbox = new LinkedBlockingQueue<>();
        HttpServer receiver = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        receiver.createContext("/inbox", ex -> {
            byte[] body = ex.getRequestBody().readAllBytes();
            inbox.add(new Delivery(ex.getRequestMethod(), new HashMap<>(ex.getRequestHeaders()), body));
            ex.sendResponseHeaders(204, -1);
            ex.close();
        });
        receiver.start();
        try {
            URI inboxUrl = URI.create("http://127.0.0.1:" + receiver.getAddress().getPort() + "/inbox");
            Subscription sub = client.subscribe(sd, WebhookSubscriptionRequest.of(inboxUrl, c));
            client.update(h, Body.of("Hello, notifications"), "text/plain");
            WebhookVerifier verifier = WebhookVerifier.builder().trustedStorages(List.of(sd.id())).build();
            boolean seenUpdate = false;
            long deadline = System.currentTimeMillis() + 5000;
            while (!seenUpdate && System.currentTimeMillis() < deadline) {
                Delivery d = inbox.poll(Math.max(1, deadline - System.currentTimeMillis()), TimeUnit.MILLISECONDS);
                if (d == null) break;
                VerifiedNotification vn = verifier.verify(d.method(), inboxUrl, d.headers(), d.body());
                for (Notification.Activity a : vn.notification().activities()) {
                    if (a.isUpdate() && a.object().id().equals(h)) seenUpdate = true;
                }
            }
            assertTrue(seenUpdate, "verified Update notification for " + h);
            assertTrue(client.listSubscriptions(notifications).anyMatch(i -> i.id().equals(sub.subscription())));
            client.unsubscribe(sub.subscription());
        } finally {
            receiver.stop(0);
        }

        // 12. Access requests and grants
        AccessRequest req = AccessRequest.builder()
                .storage(sd.id())
                .access(AccessPolicy.builder().actions(Lws.Access.ACTION_READ).assignee(creds.agent())
                        .target(AccessTarget.storageResources(c))
                        .constraint(Constraint.purpose(URI.create("https://purpose.example/interop"))).build())
                .build();
        URI reqUrl = client.requestAccess(requests, req);
        AccessRequest fetched = client.getAccessRequest(reqUrl);
        assertEquals(req.access(), fetched.access());
        assertTrue(client.listAccessRequests(requests).anyMatch(i -> i.id().equals(reqUrl)));
        URI grantUrl = client.grantAccess(grants, AccessGrant.approving(req));
        assertNotNull(client.getAccessGrant(grantUrl));
        client.revokeAccessGrant(grantUrl);
        client.cancelAccessRequest(reqUrl);

        // 13. Delete
        assertThrows(ConflictException.class, () -> client.delete(c));
        client.delete(c, DeleteOptions.recursive());
        assertThrows(NotFoundException.class, () -> client.read(h));
    }
}
