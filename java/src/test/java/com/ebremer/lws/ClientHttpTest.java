// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ebremer.lws.access.AccessGrant;
import com.ebremer.lws.access.AccessPolicy;
import com.ebremer.lws.access.AccessRequest;
import com.ebremer.lws.access.AccessTarget;
import com.ebremer.lws.access.Constraint;
import com.ebremer.lws.auth.BearerTokenAuthenticator;
import com.ebremer.lws.auth.Jwt;
import com.ebremer.lws.auth.KeyPairs;
import com.ebremer.lws.auth.SelfSignedCredentials;
import com.ebremer.lws.auth.TokenExchangeAuthenticator;
import com.ebremer.lws.http.Link;
import com.ebremer.lws.index.TypeQuery;
import com.ebremer.lws.notify.Subscription;
import com.ebremer.lws.notify.WebhookSubscriptionRequest;
import com.ebremer.lws.patch.JsonPatch;
import com.ebremer.lws.patch.JsonPointer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.InputStream;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** End-to-end client tests against the in-process {@link MockLwsServer}. */
class ClientHttpTest {
    private MockLwsServer server;
    private SelfSignedCredentials credentials;
    private LwsClient client;

    @BeforeEach
    void start() throws Exception {
        server = new MockLwsServer(true, 2);
        credentials = SelfSignedCredentials.didKey(KeyPairs.generateP256());
        client = LwsClient.builder().authenticator(TokenExchangeAuthenticator.of(credentials)).build();
    }

    @AfterEach
    void stop() {
        server.close();
    }

    @Test
    void discoveryRunsTheTokenExchangeFlow() {
        StorageDescription sd = client.discoverStorage(server.uri("/root/"));
        assertEquals(server.uri("/root/"), sd.storageRoot());
        assertEquals(server.uri("/"), sd.id());
        assertTrue(sd.notificationService().isPresent());
        assertEquals(1, server.tokenRequests.get());
        assertEquals(1, server.metadataRequests.get(), "metadata at RFC 8414 path-inserted URL");
        // the subject token is the self-signed did:key credential for this AS
        ObjectNode claims = Jwt.claims(server.lastSubjectToken);
        assertEquals(credentials.agent().toString(), claims.get("sub").asText());
        assertEquals(server.base + "/as", claims.get("aud").get(0).asText());
    }

    @Test
    void anonymousDiscoveryUsesTheStorageLinkOn401() {
        StorageDescription sd = LwsClient.create().discoverStorage(server.uri("/root/"));
        assertEquals(server.uri("/root/"), sd.storageRoot());
    }

    @Test
    void tokenIsReusedProactively() {
        client.head(server.uri("/root/"));
        int before = server.requestLog.size();
        for (int i = 0; i < 5; i++) client.readContainer(server.uri("/root/"));
        assertEquals(1, server.tokenRequests.get());
        assertEquals(before + 5, server.requestLog.size(), "no extra 401 round trips");
        assertTrue(server.lastHeaders.get("GET /root/").get("Authorization").get(0).startsWith("Bearer tok-"));
    }

    @Test
    void expiredOrRevokedTokenIsReplacedOnce() {
        client.head(server.uri("/root/"));
        server.tokens.clear(); // server forgets tokens (e.g. revoked)
        client.head(server.uri("/root/"));
        assertEquals(2, server.tokenRequests.get());
    }

    @Test
    void realmMustContainTheRequestUri() {
        AuthenticationException e = assertThrows(AuthenticationException.class, () -> client.read(server.uri("/elsewhere/x")));
        assertTrue(e.getMessage().contains("realm"));
        assertEquals(0, server.tokenRequests.get(), "no credential was sent");
    }

    @Test
    void untrustedAuthorizationServerIsRejected() {
        LwsClient c = LwsClient.builder().authenticator(TokenExchangeAuthenticator.builder(credentials)
                .authorizationServerFilter((as, realm) -> as.getHost().equals("as.example")).build()).build();
        assertThrows(AuthenticationException.class, () -> c.head(server.uri("/root/")));
        assertEquals(0, server.tokenRequests.get());
    }

    @Test
    void anonymousRequestsFailWithUnauthorized() {
        UnauthorizedException e = assertThrows(UnauthorizedException.class, () -> LwsClient.create().read(server.uri("/root/")));
        assertEquals(server.uri("/as"), e.challenges().get(0).asUri().orElseThrow());
    }

    @Test
    void crudLifecycle() {
        URI root = server.uri("/root/");
        CreateResult folder = client.createContainer(root, CreateOptions.slug("notes"));
        assertEquals(server.uri("/root/notes/"), folder.location());
        assertTrue(folder.metadata().isContainer());
        assertEquals("<" + Lws.Type.CONTAINER + ">; rel=\"type\"", server.lastHeaders.get("POST /root/").get("Link").get(0));

        CreateResult text = client.create(folder.location(), Body.of("Hello, LWS!"), "text/plain",
                CreateOptions.builder().slug("hello.txt").link(Link.of("https://example.org/license", "license")).build());
        assertEquals(server.uri("/root/notes/hello.txt"), text.location());
        assertEquals("hello.txt", server.lastHeaders.get("POST /root/notes/").get("Slug").get(0));
        assertEquals(server.uri("/root/notes/hello.txt.meta"), text.linkset().orElseThrow());

        Resource r = client.read(text.location());
        assertEquals("Hello, LWS!", r.text());
        assertTrue(r.metadata().isDataResource());
        assertEquals(folder.location(), r.metadata().parent().orElseThrow());
        assertEquals(server.uri("/"), r.metadata().storage().orElseThrow());
        String etag = r.etag().orElseThrow();

        Resource same = client.read(text.location(), ReadOptions.ifNoneMatch(etag));
        assertTrue(same.notModified());
        assertEquals(0, same.bytes().length);

        Resource part = client.read(text.location(), ReadOptions.builder().range(0, 4L).build());
        assertEquals(206, part.status());
        assertEquals("Hello", part.text());
        assertEquals("bytes 0-4/11", part.contentRange().orElseThrow());

        UpdateResult u = client.update(text.location(), Body.of("Hello again"), "text/plain", UpdateOptions.ifMatch(etag));
        assertEquals(204, u.status());
        assertThrows(PreconditionFailedException.class,
                () -> client.update(text.location(), Body.of("stale"), "text/plain", UpdateOptions.ifMatch(etag)));
        assertEquals("Hello again", client.read(text.location()).text());

        try (ResourceStream s = client.readStream(text.location())) {
            assertEquals("Hello again", new String(s.body().readAllBytes()));
        } catch (java.io.IOException e) {
            throw new AssertionError(e);
        }

        ConflictException conflict = assertThrows(ConflictException.class, () -> client.delete(folder.location()));
        assertEquals(409, conflict.status());
        client.delete(folder.location(), DeleteOptions.recursive());
        assertEquals("infinity", server.lastHeaders.get("DELETE /root/notes/").get("Depth").get(0));
        assertThrows(NotFoundException.class, () -> client.read(text.location()));
    }

    @Test
    void jsonPatchAndLinksets() {
        CreateResult p = client.createJson(server.uri("/root/"), Map.of("name", "Alice", "age", 30),
                CreateOptions.builder().slug("profile.json").type("https://schema.org/Person").build());
        Resource before = client.read(p.location());
        client.patch(p.location(), JsonPatch.builder().replace("/age", 31).add("/city", "Boston").build(),
                UpdateOptions.ifMatch(before.etag().orElseThrow()));
        JsonNode after = client.read(p.location()).json();
        assertEquals(31, after.get("age").asInt());
        assertEquals("Boston", after.get("city").asText());
        assertEquals(Lws.MediaType.JSON_PATCH, server.lastHeaders.get("PATCH /root/profile.json").get("Content-Type").get(0));
        assertTrue(client.head(p.location()).hasType("https://schema.org/Person"));

        UnsupportedMediaTypeException ume = assertThrows(UnsupportedMediaTypeException.class,
                () -> client.patch(p.location(), Body.of("x"), "application/sparql-update", UpdateOptions.DEFAULT));
        assertEquals(List.of(Lws.MediaType.JSON_PATCH), ume.acceptPatch());

        LinksetDocument ls = client.readLinkset(p.location());
        assertEquals(server.uri("/root/profile.json.meta"), ls.url());
        assertEquals(p.location().toString(), ls.linkset().contexts().get(0).anchor());
        String pointer = JsonPointer.of("linkset", "0", "describedby");
        client.patchLinkset(ls.url(), JsonPatch.builder()
                .add(pointer, List.of(Map.of("href", "https://example.org/shapes/person"))).build(),
                UpdateOptions.ifMatch(ls.etag().orElseThrow()));
        LinksetDocument again = client.readLinkset(p.location());
        assertEquals("https://example.org/shapes/person", again.linkset().targets("describedby").get(0).href());
        assertThrows(PreconditionFailedException.class, () -> client.patchLinkset(ls.url(),
                JsonPatch.builder().remove(pointer).build(), UpdateOptions.ifMatch(ls.etag().orElseThrow())));
    }

    @Test
    void paginationAcrossThreePagesIsLazy() {
        URI root = server.uri("/root/");
        IntStream.range(0, 5).forEach(i -> client.create(root, Body.of("item " + i), "text/plain", CreateOptions.slug("item" + i + ".txt")));
        ContainerPage first = client.readContainer(root);
        assertEquals(5, first.totalItems().orElseThrow());
        assertEquals(2, first.items().size());
        assertTrue(first.hasNext());
        assertEquals(server.uri("/root/?page=3"), first.last().orElseThrow());

        int before = server.requestLog.size();
        List<ContainedResource> firstTwo = client.listContainer(root).limit(2).toList();
        assertEquals(2, firstTwo.size());
        assertEquals(before + 1, server.requestLog.size(), "only the first page was fetched");

        List<URI> all = client.listContainer(root).map(ContainedResource::id).toList();
        assertEquals(5, all.size());
        assertEquals(server.uri("/root/item0.txt"), all.get(0));
        assertEquals(server.uri("/root/item4.txt"), all.get(4));
        assertTrue(client.listContainer(root).allMatch(ContainedResource::isDataResource));
    }

    @Test
    void asyncOperations() {
        URI root = server.uri("/root/");
        CreateResult c = client.createAsync(root, Body.of("async"), "text/plain", CreateOptions.slug("a.txt")).join();
        Resource r = client.readAsync(c.location()).join();
        assertEquals("async", r.text());
        assertEquals(1, server.tokenRequests.get());
        UpdateResult u = client.updateAsync(c.location(), Body.of("async2"), "text/plain", UpdateOptions.ifMatch(r.etag().orElseThrow())).join();
        assertEquals(204, u.status());
        assertEquals(1, client.readContainerAsync(root).join().items().size());
        client.deleteAsync(c.location(), DeleteOptions.DEFAULT).join();
        CompletionException e = assertThrows(CompletionException.class, () -> client.readAsync(c.location()).join());
        assertInstanceOf(NotFoundException.class, e.getCause());
        assertEquals(server.uri("/root/"), client.discoverStorageAsync(root).join().storageRoot());
    }

    @Test
    void asyncAuthenticationFlow() {
        CompletableFuture<ContainerPage> f = client.readContainerAsync(server.uri("/root/"));
        assertEquals(0, f.join().items().size());
        assertEquals(1, server.tokenRequests.get());
    }

    @Test
    void typeIndexAndSearch() {
        URI root = server.uri("/root/");
        client.createJson(root, Map.of("n", 1), CreateOptions.builder().slug("p1.json").type("https://schema.org/Person").build());
        client.createJson(root, Map.of("n", 2), CreateOptions.builder().slug("p2.json").type("https://schema.org/Person").build());
        client.createJson(root, Map.of("n", 3), CreateOptions.builder().slug("e1.json").type("https://schema.org/Event").build());
        assertTrue(client.listTypes(server.uri("/types/index")).toList().contains("https://schema.org/Person"));

        ContainerPage first = client.searchTypes(server.uri("/types/search"), TypeQuery.allOf("https://schema.org/Person"));
        assertEquals(2, first.totalItems().orElseThrow());
        List<URI> all = client.searchAll(server.uri("/types/search"), TypeQuery.allOf("https://schema.org/Person"))
                .map(ContainedResource::id).toList();
        assertEquals(List.of(server.uri("/root/p1.json"), server.uri("/root/p2.json")), all);
        assertTrue(server.requestLog.contains("GET /types/search?cursor=abc"), "next page dereferenced with GET");
        assertEquals(List.of("application/lws-query+json"), client.acceptedQueryFormats(server.uri("/types/search")));
        assertEquals(Lws.MediaType.LWS_QUERY_JSON, server.lastHeaders.get("QUERY /types/search").get("Content-Type").get(0));
    }

    @Test
    void notificationsSubscriptionLifecycle() {
        StorageDescription sd = client.discoverStorage(server.uri("/root/"));
        Subscription s = client.subscribe(sd, WebhookSubscriptionRequest.of(URI.create("https://receiver.example/hooks/lws"), sd.storageRoot())
                .withExpires(Instant.parse("2030-01-01T00:00:00Z")));
        assertEquals(Lws.Subscription.WEBHOOK, s.type());
        assertTrue(s.subscription().toString().startsWith(server.base + "/notifications/"));
        assertEquals(Instant.parse("2030-01-01T00:00:00Z"), s.expires().orElseThrow());
        assertEquals(1, client.listSubscriptions(sd.notificationService().orElseThrow().serviceEndpoint()).count());
        assertEquals(s.subscription(), client.getSubscription(s.subscription()).subscription());
        client.unsubscribe(s.subscription());
        assertEquals(0, client.listSubscriptions(sd.notificationService().orElseThrow().serviceEndpoint()).count());
    }

    @Test
    void accessRequestsAndGrants() {
        URI requests = server.uri("/access/requests/");
        AccessRequest req = AccessRequest.builder().storage(server.uri("/"))
                .access(AccessPolicy.builder().actions("read").assignee(credentials.agent())
                        .target(AccessTarget.containers(server.uri("/root/")))
                        .constraint(Constraint.purpose(URI.create("https://purpose.example/x"))).build())
                .build();
        URI created = client.requestAccess(requests, req);
        assertEquals(req.toJson(), client.getAccessRequest(created).toJson());
        assertEquals(List.of(created), client.listAccessRequests(requests).map(ContainedResource::id).toList());
        URI grant = client.grantAccess(server.uri("/access/grants/"), AccessGrant.approving(req));
        assertEquals(List.of("read"), client.getAccessGrant(grant).access().get(0).actions());
        client.revokeAccessGrant(grant);
        client.cancelAccessRequest(created);
        assertEquals(0, client.listAccessRequests(requests).count());
    }

    @Test
    void errorMappingWithProblemDetails() {
        ConflictException e = assertThrows(ConflictException.class, () -> client.read(server.uri("/problem")));
        assertEquals("Container not empty", e.problem().orElseThrow().title().orElseThrow());
        assertTrue(e.getMessage().contains("Container not empty"));
        assertThrows(NotFoundException.class, () -> client.head(server.uri("/root/missing")));
        assertThrows(MethodNotAllowedException.class, () -> client.update(server.uri("/root/"), Body.of("x"), "text/plain"));
    }

    @Test
    void redirectsAreFollowedAndReauthorized() {
        ContainerPage page = client.readContainer(server.uri("/redirect-me"));
        assertEquals(server.uri("/root/"), page.id().orElseThrow());
    }

    @Test
    void bearerTokenAuthenticatorIsScopedToItsRealm() {
        client.head(server.uri("/root/"));
        String token = server.tokens.iterator().next();
        LwsClient bearer = LwsClient.builder().authenticator(BearerTokenAuthenticator.of(token, server.uri("/"))).build();
        assertEquals(0, bearer.readContainer(server.uri("/root/")).items().size());
        LwsClient wrongRealm = LwsClient.builder().authenticator(BearerTokenAuthenticator.of(token, URI.create("https://elsewhere.example/"))).build();
        assertThrows(UnauthorizedException.class, () -> wrongRealm.readContainer(server.uri("/root/")));
    }

    @Test
    void lowLevelRequest() {
        Resource r = client.request("GET", server.uri("/"), Body.empty(), null, RequestOptions.header("Accept", "application/lws+cid"));
        assertEquals("application/lws+cid", r.contentType().orElseThrow());
        assertFalse(r.notModified());
        try (InputStream in = new java.io.ByteArrayInputStream(r.bytes())) {
            assertTrue(in.readAllBytes().length > 0);
        } catch (java.io.IOException e) {
            throw new AssertionError(e);
        }
    }
}
