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
import com.ebremer.lws.auth.AccessToken;
import com.ebremer.lws.auth.AuthorizationServerMetadata;
import com.ebremer.lws.http.ProblemDetails;
import com.ebremer.lws.index.TypeIndexPage;
import com.ebremer.lws.internal.Json;
import com.ebremer.lws.internal.Uris;
import com.ebremer.lws.notify.Notification;
import com.ebremer.lws.notify.Subscription;
import com.ebremer.lws.notify.WebhookSubscriptionRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** Model parsing tests driven by {@code conformance/fixtures/responses}. */
class ModelFixturesTest {

    static HttpHeaders headers(JsonNode h) {
        Map<String, List<String>> map = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> it = h.properties().iterator();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> e = it.next();
            List<String> values = new ArrayList<>();
            if (e.getValue().isArray()) e.getValue().forEach(v -> values.add(v.asText()));
            else values.add(e.getValue().asText());
            map.put(e.getKey(), values);
        }
        return HttpHeaders.of(map, (a, b) -> true);
    }

    static ResourceMetadata metadata(JsonNode response) {
        return ResourceMetadata.of(URI.create(response.get("url").asText()), response.path("status").asInt(200), headers(response.get("headers")));
    }

    private static Optional<String> opt(JsonNode n) {
        return n == null || n.isNull() ? Optional.empty() : Optional.of(n.asText());
    }

    @Test
    void storageDescription() {
        JsonNode f = Fixtures.json("responses/storage-description.json");
        StorageDescription d = StorageDescription.parse(f.get("body"), URI.create(f.get("url").asText()));
        JsonNode e = f.get("expected");
        assertEquals(e.get("id").asText(), d.id().toString());
        assertEquals(List.of("Storage"), d.types());
        assertEquals(e.get("storageRoot").asText(), d.storageRoot().toString());
        assertEquals(e.get("notificationService").asText(), d.notificationService().orElseThrow().serviceEndpoint().toString());
        assertEquals(List.of("WebhookSubscription"), d.notificationService().orElseThrow().subscriptionTypes());
        assertEquals(e.get("typeIndexService").asText(), d.typeIndexService().orElseThrow().serviceEndpoint().toString());
        assertEquals(e.get("typeSearchService").asText(), d.typeSearchService().orElseThrow().serviceEndpoint().toString());
        assertEquals(e.get("accessRequestService").asText(), d.accessRequestService().orElseThrow().serviceEndpoint().toString());
        assertEquals(e.get("accessGrantService").asText(), d.accessGrantService().orElseThrow().serviceEndpoint().toString());
        assertEquals(List.of(Lws.ACCESS_PROFILE), d.accessGrantService().orElseThrow().conformsTo());
        assertEquals(e.get("serviceCount").asInt(), d.services().size());
        assertEquals(List.of("https://feature.example/PatchSupport", "https://feature.example/ResumableUploads"),
                d.capabilities().stream().map(c -> c.types().get(0)).toList());
        StorageDescription.Service custom = d.service("DataSharingService").orElseThrow();
        assertEquals(e.get("customService").get("id").asText(), custom.id().orElseThrow().toString());
        assertEquals(e.get("customService").get("serviceEndpoint").asText(), custom.serviceEndpoint().toString());

        JsonNode invalid = f.get("invalid");
        assertThrows(LwsProtocolException.class, () -> StorageDescription.parse(invalid.get("notStorage"), URI.create("https://storage.example/")));
        StorageDescription noRoot = StorageDescription.parse(invalid.get("noRoot"), URI.create("https://storage.example/"));
        assertThrows(LwsProtocolException.class, noRoot::storageRoot);
    }

    @Test
    void containerPage() {
        JsonNode f = Fixtures.json("responses/container-page.json");
        ResourceMetadata md = metadata(f);
        ContainerPage page = ContainerPage.parse((ObjectNode) f.get("body"), md);
        JsonNode e = f.get("expected");
        assertEquals(e.get("id").asText(), page.id().orElseThrow().toString());
        assertTrue(page.isContainer());
        assertEquals(e.get("totalItems").asLong(), page.totalItems().orElseThrow());
        assertEquals(e.get("etag").asText(), page.etag().orElseThrow());
        assertEquals(e.get("linkset").asText(), md.linkset().orElseThrow().toString());
        assertEquals(e.get("parent").asText(), md.parent().orElseThrow().toString());
        assertEquals(e.get("storage").asText(), md.storage().orElseThrow().toString());
        assertEquals(opt(e.get("first")), page.first().map(URI::toString));
        assertEquals(opt(e.get("next")), page.next().map(URI::toString));
        assertEquals(opt(e.get("prev")), page.prev().map(URI::toString));
        assertEquals(opt(e.get("last")), page.last().map(URI::toString));
        assertEquals(e.get("items").size(), page.items().size());
        for (int i = 0; i < page.items().size(); i++) {
            ContainedResource item = page.items().get(i);
            JsonNode ei = e.get("items").get(i);
            assertEquals(ei.get("id").asText(), item.id().toString());
            assertEquals(ei.get("isContainer").asBoolean(), item.isContainer());
            assertEquals(ei.get("isDataResource").asBoolean(), item.isDataResource());
            assertEquals(opt(ei.get("format")), item.format());
            assertEquals(ei.get("size") == null || ei.get("size").isNull() ? null : ei.get("size").asLong(),
                    item.size().isPresent() ? item.size().getAsLong() : null);
            if (ei.has("modified") && !ei.get("modified").isNull()) {
                assertEquals(Instant.parse(ei.get("modified").asText()), item.modified().orElseThrow());
            } else {
                assertTrue(item.modified().isEmpty());
            }
            if (ei.has("modifiedRaw")) assertEquals(ei.get("modifiedRaw").asText(), item.modifiedRaw().orElseThrow());
            List<String> types = new ArrayList<>();
            ei.get("types").forEach(t -> types.add(t.asText()));
            assertEquals(types, item.types());
            if (ei.has("hasType")) assertTrue(item.hasType(ei.get("hasType").asText()));
        }
    }

    @Test
    void linkset() {
        JsonNode f = Fixtures.json("responses/linkset.json");
        ResourceMetadata md = metadata(f);
        Linkset ls = Linkset.parse(f.get("body"));
        LinksetDocument doc = new LinksetDocument(md.url(), ls, md);
        JsonNode e = f.get("expected");
        assertEquals(e.get("etag").asText(), doc.etag().orElseThrow());
        assertEquals(List.of("GET", "HEAD", "PUT", "PATCH"), doc.allow());
        assertTrue(doc.supportsPut());
        assertEquals(List.of("application/json-patch+json"), doc.acceptPatch());
        assertEquals(e.get("contexts").asInt(), ls.contexts().size());
        assertEquals(e.get("anchor").asText(), ls.contexts().get(0).anchor());
        assertEquals(e.get("linkCount").asInt(), ls.links().size());
        e.get("targets").properties().forEach(t -> {
            List<String> hrefs = ls.targets(t.getKey()).stream().map(Linkset.LinkTarget::href).toList();
            List<String> exp = new ArrayList<>();
            t.getValue().forEach(x -> exp.add(x.asText()));
            assertEquals(exp, hrefs);
        });
        assertEquals(f.get("body"), ls.toJson(), "round trip");
        JsonNode op = e.get("afterAdd").get("operation");
        Linkset added = ls.add(op.get("anchor").asText(), op.get("rel").asText(), op.get("href").asText(), Map.of());
        List<String> exp = new ArrayList<>();
        e.get("afterAdd").get("licenseTargets").forEach(x -> exp.add(x.asText()));
        assertEquals(exp, added.targets(op.get("anchor").asText(), "license").stream().map(Linkset.LinkTarget::href).toList());
        assertEquals(f.get("body"), ls.toJson(), "original unchanged");
        Linkset removed = added.remove(op.get("anchor").asText(), "license", "https://example.org/license-2");
        assertEquals(f.get("body"), removed.toJson());
    }

    @Test
    void notifications() {
        JsonNode f = Fixtures.json("responses/notification.json");
        for (String which : List.of("single", "batch")) {
            Notification n = Notification.parse(f.get(which));
            JsonNode e = f.get(which + "Expected");
            assertEquals(e.get("storage").asText(), n.storage().toString());
            assertEquals(e.get("activities").size(), n.activities().size());
            for (int i = 0; i < n.activities().size(); i++) {
                Notification.Activity a = n.activities().get(i);
                JsonNode ea = e.get("activities").get(i);
                assertEquals(ea.get("id").asText(), a.id());
                List<String> types = new ArrayList<>();
                ea.get("types").forEach(t -> types.add(t.asText()));
                assertEquals(types, a.types());
                assertEquals(ea.get("objectId").asText(), a.object().id().toString());
                if (ea.has("isCreate")) assertTrue(a.isCreate());
                if (ea.has("isUpdate")) assertTrue(a.isUpdate());
                if (ea.has("isDelete")) assertTrue(a.isDelete());
                if (ea.has("objectTypes")) assertEquals(ea.get("objectTypes").get(0).asText(), a.object().types().get(0));
                if (ea.has("target")) assertEquals(ea.get("target").asText(), a.target().orElseThrow().toString());
                if (ea.has("origin")) assertEquals(ea.get("origin").asText(), a.origin().orElseThrow().toString());
                if (ea.has("actor")) assertEquals(ea.get("actor").asText(), a.actor().orElseThrow().toString());
                if (ea.has("published")) assertEquals(Instant.parse(ea.get("published").asText()), a.published().orElseThrow());
            }
        }
        assertThrows(LwsProtocolException.class, () -> Notification.parse(f.get("invalid")));
    }

    @Test
    void accessDocuments() {
        JsonNode f = Fixtures.json("responses/access.json");
        AccessRequest req = AccessRequest.parse(f.get("request"));
        assertEquals(URI.create("https://storage.example/"), req.storage());
        assertEquals(List.of("read", "create"), req.access().get(0).actions());
        assertEquals("StorageResource", req.access().get(0).target().orElseThrow().type());
        assertEquals(2, req.access().get(0).constraints().size());
        assertEquals(f.get("request"), req.toJson(), "parsed request round-trips");

        AccessGrant grant = AccessGrant.parse(f.get("grant"));
        assertEquals("isAnyOf", grant.access().get(0).constraints().get(0).operator());
        assertEquals(f.get("grant"), grant.toJson());
        assertThrows(LwsProtocolException.class, () -> AccessGrant.parse(f.get("request")));

        AccessRequest built = AccessRequest.builder()
                .storage(URI.create("https://storage.example/"))
                .inbox(URI.create("https://id.example/agent/inbox/"))
                .access(AccessPolicy.builder()
                        .actions(Lws.Access.ACTION_READ, Lws.Access.ACTION_CREATE)
                        .assignee(URI.create("https://id.example/agent"))
                        .target(AccessTarget.storageResources(URI.create("https://storage.example/root/projects/")))
                        .constraint(Constraint.purpose(URI.create("https://purpose.example/collaboration")))
                        .constraint(Constraint.notAfter(Instant.parse("2026-06-09T10:00:00Z")))
                        .build())
                .build();
        assertEquals(f.get("request"), built.toJson());
        AccessGrant approved = AccessGrant.approving(built);
        assertEquals(List.of("AccessGrant"), approved.types());

        // A malformed document from the server is a protocol error, not an argument error.
        ObjectNode badStorage = f.get("request").deepCopy();
        badStorage.put("storage", "not a uri");
        assertThrows(LwsProtocolException.class, () -> AccessRequest.parse(badStorage));
        ObjectNode noAction = f.get("grant").deepCopy();
        ((ObjectNode) noAction.withArray("access").get(0)).putArray("action");
        assertThrows(LwsProtocolException.class, () -> AccessGrant.parse(noAction));
    }

    @Test
    void typeIndexAndSearch() {
        JsonNode f = Fixtures.json("responses/type-index.json");
        JsonNode ti = f.get("typeIndex");
        TypeIndexPage page = TypeIndexPage.parse((ObjectNode) ti.get("body"), metadata(ti));
        assertEquals(ti.get("expected").get("totalItems").asLong(), page.totalItems().orElseThrow());
        assertEquals(List.of("https://schema.org/Person", "https://schema.org/Event", "https://schema.org/Message"), page.types());
        assertEquals(ti.get("expected").get("next").asText(), page.next().orElseThrow().toString());

        JsonNode s = f.get("search");
        ContainerPage results = ContainerPage.parse((ObjectNode) s.get("body"), metadata(s));
        assertEquals(27, results.totalItems().orElseThrow());
        List<String> ids = new ArrayList<>();
        s.get("expected").get("ids").forEach(x -> ids.add(x.asText()));
        assertEquals(ids, results.items().stream().map(i -> i.id().toString()).toList());
        assertEquals(s.get("expected").get("next").asText(), results.next().orElseThrow().toString());
        assertTrue(results.hasType("ContainerPage"));
        // The body names no id: the page's own URL stands in.
        assertEquals(URI.create(s.get("url").asText()), results.id().orElseThrow());
    }

    @Test
    void oauth() {
        JsonNode f = Fixtures.json("responses/oauth.json");
        AuthorizationServerMetadata md = AuthorizationServerMetadata.parse(f.get("metadata"), URI.create("https://authorization.example/.well-known/lws-configuration"));
        assertEquals("https://authorization.example", md.issuer());
        assertEquals(URI.create("https://authorization.example/token"), md.tokenEndpoint());
        assertTrue(md.supportsSubjectTokenType(Lws.TokenType.JWT));
        assertFalse(md.supportsSubjectTokenType(Lws.TokenType.SAML2));
        for (JsonNode m : f.get("metadataUrls")) {
            assertEquals(m.get("url").asText(), AuthorizationServerMetadata.metadataUrl(URI.create(m.get("issuer").asText())).toString());
        }
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        AccessToken t = AccessToken.fromTokenResponse(f.get("tokenResponse").get("body"), now);
        assertEquals(now.plusSeconds(f.get("tokenResponse").get("expectedExpiresIn").asLong()), t.expiresAt());
        AccessToken t2 = AccessToken.fromTokenResponse(f.get("tokenResponseNoExpiry").get("body"), now);
        assertEquals(Instant.ofEpochSecond(f.get("tokenResponseNoExpiry").get("expectedExp").asLong()), t2.expiresAt());
        for (JsonNode c : f.get("realmChecks")) {
            assertEquals(c.get("contained").asBoolean(), Uris.contains(URI.create(c.get("realm").asText()), URI.create(c.get("url").asText())),
                    c.toString());
        }
    }

    @Test
    void problemDetails() {
        JsonNode f = Fixtures.json("responses/problem-details.json");
        HttpStatusException ex = HttpStatusException.of("DELETE", URI.create("https://storage.example/alice/notes/"),
                f.get("status").asInt(), headers(f.get("headers")), Json.toBytes(f.get("body")));
        assertInstanceOf(ConflictException.class, ex);
        ProblemDetails p = ex.problem().orElseThrow();
        JsonNode e = f.get("expected");
        assertEquals(e.get("type").asText(), p.type().orElseThrow());
        assertEquals(e.get("title").asText(), p.title().orElseThrow());
        assertEquals(e.get("detail").asText(), p.detail().orElseThrow());
        assertEquals(e.get("instance").asText(), p.instance().orElseThrow());
        assertEquals(409, p.status().getAsInt());
        assertEquals(3, p.extensions().get("itemCount").asInt());
    }

    @Test
    void subscription() {
        JsonNode f = Fixtures.json("responses/subscription.json");
        JsonNode in = f.get("input");
        WebhookSubscriptionRequest req = new WebhookSubscriptionRequest(
                List.of(URI.create(in.get("topics").get(0).asText()), URI.create(in.get("topics").get(1).asText())),
                URI.create(in.get("inbox").asText()), Optional.of(Instant.parse(in.get("expires").asText())));
        assertEquals(f.get("expectedRequestBody"), req.toJson());
        JsonNode resp = f.get("response");
        Subscription s = Subscription.parse(resp.get("body"), URI.create("https://notification.example/subscriptions"), null);
        assertEquals(f.get("expected").get("type").asText(), s.type());
        assertEquals(f.get("expected").get("subscription").asText(), s.subscription().toString());
        assertEquals(Instant.parse(f.get("expected").get("expires").asText()), s.expires().orElseThrow());
    }

    @Test
    void uriResolution() {
        URI base = URI.create("https://example.org/dir/doc?x=1");
        assertEquals("https://example.org/dir/doc?page=2", Uris.resolve(base, "?page=2").toString());
        assertEquals("https://example.org/dir/doc?x=1", Uris.resolve(base, "").toString());
        assertEquals("https://example.org/dir/doc?x=1#f", Uris.resolve(base, "#f").toString());
        assertEquals("https://example.org/a", Uris.resolve(base, "../a").toString());
        assertEquals("https://example.org/g", Uris.resolve(base, "/./g").toString());
        assertEquals("https://other.example/p", Uris.resolve(base, "//other.example/p").toString());
    }
}
