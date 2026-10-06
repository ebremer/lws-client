// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.access.AccessGrant;
import com.ebremer.lws.access.AccessRequest;
import com.ebremer.lws.auth.Authenticator;
import com.ebremer.lws.http.Link;
import com.ebremer.lws.http.LinkHeader;
import com.ebremer.lws.index.TypeIndexPage;
import com.ebremer.lws.index.TypeQuery;
import com.ebremer.lws.internal.HeaderLists;
import com.ebremer.lws.internal.Json;
import com.ebremer.lws.notify.Subscription;
import com.ebremer.lws.notify.WebhookSubscriptionRequest;
import com.ebremer.lws.patch.JsonPatch;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * Client for the W3C Linked Web Storage (LWS) Protocol 1.0.
 *
 * <pre>{@code
 * LwsClient client = LwsClient.builder()
 *     .authenticator(TokenExchangeAuthenticator.of(SelfSignedCredentials.didKey(KeyPairs.generateP256())))
 *     .build();
 *
 * StorageDescription storage = client.discoverStorage(URI.create("https://storage.example/root/"));
 * CreateResult note = client.create(storage.storageRoot(), Body.of("Hello"), "text/plain", CreateOptions.slug("hello.txt"));
 * Resource r = client.read(note.location());
 * client.listContainer(storage.storageRoot()).forEach(item -> System.out.println(item.id()));
 * }</pre>
 *
 * <p>Instances are immutable and thread-safe. Blocking methods work well with virtual threads; the
 * {@code *Async} variants of the core operations return {@link CompletableFuture}s. Errors are reported
 * with unchecked {@link LwsException}s (for example {@link NotFoundException},
 * {@link PreconditionFailedException}, {@link ConflictException}).
 */
public final class LwsClient {
    /** Library version. */
    public static final String VERSION = "0.1.0";
    /** Default {@code User-Agent}. */
    public static final String DEFAULT_USER_AGENT = "lws-client-java/" + VERSION;

    private static final String ACCEPT_CONTAINER = Lws.MediaType.LWS_JSON + ", " + Lws.MediaType.LD_JSON + ";q=0.9, "
            + Lws.MediaType.JSON + ";q=0.8";
    private static final String ACCEPT_DESCRIPTION = Lws.MediaType.LWS_CID + ", " + Lws.MediaType.LD_JSON + ";q=0.9, "
            + Lws.MediaType.JSON + ";q=0.8";
    private static final DateTimeFormatter HTTP_DATE = DateTimeFormatter.RFC_1123_DATE_TIME.withZone(ZoneOffset.UTC);

    private final Pipeline pipeline;
    private final Builder settings;

    private LwsClient(Builder b) {
        this.settings = b.copy();
        HttpClient http = b.http != null ? b.http
                : HttpClient.newBuilder()
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .connectTimeout(b.connectTimeout)
                        .build();
        Executor executor = b.executor != null ? b.executor : DefaultExecutor.INSTANCE;
        this.pipeline = new Pipeline(http, b.authenticator, b.userAgent, RequestOptions.freeze(b.headers), b.timeout, executor);
    }

    /** A new builder. */
    public static Builder builder() {
        return new Builder();
    }

    /** An anonymous client with default settings. */
    public static LwsClient create() {
        return builder().build();
    }

    /** A copy of this client using another authenticator (sharing the underlying HTTP client). */
    public LwsClient withAuthenticator(Authenticator authenticator) {
        Builder b = settings.copy();
        b.http = pipeline.http();
        b.authenticator = authenticator;
        return new LwsClient(b);
    }

    /** The configured authenticator, if any. */
    public Optional<Authenticator> authenticator() {
        return Optional.ofNullable(pipeline.authenticator());
    }

    // ================================================================================================
    // Discovery
    // ================================================================================================

    /**
     * Finds the storage a resource belongs to (via its {@code rel="https://www.w3.org/ns/lws#storage"}
     * link) and retrieves the storage description.
     */
    public StorageDescription discoverStorage(URI resource) {
        HttpResponse<byte[]> resp = send("HEAD", resource, Body.empty(), Map.of(), null);
        if (resp.statusCode() == 405 || resp.statusCode() == 501) {
            resp = send("GET", resource, Body.empty(), Map.of(), null);
        }
        return getStorageDescription(storageLink(resp, resource));
    }

    /** Asynchronous {@link #discoverStorage(URI)}. */
    public CompletableFuture<StorageDescription> discoverStorageAsync(URI resource) {
        return sendAsync("HEAD", resource, Body.empty(), Map.of(), null)
                .thenCompose(resp -> resp.statusCode() == 405 || resp.statusCode() == 501
                        ? sendAsync("GET", resource, Body.empty(), Map.of(), null)
                        : CompletableFuture.completedFuture(resp))
                .thenCompose(resp -> getStorageDescriptionAsync(storageLink(resp, resource)));
    }

    private static URI storageLink(HttpResponse<byte[]> resp, URI resource) {
        ResourceMetadata md = ResourceMetadata.of(resp.uri(), resp.statusCode(), resp.headers());
        Optional<URI> storage = md.storage();
        // 401 responses SHOULD carry the storage link too, so anonymous discovery still works.
        if (storage.isPresent() && (resp.statusCode() / 100 == 2 || resp.statusCode() == 401)) return storage.get();
        check(resp, "HEAD");
        throw new LwsProtocolException("Response for " + resource + " has no storage link (rel=\"" + Lws.Rel.STORAGE + "\")");
    }

    /** Retrieves and parses a storage description ({@code application/lws+cid}). */
    public StorageDescription getStorageDescription(URI storage) {
        return parseDescription(send("GET", storage, Body.empty(), Map.of("Accept", List.of(ACCEPT_DESCRIPTION)), null));
    }

    /** Asynchronous {@link #getStorageDescription(URI)}. */
    public CompletableFuture<StorageDescription> getStorageDescriptionAsync(URI storage) {
        return sendAsync("GET", storage, Body.empty(), Map.of("Accept", List.of(ACCEPT_DESCRIPTION)), null)
                .thenApply(LwsClient::parseDescription);
    }

    private static StorageDescription parseDescription(HttpResponse<byte[]> resp) {
        check(resp, "GET");
        String ct = resp.headers().firstValue("content-type").orElse(null);
        if (ct != null && !HeaderLists.isJson(ct) && !Lws.MediaType.LWS_CID.equals(HeaderLists.essence(ct))) {
            throw new LwsProtocolException("Storage description has unexpected media type " + ct);
        }
        return StorageDescription.parse(Json.parse(resp.body()), resp.uri());
    }

    // ================================================================================================
    // Reading
    // ================================================================================================

    /** Retrieves a resource's metadata ({@code HEAD}). */
    public ResourceMetadata head(URI uri) {
        return head(uri, RequestOptions.DEFAULT);
    }

    /** Retrieves a resource's metadata ({@code HEAD}). */
    public ResourceMetadata head(URI uri, RequestOptions options) {
        HttpResponse<byte[]> resp = send("HEAD", uri, Body.empty(), options.headers(), options.timeout().orElse(null));
        check(resp, "HEAD");
        return metadata(resp);
    }

    /** Asynchronous {@link #head(URI)}. */
    public CompletableFuture<ResourceMetadata> headAsync(URI uri) {
        return sendAsync("HEAD", uri, Body.empty(), Map.of(), null).thenApply(resp -> {
            check(resp, "HEAD");
            return metadata(resp);
        });
    }

    /** Reads a resource. */
    public Resource read(URI uri) {
        return read(uri, ReadOptions.DEFAULT);
    }

    /**
     * Reads a resource. A conditional read answered {@code 304} returns a result with
     * {@link Resource#notModified()} set instead of throwing.
     */
    public Resource read(URI uri, ReadOptions options) {
        return toResource(send("GET", uri, Body.empty(), readHeaders(options), options.timeout().orElse(null)));
    }

    /** Asynchronous {@link #read(URI, ReadOptions)}. */
    public CompletableFuture<Resource> readAsync(URI uri, ReadOptions options) {
        return sendAsync("GET", uri, Body.empty(), readHeaders(options), options.timeout().orElse(null))
                .thenApply(LwsClient::toResource);
    }

    /** Asynchronous {@link #read(URI)}. */
    public CompletableFuture<Resource> readAsync(URI uri) {
        return readAsync(uri, ReadOptions.DEFAULT);
    }

    /** Reads a resource as a stream (for large content). Close the result. */
    public ResourceStream readStream(URI uri, ReadOptions options) {
        HttpResponse<InputStream> resp = pipeline.send(
                new Pipeline.Call("GET", uri, Body.empty(), readHeaders(options), options.timeout().orElse(null)),
                BodyHandlers.ofInputStream());
        int s = resp.statusCode();
        if (s == 304) {
            closeQuietly(resp.body());
            return new ResourceStream(metadata(resp), InputStream.nullInputStream(), true);
        }
        if (s / 100 != 2) {
            byte[] err;
            try (InputStream in = resp.body()) {
                err = in.readNBytes(4096);
            } catch (IOException e) {
                err = new byte[0];
            }
            throw HttpStatusException.of("GET", resp.uri(), s, resp.headers(), err);
        }
        return new ResourceStream(metadata(resp), resp.body(), false);
    }

    /** Reads a resource as a stream. */
    public ResourceStream readStream(URI uri) {
        return readStream(uri, ReadOptions.DEFAULT);
    }

    /** Reads one page of a container listing. */
    public ContainerPage readContainer(URI container) {
        return readContainer(container, ReadOptions.DEFAULT);
    }

    /** Reads one page of a container listing (also used for opaque pagination URIs). */
    public ContainerPage readContainer(URI container, ReadOptions options) {
        return toContainerPage(send("GET", container, Body.empty(), containerHeaders(options), options.timeout().orElse(null)), true);
    }

    /** Asynchronous {@link #readContainer(URI)}. */
    public CompletableFuture<ContainerPage> readContainerAsync(URI container) {
        return sendAsync("GET", container, Body.empty(), containerHeaders(ReadOptions.DEFAULT), null)
                .thenApply(resp -> toContainerPage(resp, true));
    }

    /**
     * All members of a container, fetched lazily page by page (following {@code rel="next"}).
     * Pages are requested as the stream is consumed.
     */
    public Stream<ContainedResource> listContainer(URI container) {
        return paginate(() -> readContainer(container), ContainerPage::next, this::readContainer, ContainerPage::items);
    }

    // ================================================================================================
    // Creating
    // ================================================================================================

    /** Creates a data resource in {@code container}. */
    public CreateResult create(URI container, Body body, String contentType) {
        return create(container, body, contentType, CreateOptions.DEFAULT);
    }

    /** Creates a data resource in {@code container}; the server assigns the URI (see {@link CreateResult#location()}). */
    public CreateResult create(URI container, Body body, String contentType, CreateOptions options) {
        Map<String, List<String>> h = createHeaders(options, null);
        h.put("Content-Type", List.of(Objects.requireNonNull(contentType, "contentType")));
        return toCreateResult(send("POST", container, body, h, options.timeout().orElse(null)));
    }

    /** Asynchronous {@link #create(URI, Body, String, CreateOptions)}. */
    public CompletableFuture<CreateResult> createAsync(URI container, Body body, String contentType, CreateOptions options) {
        Map<String, List<String>> h = createHeaders(options, null);
        h.put("Content-Type", List.of(Objects.requireNonNull(contentType, "contentType")));
        return sendAsync("POST", container, body, h, options.timeout().orElse(null)).thenApply(LwsClient::toCreateResult);
    }

    /** Creates a JSON data resource ({@code application/json}) from a Jackson node or serialisable value. */
    public CreateResult createJson(URI container, Object value, CreateOptions options) {
        return create(container, Body.ofJson(value), Lws.MediaType.JSON, options);
    }

    /** Creates a sub-container of {@code parent}. */
    public CreateResult createContainer(URI parent) {
        return createContainer(parent, CreateOptions.DEFAULT);
    }

    /** Creates a sub-container of {@code parent} ({@code Link: <…#Container>; rel="type"}). */
    public CreateResult createContainer(URI parent, CreateOptions options) {
        return toCreateResult(send("POST", parent, Body.empty(), createHeaders(options, Lws.Type.CONTAINER), options.timeout().orElse(null)));
    }

    /** Asynchronous {@link #createContainer(URI, CreateOptions)}. */
    public CompletableFuture<CreateResult> createContainerAsync(URI parent, CreateOptions options) {
        return sendAsync("POST", parent, Body.empty(), createHeaders(options, Lws.Type.CONTAINER), options.timeout().orElse(null))
                .thenApply(LwsClient::toCreateResult);
    }

    // ================================================================================================
    // Updating
    // ================================================================================================

    /** Replaces a resource's content ({@code PUT}). */
    public UpdateResult update(URI uri, Body body, String contentType) {
        return update(uri, body, contentType, UpdateOptions.DEFAULT);
    }

    /** Replaces a resource's content ({@code PUT}); use {@link UpdateOptions#ifMatch(String)} to avoid lost updates. */
    public UpdateResult update(URI uri, Body body, String contentType, UpdateOptions options) {
        return toUpdateResult(send("PUT", uri, body, updateHeaders(options, contentType), options.timeout().orElse(null)), "PUT");
    }

    /** Asynchronous {@link #update(URI, Body, String, UpdateOptions)}. */
    public CompletableFuture<UpdateResult> updateAsync(URI uri, Body body, String contentType, UpdateOptions options) {
        return sendAsync("PUT", uri, body, updateHeaders(options, contentType), options.timeout().orElse(null))
                .thenApply(r -> toUpdateResult(r, "PUT"));
    }

    /** Applies a JSON Patch ({@code application/json-patch+json}, the LWS baseline patch format). */
    public UpdateResult patch(URI uri, JsonPatch patch) {
        return patch(uri, patch, UpdateOptions.DEFAULT);
    }

    /** Applies a JSON Patch. */
    public UpdateResult patch(URI uri, JsonPatch patch, UpdateOptions options) {
        return patch(uri, Body.of(patch.toBytes()), Lws.MediaType.JSON_PATCH, options);
    }

    /** Applies a patch in any format the server advertises in {@code Accept-Patch} (e.g. {@code application/sparql-update}). */
    public UpdateResult patch(URI uri, Body patch, String patchContentType, UpdateOptions options) {
        return toUpdateResult(send("PATCH", uri, patch, updateHeaders(options, patchContentType), options.timeout().orElse(null)), "PATCH");
    }

    /** Asynchronous {@link #patch(URI, JsonPatch, UpdateOptions)}. */
    public CompletableFuture<UpdateResult> patchAsync(URI uri, JsonPatch patch, UpdateOptions options) {
        return sendAsync("PATCH", uri, Body.of(patch.toBytes()), updateHeaders(options, Lws.MediaType.JSON_PATCH), options.timeout().orElse(null))
                .thenApply(r -> toUpdateResult(r, "PATCH"));
    }

    // ================================================================================================
    // Deleting
    // ================================================================================================

    /** Deletes a resource (a container must be empty). */
    public void delete(URI uri) {
        delete(uri, DeleteOptions.DEFAULT);
    }

    /** Deletes a resource; {@link DeleteOptions#recursive()} deletes a container with its contents. */
    public void delete(URI uri, DeleteOptions options) {
        check(send("DELETE", uri, Body.empty(), deleteHeaders(options), options.timeout().orElse(null)), "DELETE");
    }

    /** Asynchronous {@link #delete(URI, DeleteOptions)}. */
    public CompletableFuture<Void> deleteAsync(URI uri, DeleteOptions options) {
        return sendAsync("DELETE", uri, Body.empty(), deleteHeaders(options), options.timeout().orElse(null))
                .thenAccept(r -> check(r, "DELETE"));
    }

    // ================================================================================================
    // Metadata (linksets)
    // ================================================================================================

    /** The linkset resource URL of a resource (from {@code rel="linkset"}). */
    public URI linksetUrl(URI resource) {
        return head(resource).linkset()
                .orElseThrow(() -> new LwsProtocolException("Resource " + resource + " has no linkset link"));
    }

    /** Discovers and reads a resource's linkset. */
    public LinksetDocument readLinkset(URI resource) {
        return readLinksetResource(linksetUrl(resource));
    }

    /** Reads a linkset resource at a known URL. */
    public LinksetDocument readLinksetResource(URI linksetUrl) {
        HttpResponse<byte[]> resp = send("GET", linksetUrl, Body.empty(),
                Map.of("Accept", List.of(Lws.MediaType.LINKSET_JSON + ", " + Lws.MediaType.JSON + ";q=0.5")), null);
        check(resp, "GET");
        return new LinksetDocument(resp.uri(), Linkset.parse(Json.parse(resp.body())), metadata(resp));
    }

    /** Replaces a linkset ({@code PUT}; only if the server allows it, else {@link MethodNotAllowedException}). */
    public UpdateResult updateLinkset(URI linksetUrl, Linkset linkset, UpdateOptions options) {
        return update(linksetUrl, Body.of(Json.toBytes(linkset.toJson())), Lws.MediaType.LINKSET_JSON, options);
    }

    /** Patches a linkset with JSON Patch. Use {@link com.ebremer.lws.patch.JsonPointer} to address relation keys. */
    public UpdateResult patchLinkset(URI linksetUrl, JsonPatch patch, UpdateOptions options) {
        return patch(linksetUrl, patch, options);
    }

    // ================================================================================================
    // Notifications
    // ================================================================================================

    /** Creates a webhook subscription at a notification service endpoint. */
    public Subscription subscribe(URI notificationService, WebhookSubscriptionRequest request) {
        HttpResponse<byte[]> resp = send("POST", notificationService, Body.of(Json.toBytes(request.toJson())),
                jsonHeaders(Lws.MediaType.LWS_JSON), null);
        check(resp, "POST");
        URI location = resp.headers().firstValue("location").map(l -> com.ebremer.lws.internal.Uris.resolveOrNull(resp.uri(), l)).orElse(null);
        if (resp.body() == null || resp.body().length == 0) {
            if (location == null) throw new LwsProtocolException("Subscription response has neither body nor Location");
            ObjectNode o = Json.object().put("type", Lws.Subscription.WEBHOOK).put("subscription", location.toString());
            return Subscription.parse(o, resp.uri(), location);
        }
        return Subscription.parse(Json.parse(resp.body()), resp.uri(), location);
    }

    /**
     * Creates a webhook subscription using the storage's notification service.
     *
     * @throws LwsProtocolException if the storage has no notification service supporting webhooks
     */
    public Subscription subscribe(StorageDescription storage, WebhookSubscriptionRequest request) {
        StorageDescription.Service svc = storage.notificationService()
                .orElseThrow(() -> new LwsProtocolException("Storage " + storage.id() + " has no NotificationService"));
        if (!svc.subscriptionTypes().isEmpty() && !svc.subscriptionTypes().contains(Lws.Subscription.WEBHOOK)) {
            throw new LwsProtocolException("Notification service does not support WebhookSubscription: " + svc.subscriptionTypes());
        }
        return subscribe(svc.serviceEndpoint(), request);
    }

    /** The subscriber's active subscriptions (a container listing of the notification service). */
    public Stream<ContainedResource> listSubscriptions(URI notificationService) {
        return listContainer(notificationService);
    }

    /** Retrieves a subscription's current state. */
    public Subscription getSubscription(URI subscription) {
        HttpResponse<byte[]> resp = send("GET", subscription, Body.empty(), Map.of("Accept", List.of(ACCEPT_CONTAINER)), null);
        check(resp, "GET");
        return Subscription.parse(Json.parse(resp.body()), resp.uri(), resp.uri());
    }

    /** Cancels a subscription. */
    public void unsubscribe(URI subscription) {
        delete(subscription);
    }

    // ================================================================================================
    // Access requests and grants
    // ================================================================================================

    /** Submits an access request; returns its URL. */
    public URI requestAccess(URI accessRequestService, AccessRequest request) {
        return postForLocation(accessRequestService, request.toJson());
    }

    /** Lists access requests. */
    public Stream<ContainedResource> listAccessRequests(URI accessRequestService) {
        return listContainer(accessRequestService);
    }

    /** Retrieves an access request. */
    public AccessRequest getAccessRequest(URI request) {
        return AccessRequest.parse(getJson(request));
    }

    /** Cancels (deletes) an access request. */
    public void cancelAccessRequest(URI request) {
        delete(request);
    }

    /** Creates an access grant (as storage controller); returns its URL. */
    public URI grantAccess(URI accessGrantService, AccessGrant grant) {
        return postForLocation(accessGrantService, grant.toJson());
    }

    /** Lists access grants. */
    public Stream<ContainedResource> listAccessGrants(URI accessGrantService) {
        return listContainer(accessGrantService);
    }

    /** Retrieves an access grant. */
    public AccessGrant getAccessGrant(URI grant) {
        return AccessGrant.parse(getJson(grant));
    }

    /** Revokes (deletes) an access grant. */
    public void revokeAccessGrant(URI grant) {
        delete(grant);
    }

    // ================================================================================================
    // Type index and type search
    // ================================================================================================

    /** Reads a Type Index page (the service endpoint, or an opaque page URL). */
    public TypeIndexPage readTypeIndex(URI typeIndex) {
        HttpResponse<byte[]> resp = send("GET", typeIndex, Body.empty(), Map.of("Accept", List.of(ACCEPT_CONTAINER)), null);
        check(resp, "GET");
        requireLwsJson(resp);
        return TypeIndexPage.parse(Json.parseObject(resp.body(), "Type index"), metadata(resp));
    }

    /** All type IRIs visible to the client, fetched lazily page by page. */
    public Stream<String> listTypes(URI typeIndexService) {
        return paginate(() -> readTypeIndex(typeIndexService), TypeIndexPage::next, this::readTypeIndex, TypeIndexPage::types);
    }

    /** Runs a type search ({@code QUERY}, RFC 10008) and returns the first result page. */
    public ContainerPage searchTypes(URI typeSearchService, TypeQuery query) {
        Map<String, List<String>> h = new LinkedHashMap<>();
        h.put("Content-Type", List.of(Lws.MediaType.LWS_QUERY_JSON));
        h.put("Accept", List.of(Lws.MediaType.LWS_JSON));
        return toContainerPage(send("QUERY", typeSearchService, Body.of(query.toBytes()), h, null), false);
    }

    /** All search results: the first page via {@code QUERY}, further pages by dereferencing {@code next} links. */
    public Stream<ContainedResource> searchAll(URI typeSearchService, TypeQuery query) {
        return paginate(() -> searchTypes(typeSearchService, query), ContainerPage::next,
                u -> toContainerPage(send("GET", u, Body.empty(), Map.of("Accept", List.of(Lws.MediaType.LWS_JSON)), null), false),
                ContainerPage::items);
    }

    /** The query formats a search service accepts ({@code OPTIONS} → {@code Accept-Query}). */
    public List<String> acceptedQueryFormats(URI typeSearchService) {
        HttpResponse<byte[]> resp = send("OPTIONS", typeSearchService, Body.empty(), Map.of(), null);
        check(resp, "OPTIONS");
        return HeaderLists.mediaTypes(resp.headers().allValues("accept-query"));
    }

    // ================================================================================================
    // Low-level access
    // ================================================================================================

    /**
     * Sends an arbitrary request through the client's authentication pipeline. Non-success statuses throw
     * the matching {@link HttpStatusException}; {@code 304} yields a not-modified result.
     */
    public Resource request(String method, URI uri, Body body, String contentType, RequestOptions options) {
        Map<String, List<String>> h = new LinkedHashMap<>(options.headers());
        if (contentType != null) h.put("Content-Type", List.of(contentType));
        return toResource(send(method, uri, body, h, options.timeout().orElse(null)));
    }

    // ================================================================================================
    // Internals
    // ================================================================================================

    private HttpResponse<byte[]> send(String method, URI uri, Body body, Map<String, List<String>> headers, Duration timeout) {
        return pipeline.send(new Pipeline.Call(method, uri, body, headers, timeout), BodyHandlers.ofByteArray());
    }

    private CompletableFuture<HttpResponse<byte[]>> sendAsync(String method, URI uri, Body body, Map<String, List<String>> headers, Duration timeout) {
        return pipeline.sendAsync(new Pipeline.Call(method, uri, body, headers, timeout), BodyHandlers.ofByteArray());
    }

    private static ResourceMetadata metadata(HttpResponse<?> resp) {
        return ResourceMetadata.of(resp.uri(), resp.statusCode(), resp.headers());
    }

    private static void check(HttpResponse<byte[]> resp, String method) {
        if (resp.statusCode() / 100 != 2) {
            throw HttpStatusException.of(method, resp.uri(), resp.statusCode(), resp.headers(), resp.body());
        }
    }

    private static Resource toResource(HttpResponse<byte[]> resp) {
        if (resp.statusCode() == 304) return new Resource(metadata(resp), new byte[0], true);
        check(resp, resp.request().method());
        return new Resource(metadata(resp), resp.body(), false);
    }

    private static ContainerPage toContainerPage(HttpResponse<byte[]> resp, boolean requireContainer) {
        check(resp, resp.request().method());
        requireLwsJson(resp);
        ContainerPage page = ContainerPage.parse(Json.parseObject(resp.body(), "Container representation"), metadata(resp));
        if (requireContainer && !page.isContainer()) {
            throw new LwsProtocolException(resp.uri() + " is not a container");
        }
        return page;
    }

    private static void requireLwsJson(HttpResponse<byte[]> resp) {
        String essence = HeaderLists.essence(resp.headers().firstValue("content-type").orElse(null));
        if (essence == null) return;
        if (!(essence.equals(Lws.MediaType.LWS_JSON) || essence.equals(Lws.MediaType.LD_JSON) || essence.equals(Lws.MediaType.JSON))) {
            throw new LwsProtocolException("Unexpected media type " + essence + " for an LWS JSON representation at " + resp.uri());
        }
    }

    private static CreateResult toCreateResult(HttpResponse<byte[]> resp) {
        check(resp, "POST");
        String loc = resp.headers().firstValue("location")
                .orElseThrow(() -> new LwsProtocolException("Create response (HTTP " + resp.statusCode() + ") has no Location header"));
        URI location = com.ebremer.lws.internal.Uris.resolveOrNull(resp.uri(), loc);
        if (location == null) throw new LwsProtocolException("Invalid Location header: " + loc);
        return new CreateResult(location, metadata(resp), resp.body());
    }

    private static UpdateResult toUpdateResult(HttpResponse<byte[]> resp, String method) {
        check(resp, method);
        return new UpdateResult(resp.statusCode(), metadata(resp), resp.body());
    }

    private URI postForLocation(URI endpoint, ObjectNode body) {
        HttpResponse<byte[]> resp = send("POST", endpoint, Body.of(Json.toBytes(body)), jsonHeaders(Lws.MediaType.LWS_JSON), null);
        return toCreateResult(resp).location();
    }

    private JsonNode getJson(URI uri) {
        HttpResponse<byte[]> resp = send("GET", uri, Body.empty(), Map.of("Accept", List.of(ACCEPT_CONTAINER)), null);
        check(resp, "GET");
        return Json.parse(resp.body());
    }

    private static Map<String, List<String>> jsonHeaders(String contentType) {
        Map<String, List<String>> h = new LinkedHashMap<>();
        h.put("Content-Type", List.of(contentType));
        h.put("Accept", List.of(ACCEPT_CONTAINER));
        return h;
    }

    private static Map<String, List<String>> readHeaders(ReadOptions o) {
        Map<String, List<String>> h = new LinkedHashMap<>();
        o.acceptValue().ifPresent(v -> h.put("Accept", List.of(v)));
        o.range().ifPresent(v -> h.put("Range", List.of(v)));
        o.ifNoneMatchValue().ifPresent(v -> h.put("If-None-Match", List.of(v)));
        o.ifModifiedSince().ifPresent(v -> h.put("If-Modified-Since", List.of(HTTP_DATE.format(v))));
        o.prefer().ifPresent(v -> h.put("Prefer", List.of(v)));
        h.putAll(o.headers());
        return h;
    }

    private static Map<String, List<String>> containerHeaders(ReadOptions o) {
        Map<String, List<String>> h = readHeaders(o);
        if (o.acceptValue().isEmpty()) h.put("Accept", List.of(ACCEPT_CONTAINER));
        return h;
    }

    private static Map<String, List<String>> createHeaders(CreateOptions o, String containerType) {
        Map<String, List<String>> h = new LinkedHashMap<>();
        List<String> links = new ArrayList<>();
        if (containerType != null) links.add(LinkHeader.format(Link.type(containerType)));
        for (String t : o.types()) links.add(LinkHeader.format(Link.type(t)));
        for (Link l : o.links()) links.add(LinkHeader.format(l));
        if (!links.isEmpty()) h.put("Link", links);
        o.slugValue().ifPresent(s -> h.put("Slug", List.of(encodeSlug(s))));
        h.putAll(o.headers());
        return h;
    }

    private static Map<String, List<String>> updateHeaders(UpdateOptions o, String contentType) {
        Map<String, List<String>> h = new LinkedHashMap<>();
        if (contentType != null) h.put("Content-Type", List.of(contentType));
        o.ifMatchValue().ifPresent(v -> h.put("If-Match", List.of(v)));
        o.ifNoneMatchValue().ifPresent(v -> h.put("If-None-Match", List.of(v)));
        if (!o.links().isEmpty()) {
            List<String> links = new ArrayList<>();
            for (Link l : o.links()) links.add(LinkHeader.format(l));
            h.put("Link", links);
        }
        if (o.setLinkset()) h.put("Prefer", List.of(Lws.Prefer.SET_LINKSET));
        h.putAll(o.headers());
        return h;
    }

    private static Map<String, List<String>> deleteHeaders(DeleteOptions o) {
        Map<String, List<String>> h = new LinkedHashMap<>();
        o.ifMatchValue().ifPresent(v -> h.put("If-Match", List.of(v)));
        if (o.isRecursive()) h.put("Depth", List.of("infinity"));
        h.putAll(o.headers());
        return h;
    }

    /** Percent-encodes a {@code Slug} value (RFC 5023 section 9.7): non-ASCII, control and {@code %} characters. */
    static String encodeSlug(String slug) {
        StringBuilder sb = new StringBuilder();
        for (byte b : slug.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            if (c >= 0x20 && c < 0x7f && c != '%') sb.append((char) c);
            else sb.append('%').append(String.format("%02X", c));
        }
        return sb.toString();
    }

    private static void closeQuietly(InputStream in) {
        try {
            in.close();
        } catch (IOException ignored) {
            // ignore
        }
    }

    /** Lazily concatenates the items of a chain of pages. */
    static <P, T> Stream<T> paginate(Supplier<P> first, Function<P, Optional<URI>> next, Function<URI, P> fetch,
                                     Function<P, List<T>> items) {
        Iterator<T> it = new Iterator<>() {
            private P page;
            private Iterator<T> current = Collections.emptyIterator();
            private boolean started;
            private boolean done;
            private final Set<URI> seen = new HashSet<>();

            @Override
            public boolean hasNext() {
                while (!current.hasNext()) {
                    if (done) return false;
                    if (!started) {
                        started = true;
                        page = first.get();
                    } else {
                        Optional<URI> n = next.apply(page);
                        if (n.isEmpty() || !seen.add(n.get())) {
                            done = true;
                            return false;
                        }
                        page = fetch.apply(n.get());
                    }
                    current = items.apply(page).iterator();
                }
                return true;
            }

            @Override
            public T next() {
                if (!hasNext()) throw new NoSuchElementException();
                return current.next();
            }
        };
        return StreamSupport.stream(Spliterators.spliteratorUnknownSize(it, Spliterator.ORDERED | Spliterator.NONNULL), false);
    }

    /** Executor for blocking authentication work in async calls: virtual threads on Java 21+, else a cached pool. */
    private static final class DefaultExecutor {
        static final Executor INSTANCE = create();

        private static Executor create() {
            try {
                return (ExecutorService) Executors.class.getMethod("newVirtualThreadPerTaskExecutor").invoke(null);
            } catch (ReflectiveOperationException | RuntimeException e) {
                return Executors.newCachedThreadPool(r -> {
                    Thread t = new Thread(r, "lws-client-async");
                    t.setDaemon(true);
                    return t;
                });
            }
        }
    }

    /** Builder for {@link LwsClient}. */
    public static final class Builder {
        private HttpClient http;
        private Authenticator authenticator;
        private String userAgent = DEFAULT_USER_AGENT;
        private final Map<String, List<String>> headers = new LinkedHashMap<>();
        private Duration timeout = Duration.ofSeconds(30);
        private Duration connectTimeout = Duration.ofSeconds(30);
        private Executor executor;

        private Builder() {}

        private Builder copy() {
            Builder b = new Builder();
            b.http = http;
            b.authenticator = authenticator;
            b.userAgent = userAgent;
            headers.forEach((k, v) -> b.headers.put(k, new ArrayList<>(v)));
            b.timeout = timeout;
            b.connectTimeout = connectTimeout;
            b.executor = executor;
            return b;
        }

        /**
         * The HTTP client to use. If you supply one, configure it with
         * {@code followRedirects(HttpClient.Redirect.NEVER)} so that redirects pass through the client's
         * credential checks.
         */
        public Builder httpClient(HttpClient http) {
            this.http = http;
            return this;
        }

        /** Request authentication (e.g. {@link com.ebremer.lws.auth.TokenExchangeAuthenticator}). */
        public Builder authenticator(Authenticator authenticator) {
            this.authenticator = authenticator;
            return this;
        }

        public Builder userAgent(String userAgent) {
            this.userAgent = userAgent;
            return this;
        }

        /** A header sent with every request. */
        public Builder header(String name, String value) {
            RequestOptions.addHeader(headers, name, value);
            return this;
        }

        /** Default per-request timeout (default 30 seconds). */
        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        /** Connect timeout of the default HTTP client (default 30 seconds). */
        public Builder connectTimeout(Duration connectTimeout) {
            this.connectTimeout = Objects.requireNonNull(connectTimeout);
            return this;
        }

        /** Executor for blocking authentication steps of async calls (default: virtual threads when available). */
        public Builder executor(Executor executor) {
            this.executor = executor;
            return this;
        }

        public LwsClient build() {
            return new LwsClient(this);
        }
    }
}
