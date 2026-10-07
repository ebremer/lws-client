// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.adapter;

import com.ebremer.lws.ContainedResource;
import com.ebremer.lws.CreateOptions;
import com.ebremer.lws.DeleteOptions;
import com.ebremer.lws.Linkset;
import com.ebremer.lws.LinksetDocument;
import com.ebremer.lws.LwsClient;
import com.ebremer.lws.LwsProtocolException;
import com.ebremer.lws.ReadOptions;
import com.ebremer.lws.Resource;
import com.ebremer.lws.UpdateOptions;
import com.ebremer.lws.access.AccessDocument;
import com.ebremer.lws.access.AccessGrant;
import com.ebremer.lws.access.AccessRequest;
import com.ebremer.lws.auth.Authenticator;
import com.ebremer.lws.auth.BearerTokenAuthenticator;
import com.ebremer.lws.auth.CredentialProvider;
import com.ebremer.lws.auth.Jwk;
import com.ebremer.lws.auth.KeyPairs;
import com.ebremer.lws.auth.OpenIdCredentials;
import com.ebremer.lws.auth.SelfSignedCredentials;
import com.ebremer.lws.auth.TokenExchangeAuthenticator;
import com.ebremer.lws.http.Link;
import com.ebremer.lws.index.TypeIndexPage;
import com.ebremer.lws.notify.Notification;
import com.ebremer.lws.notify.VerifiedNotification;
import com.ebremer.lws.notify.WebhookSubscriptionRequest;
import com.ebremer.lws.notify.WebhookVerifier;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import java.io.BufferedReader;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Stream;

/**
 * The Java adapter of the lws-client driver: runs the operations of {@code driver/PROTOCOL.md}
 * ({@code lws-driver/1}) with lws-client for Java. It reads one JSON request per line on stdin and writes
 * one JSON response per line on stdout; everything else goes to stderr.
 *
 * <p>The adapter is a thin wrapper: it calls the library's operations with the library's options and
 * reports the library's results and errors, without retrying or fixing anything up.
 */
public final class JavaAdapter {
    static final String PROTOCOL = "lws-driver/1";
    static final String LANGUAGE = "java";
    static final String LIBRARY = "lws-client-java/" + LwsClient.VERSION;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** One protocol operation. */
    @FunctionalInterface
    private interface Operation {
        ObjectNode run(ObjectNode args);
    }

    private final PrintStream out;
    private final Map<String, Operation> operations = new LinkedHashMap<>();
    /** The client every operation uses; {@code configure} replaces it. */
    private LwsClient client = LwsClient.create();

    private JavaAdapter(PrintStream out) {
        this.out = out;
        operations.put("configure", this::configure);
        operations.put("discover_storage", a -> Results.storage(client.discoverStorage(Args.requiredUri(a, "url"))));
        operations.put("get_storage_description", a -> Results.storage(client.getStorageDescription(Args.requiredUri(a, "url"))));
        operations.put("head", a -> Results.metadata(client.head(Args.requiredUri(a, "url"))));
        operations.put("read", this::read);
        operations.put("read_container", a -> Results.page(client.readContainer(Args.requiredUri(a, "url"))));
        operations.put("list_container", a -> items(client.listContainer(Args.requiredUri(a, "url")), Args.limit(a)));
        operations.put("create", this::create);
        operations.put("create_container", this::createContainer);
        operations.put("update", this::update);
        operations.put("patch", this::patch);
        operations.put("delete", this::delete);
        operations.put("linkset_url", this::linksetUrl);
        operations.put("read_linkset", this::readLinkset);
        operations.put("update_linkset", this::updateLinkset);
        operations.put("patch_linkset", this::patchLinkset);
        operations.put("subscribe", this::subscribe);
        operations.put("list_subscriptions",
                a -> items(client.listSubscriptions(Args.requiredUri(a, "serviceUrl")), Args.limit(a)));
        operations.put("get_subscription", a -> Results.subscription(client.getSubscription(Args.requiredUri(a, "url"))));
        operations.put("unsubscribe", a -> {
            client.unsubscribe(Args.requiredUri(a, "url"));
            return Results.object();
        });
        operations.put("verify_notification", this::verifyNotification);
        operations.put("request_access", a -> {
            AccessRequest request = document(() -> AccessRequest.parse(Args.requiredObject(a, "request")), "request");
            return location(client.requestAccess(Args.requiredUri(a, "serviceUrl"), request));
        });
        operations.put("get_access_request", a -> document(client.getAccessRequest(Args.requiredUri(a, "url"))));
        operations.put("list_access_requests",
                a -> items(client.listAccessRequests(Args.requiredUri(a, "serviceUrl")), Args.limit(a)));
        operations.put("cancel_access_request", a -> {
            client.cancelAccessRequest(Args.requiredUri(a, "url"));
            return Results.object();
        });
        operations.put("grant_access", a -> {
            AccessGrant grant = document(() -> AccessGrant.parse(Args.requiredObject(a, "grant")), "grant");
            return location(client.grantAccess(Args.requiredUri(a, "serviceUrl"), grant));
        });
        operations.put("get_access_grant", a -> document(client.getAccessGrant(Args.requiredUri(a, "url"))));
        operations.put("list_access_grants",
                a -> items(client.listAccessGrants(Args.requiredUri(a, "serviceUrl")), Args.limit(a)));
        operations.put("revoke_access_grant", a -> {
            client.revokeAccessGrant(Args.requiredUri(a, "url"));
            return Results.object();
        });
        operations.put("read_type_index", this::readTypeIndex);
        operations.put("list_types", a -> take(client.listTypes(Args.requiredUri(a, "serviceUrl")), Args.limit(a), "types", TextNode::valueOf));
        operations.put("search_types",
                a -> Results.page(client.searchTypes(Args.requiredUri(a, "serviceUrl"), Args.query(Args.requiredObject(a, "query")))));
        operations.put("search_all", a -> {
            URI service = Args.requiredUri(a, "serviceUrl");
            return items(client.searchAll(service, Args.query(Args.requiredObject(a, "query"))), Args.limit(a));
        });
        operations.put("accepted_query_formats", a -> {
            ObjectNode result = Results.object();
            result.set("formats", Results.strings(client.acceptedQueryFormats(Args.requiredUri(a, "serviceUrl"))));
            return result;
        });
        operations.put("shutdown", a -> Results.object());
    }

    /** Runs the adapter on the process's standard streams. */
    public static void main(String[] argv) throws IOException {
        // stdout carries protocol messages only: keep it for them, and send every other print to stderr.
        PrintStream protocol = new PrintStream(new FileOutputStream(FileDescriptor.out), false, StandardCharsets.UTF_8);
        System.setOut(System.err);
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        new JavaAdapter(protocol).serve(in);
        protocol.flush();
        System.exit(0);
    }

    /** Says hello, then answers requests until end of input or {@code shutdown}. */
    private void serve(BufferedReader in) throws IOException {
        ObjectNode hello = Results.object();
        hello.put("protocol", PROTOCOL);
        hello.put("language", LANGUAGE);
        hello.put("library", LIBRARY);
        hello.set("operations", Results.strings(operations.keySet()));
        ObjectNode message = Results.object();
        message.set("hello", hello);
        write(message);

        String line;
        while ((line = in.readLine()) != null) {
            if (line.isBlank()) continue;
            JsonNode request;
            try {
                request = MAPPER.readTree(line);
            } catch (JacksonException e) {
                write(failure(NullNode.getInstance(), Errors.error(Errors.INVALID_ARGUMENTS, "the request is not JSON")));
                continue;
            }
            if (request == null || !request.isObject()) {
                write(failure(NullNode.getInstance(), Errors.error(Errors.INVALID_ARGUMENTS, "the request is not a JSON object")));
                continue;
            }
            JsonNode id = request.has("id") ? request.get("id") : NullNode.getInstance();
            String op = request.path("op").isTextual() ? request.get("op").textValue() : null;
            Operation operation = op == null ? null : operations.get(op);
            if (operation == null) {
                write(failure(id, Errors.error(Errors.UNSUPPORTED, "unknown operation '" + op + "'")));
                continue;
            }
            write(answer(id, operation, request.get("args")));
            if (op.equals("shutdown")) return;
        }
    }

    /** Runs one operation; whatever it throws is the outcome. */
    private static ObjectNode answer(JsonNode id, Operation operation, JsonNode args) {
        try {
            JsonNode a = Args.absent(args) ? Results.object() : args;
            if (!a.isObject()) throw AdapterException.invalid("args must be an object");
            ObjectNode response = Results.object();
            response.set("id", id);
            response.put("ok", true);
            response.set("result", operation.run((ObjectNode) a));
            return response;
        } catch (Exception e) {
            return failure(id, Errors.of(e));
        } catch (StackOverflowError | LinkageError e) {
            return failure(id, Errors.internal(e));
        }
    }

    private static ObjectNode failure(JsonNode id, ObjectNode error) {
        ObjectNode response = Results.object();
        response.set("id", id);
        response.put("ok", false);
        response.set("error", error);
        return response;
    }

    /** Writes one protocol line and flushes it. */
    private void write(ObjectNode message) throws IOException {
        out.print(MAPPER.writeValueAsString(message));
        out.print('\n');
        out.flush();
    }

    // ---------------------------------------------------------------------------------------------
    // configure

    private ObjectNode configure(ObjectNode args) {
        JsonNode authArg = args.get("auth");
        if (!Args.absent(authArg) && !authArg.isObject()) throw AdapterException.invalid("argument 'auth' must be an object");
        JsonNode auth = Args.absent(authArg) ? Results.object().put("type", "none") : authArg;
        Boolean allowInsecureHttp = Args.optionalBoolean(args, "allowInsecureHttp");
        ObjectNode result = Results.object();
        result.put("library", LIBRARY);
        Authenticator authenticator;
        String type = Args.requiredString(auth, "type");
        switch (type) {
            case "none" -> authenticator = null;
            case "bearer" -> {
                String token = Args.requiredString(auth, "token");
                String realm = Args.optionalString(auth, "realm");
                authenticator = realm == null ? BearerTokenAuthenticator.unrestricted(token)
                        : BearerTokenAuthenticator.of(token, Args.uri(realm, "realm"));
            }
            case "openid" -> authenticator = tokenExchange(OpenIdCredentials.of(Args.requiredString(auth, "idToken")), allowInsecureHttp);
            case "selfSigned" -> {
                URI agent = Args.requiredUri(auth, "agent");
                ObjectNode jwk = Args.requiredObject(auth, "privateJwk");
                String kid = Args.optionalString(auth, "kid");
                if (kid == null) {
                    if (!jwk.path("kid").isTextual()) throw AdapterException.invalid("selfSigned needs 'kid', or a 'kid' in the private JWK");
                    kid = jwk.get("kid").textValue();
                }
                PrivateKey key;
                try {
                    key = Jwk.toPrivateKey(jwk);
                } catch (IllegalArgumentException e) {
                    throw AdapterException.invalid("argument 'privateJwk' is not a usable private key: " + e.getMessage());
                }
                authenticator = tokenExchange(SelfSignedCredentials.forAgent(agent, key, kid), allowInsecureHttp);
                result.put("agent", agent.toString());
                result.put("kid", kid);
            }
            case "didKey" -> {
                String algorithm = Optional.ofNullable(Args.optionalString(auth, "algorithm")).orElse("ES256");
                KeyPair keys = switch (algorithm) {
                    case "ES256" -> KeyPairs.generateP256();
                    case "EdDSA" -> KeyPairs.generateEd25519();
                    default -> throw AdapterException.invalid("unknown algorithm '" + algorithm + "'");
                };
                SelfSignedCredentials credentials = SelfSignedCredentials.didKey(keys);
                authenticator = tokenExchange(credentials, allowInsecureHttp);
                result.put("agent", credentials.agent().toString());
                result.put("kid", credentials.keyId());
            }
            default -> throw AdapterException.invalid("unknown auth type '" + type + "'");
        }
        LwsClient.Builder builder = LwsClient.builder().authenticator(authenticator);
        String userAgent = Args.optionalString(args, "userAgent");
        if (userAgent != null) builder.userAgent(userAgent);
        Double timeoutSeconds = Args.optionalNumber(args, "timeoutSeconds");
        if (timeoutSeconds != null) {
            if (!(timeoutSeconds > 0) || timeoutSeconds.isInfinite()) {
                throw AdapterException.invalid("argument 'timeoutSeconds' must be a positive number");
            }
            builder.timeout(Duration.ofNanos(Math.max(1, Math.round(timeoutSeconds * 1e9))));
        }
        ObjectNode headers = Args.optionalObject(args, "headers");
        if (headers != null) {
            for (Map.Entry<String, JsonNode> h : headers.properties()) {
                if (!h.getValue().isTextual()) throw AdapterException.invalid("header '" + h.getKey() + "' must be a string");
                builder.header(h.getKey(), h.getValue().textValue());
            }
        }
        client = builder.build();
        return result;
    }

    private static TokenExchangeAuthenticator tokenExchange(CredentialProvider credentials, Boolean allowInsecureHttp) {
        TokenExchangeAuthenticator.Builder builder = TokenExchangeAuthenticator.builder(credentials);
        if (allowInsecureHttp != null) builder.allowInsecureHttp(allowInsecureHttp);
        return builder.build();
    }

    // ---------------------------------------------------------------------------------------------
    // Resources

    private ObjectNode read(ObjectNode args) {
        URI url = Args.requiredUri(args, "url");
        ReadOptions.Builder options = ReadOptions.builder();
        String accept = Args.optionalString(args, "accept");
        if (accept != null) options.accept(accept);
        Long start = Args.optionalInteger(args, "rangeStart");
        Long end = Args.optionalInteger(args, "rangeEnd");
        if (start != null) options.range(start, end);
        else if (end != null) throw AdapterException.invalid("rangeEnd needs rangeStart");
        String ifNoneMatch = Args.optionalString(args, "ifNoneMatch");
        if (ifNoneMatch != null) options.ifNoneMatch(ifNoneMatch);
        String prefer = Args.optionalString(args, "prefer");
        if (prefer != null) options.prefer(prefer);
        Resource resource = client.read(url, options.build());
        ObjectNode result = Results.object();
        result.set("metadata", Results.metadata(resource.metadata()));
        result.put("notModified", resource.notModified());
        Results.put(result, "contentRange", resource.contentRange());
        result.set("body", Results.body(resource));
        return result;
    }

    private ObjectNode create(ObjectNode args) {
        URI container = Args.requiredUri(args, "container");
        Args.BodyArg body = Args.body(args.get("body"), Args.optionalString(args, "contentType"));
        CreateOptions.Builder options = CreateOptions.builder();
        String slug = Args.optionalString(args, "slug");
        if (slug != null) options.slug(slug);
        ArrayNode types = Args.optionalArray(args, "types");
        if (types != null) Args.strings(types, "types").forEach(options::type);
        ArrayNode links = Args.optionalArray(args, "links");
        if (links != null) {
            for (JsonNode l : links) {
                if (!l.isObject()) throw AdapterException.invalid("argument 'links' must be a list of {href, rel} objects");
                options.link(Link.of(Args.requiredUri(l, "href"), Args.requiredString(l, "rel")));
            }
        }
        return Results.created(client.create(container, body.body(), body.contentType(), options.build()));
    }

    private ObjectNode createContainer(ObjectNode args) {
        URI parent = Args.requiredUri(args, "parent");
        CreateOptions.Builder options = CreateOptions.builder();
        String slug = Args.optionalString(args, "slug");
        if (slug != null) options.slug(slug);
        return Results.created(client.createContainer(parent, options.build()));
    }

    private ObjectNode update(ObjectNode args) {
        URI url = Args.requiredUri(args, "url");
        if (Args.absent(args.get("body"))) throw AdapterException.invalid("missing argument 'body'");
        Args.BodyArg body = Args.body(args.get("body"), Args.optionalString(args, "contentType"));
        UpdateOptions.Builder options = UpdateOptions.builder();
        String ifMatch = Args.optionalString(args, "ifMatch");
        if (ifMatch != null) options.ifMatch(ifMatch);
        String ifNoneMatch = Args.optionalString(args, "ifNoneMatch");
        if (ifNoneMatch != null) options.ifNoneMatch(ifNoneMatch);
        return Results.update(client.update(url, body.body(), body.contentType(), options.build()));
    }

    private ObjectNode patch(ObjectNode args) {
        URI url = Args.requiredUri(args, "url");
        return Results.update(client.patch(url, Args.patch(args.get("patch")), ifMatch(args)));
    }

    private ObjectNode delete(ObjectNode args) {
        URI url = Args.requiredUri(args, "url");
        DeleteOptions.Builder options = DeleteOptions.builder();
        String ifMatch = Args.optionalString(args, "ifMatch");
        if (ifMatch != null) options.ifMatch(ifMatch);
        if (Boolean.TRUE.equals(Args.optionalBoolean(args, "recursive"))) options.recursive(true);
        client.delete(url, options.build());
        return Results.object();
    }

    /** Update options carrying only the optional {@code ifMatch}. */
    private static UpdateOptions ifMatch(ObjectNode args) {
        UpdateOptions.Builder options = UpdateOptions.builder();
        String ifMatch = Args.optionalString(args, "ifMatch");
        if (ifMatch != null) options.ifMatch(ifMatch);
        return options.build();
    }

    // ---------------------------------------------------------------------------------------------
    // Linksets

    private ObjectNode linksetUrl(ObjectNode args) {
        ObjectNode result = Results.object();
        result.put("linkset", client.linksetUrl(Args.requiredUri(args, "url")).toString());
        return result;
    }

    private ObjectNode readLinkset(ObjectNode args) {
        LinksetDocument doc = client.readLinkset(Args.requiredUri(args, "url"));
        ObjectNode result = Results.object();
        result.put("url", doc.url().toString());
        Results.put(result, "etag", doc.etag());
        result.set("linkset", doc.linkset().toJson());
        result.set("allow", Results.strings(doc.allow()));
        result.set("acceptPatch", Results.strings(doc.acceptPatch()));
        return result;
    }

    private ObjectNode updateLinkset(ObjectNode args) {
        URI linksetUrl = Args.requiredUri(args, "linksetUrl");
        Linkset linkset = document(() -> Linkset.parse(Args.requiredObject(args, "linkset")), "linkset");
        return Results.update(client.updateLinkset(linksetUrl, linkset, ifMatch(args)));
    }

    private ObjectNode patchLinkset(ObjectNode args) {
        URI linksetUrl = Args.requiredUri(args, "linksetUrl");
        return Results.update(client.patchLinkset(linksetUrl, Args.patch(args.get("patch")), ifMatch(args)));
    }

    // ---------------------------------------------------------------------------------------------
    // Notifications

    private ObjectNode subscribe(ObjectNode args) {
        URI service = Args.requiredUri(args, "serviceUrl");
        List<URI> topics = Args.uris(Args.requiredArray(args, "topics"), "topics");
        URI inbox = Args.requiredUri(args, "inbox");
        String expires = Args.optionalString(args, "expires");
        Optional<Instant> expiry = expires == null ? Optional.empty() : Optional.of(Args.instant(expires, "expires"));
        return Results.subscription(client.subscribe(service, new WebhookSubscriptionRequest(topics, inbox, expiry)));
    }

    private ObjectNode verifyNotification(ObjectNode args) {
        String method = Args.requiredString(args, "method");
        URI url = Args.requiredUri(args, "url");
        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> h : Args.requiredObject(args, "headers").properties()) {
            JsonNode v = h.getValue();
            List<String> values = new ArrayList<>();
            if (v.isTextual()) values.add(v.textValue());
            else if (v.isArray()) values.addAll(Args.strings(v, "headers." + h.getKey()));
            else throw AdapterException.invalid("header '" + h.getKey() + "' must be a list of values");
            headers.computeIfAbsent(h.getKey(), k -> new ArrayList<>()).addAll(values);
        }
        byte[] body = Args.base64(Args.requiredString(args, "bodyBase64"), "bodyBase64");
        WebhookVerifier.Builder verifier = WebhookVerifier.builder().client(client);
        ArrayNode trusted = Args.optionalArray(args, "trustedStorages");
        if (trusted != null) verifier.trustedStorages(Args.uris(trusted, "trustedStorages"));
        VerifiedNotification verified = verifier.build().verify(method, url, headers, body);
        ObjectNode result = Results.object();
        result.put("storage", verified.storage().toString());
        result.put("keyid", verified.keyId());
        ArrayNode activities = result.putArray("activities");
        for (Notification.Activity a : verified.notification().activities()) {
            ObjectNode activity = activities.addObject();
            Results.put(activity, "id", Optional.ofNullable(a.id()));
            activity.set("types", Results.strings(a.types()));
            activity.put("object", a.object().id().toString());
            activity.set("objectTypes", Results.strings(a.object().types()));
        }
        result.set("raw", verified.notification().raw());
        return result;
    }

    // ---------------------------------------------------------------------------------------------
    // Access requests and grants

    /** The document as the library received it (its {@code raw}), else as the library serialises it. */
    private static ObjectNode document(AccessDocument doc) {
        ObjectNode result = Results.object();
        ObjectNode raw = doc instanceof AccessRequest r ? r.raw() : ((AccessGrant) doc).raw();
        result.set("document", raw != null ? raw : doc.toJson());
        return result;
    }

    private static ObjectNode location(URI location) {
        ObjectNode result = Results.object();
        result.put("location", location.toString());
        return result;
    }

    /** Parses a document argument with the library's parser; a document it rejects is a malformed argument. */
    private static <T> T document(Supplier<T> parse, String name) {
        try {
            return parse.get();
        } catch (LwsProtocolException e) {
            throw AdapterException.invalid("argument '" + name + "' is not a valid document: " + e.getMessage());
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Type index and search

    private ObjectNode readTypeIndex(ObjectNode args) {
        TypeIndexPage page = client.readTypeIndex(Args.requiredUri(args, "url"));
        ObjectNode result = Results.object();
        Results.put(result, "totalItems", page.totalItems());
        result.set("types", Results.strings(page.types()));
        Results.put(result, "first", page.first());
        Results.put(result, "next", page.next());
        Results.put(result, "prev", page.prev());
        Results.put(result, "last", page.last());
        return result;
    }

    // ---------------------------------------------------------------------------------------------
    // Lazy sequences

    private static ObjectNode items(Stream<ContainedResource> sequence, long limit) {
        return take(sequence, limit, "items", Results::item);
    }

    /**
     * Pulls at most {@code limit + 1} elements from a lazy sequence, returns the first {@code limit} under
     * {@code member}, and sets {@code truncated} to whether there was one more.
     */
    private static <T> ObjectNode take(Stream<T> sequence, long limit, String member, Function<T, JsonNode> shape) {
        ObjectNode result = Results.object();
        ArrayNode items = result.putArray(member);
        boolean truncated = false;
        try (Stream<T> s = sequence) {
            Iterator<T> it = s.iterator();
            long taken = 0;
            while (it.hasNext()) {
                T item = it.next();
                if (taken == limit) {
                    truncated = true;
                    break;
                }
                items.add(shape.apply(item));
                taken++;
            }
        }
        result.put("truncated", truncated);
        return result;
    }
}
