// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.auth.DidKey;
import com.ebremer.lws.auth.Jwt;
import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A small in-memory LWS server for client tests: storage description, authorization server (token
 * exchange of self-signed did:key JWTs), containers with pagination, data resources with ETags,
 * linksets, notifications, access requests and type index/search.
 */
final class MockLwsServer implements AutoCloseable {
    final HttpServer server;
    final String base;
    final int pageSize;
    final boolean requireAuth;

    final AtomicInteger tokenRequests = new AtomicInteger();
    final AtomicInteger metadataRequests = new AtomicInteger();
    final List<String> requestLog = Collections.synchronizedList(new ArrayList<>());
    final Map<String, Map<String, List<String>>> lastHeaders = new ConcurrentHashMap<>();
    final Set<String> tokens = ConcurrentHashMap.newKeySet();
    volatile String lastSubjectToken;

    private final Map<String, Res> store = new LinkedHashMap<>();
    private final AtomicInteger counter = new AtomicInteger();

    static final class Res {
        final boolean container;
        byte[] body = new byte[0];
        String contentType;
        int version = 1;
        final List<String> children = new ArrayList<>();
        ObjectNode linkset;
        final List<String> types = new ArrayList<>();

        Res(boolean container) {
            this.container = container;
        }
    }

    MockLwsServer(boolean requireAuth, int pageSize) throws IOException {
        this.requireAuth = requireAuth;
        this.pageSize = pageSize;
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        for (String c : List.of("/root/", "/notifications/", "/access/requests/", "/access/grants/")) {
            store.put(c, new Res(true));
        }
        server.createContext("/", this::handle);
        server.start();
    }

    URI uri(String path) {
        return URI.create(base + path);
    }

    @Override
    public void close() {
        server.stop(0);
    }

    // ------------------------------------------------------------------------------------------------

    private void handle(HttpExchange ex) throws IOException {
        try {
            String method = ex.getRequestMethod();
            String path = ex.getRequestURI().getRawPath();
            String query = ex.getRequestURI().getRawQuery();
            requestLog.add(method + " " + path + (query != null ? "?" + query : ""));
            Map<String, List<String>> copy = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            copy.putAll(ex.getRequestHeaders());
            lastHeaders.put(method + " " + path, copy);
            byte[] body = readAll(ex.getRequestBody());

            if (path.equals("/") && (method.equals("GET") || method.equals("HEAD"))) {
                send(ex, 200, "application/lws+cid", Json.toBytes(storageDescription()));
                return;
            }
            if (path.equals("/.well-known/lws-configuration/as")) {
                metadataRequests.incrementAndGet();
                ObjectNode md = Json.object();
                md.put("issuer", base + "/as");
                md.put("token_endpoint", base + "/as/token");
                md.putArray("grant_types_supported").add(Lws.GRANT_TYPE_TOKEN_EXCHANGE);
                md.putArray("subject_token_types_supported").add(Lws.TokenType.JWT);
                send(ex, 200, "application/json", Json.toBytes(md));
                return;
            }
            if (path.equals("/as/token") && method.equals("POST")) {
                token(ex, body);
                return;
            }
            if (path.equals("/problem")) {
                ObjectNode p = Json.object().put("type", "https://storage.example/problems/not-empty").put("title", "Container not empty")
                        .put("status", 409).put("detail", "nope").put("itemCount", 3);
                send(ex, 409, "application/problem+json", Json.toBytes(p));
                return;
            }
            if (path.equals("/redirect-me")) {
                ex.getResponseHeaders().add("Location", "/root/");
                send(ex, 307, null, null);
                return;
            }
            if (requireAuth) {
                String auth = ex.getRequestHeaders().getFirst("Authorization");
                boolean ok = auth != null && auth.startsWith("Bearer ") && tokens.contains(auth.substring(7));
                if (!ok) {
                    String realm = path.startsWith("/elsewhere/") ? base + "/root/" : base + "/";
                    ex.getResponseHeaders().add("WWW-Authenticate",
                            "Bearer as_uri=\"" + base + "/as\", realm=\"" + realm + "\", error=\"invalid_token\"");
                    ex.getResponseHeaders().add("Link", "<" + base + "/>; rel=\"" + Lws.Rel.STORAGE + "\"");
                    send(ex, 401, null, null);
                    return;
                }
            }
            if (path.equals("/types/index")) {
                typeIndex(ex);
                return;
            }
            if (path.equals("/types/search")) {
                search(ex, method, body, query);
                return;
            }
            synchronized (store) {
                resource(ex, method, path, query, body);
            }
        } catch (RuntimeException e) {
            e.printStackTrace();
            send(ex, 500, "text/plain", String.valueOf(e).getBytes(StandardCharsets.UTF_8));
        }
    }

    private ObjectNode storageDescription() {
        ObjectNode d = Json.object();
        d.putArray("@context").add(Lws.CID_CONTEXT).add(Lws.LWS_CONTEXT);
        d.put("id", base + "/");
        d.put("type", "Storage");
        ArrayNode s = d.putArray("service");
        s.addObject().put("type", "StorageRoot").put("serviceEndpoint", base + "/root/");
        ObjectNode n = s.addObject().put("type", "NotificationService").put("serviceEndpoint", base + "/notifications/");
        n.putArray("subscriptionType").add("WebhookSubscription");
        s.addObject().put("type", "AccessRequestService").put("serviceEndpoint", base + "/access/requests/");
        s.addObject().put("type", "AccessGrantService").put("serviceEndpoint", base + "/access/grants/");
        s.addObject().put("type", "TypeIndexService").put("serviceEndpoint", base + "/types/index");
        s.addObject().put("type", "TypeSearchService").put("serviceEndpoint", base + "/types/search");
        return d;
    }

    private void token(HttpExchange ex, byte[] body) throws IOException {
        tokenRequests.incrementAndGet();
        Map<String, String> form = new HashMap<>();
        for (String kv : new String(body, StandardCharsets.UTF_8).split("&")) {
            int i = kv.indexOf('=');
            if (i > 0) form.put(URLDecoder.decode(kv.substring(0, i), StandardCharsets.UTF_8), URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8));
        }
        String subject = form.get("subject_token");
        lastSubjectToken = subject;
        boolean ok = Lws.GRANT_TYPE_TOKEN_EXCHANGE.equals(form.get("grant_type"))
                && ((base + "/").equals(form.get("resource")) || (base + "/root/").equals(form.get("resource")));
        ok &= Lws.TokenType.JWT.equals(form.get("subject_token_type")) && subject != null;
        if (ok) {
            ObjectNode claims = Jwt.claims(subject);
            String sub = claims.path("sub").asText();
            ok = sub.startsWith("did:key:") && sub.equals(claims.path("iss").asText()) && sub.equals(claims.path("client_id").asText())
                    && claims.path("aud").toString().contains(base + "/as")
                    && Jwt.verify(subject, DidKey.toPublicKey(sub));
        }
        if (!ok) {
            send(ex, 400, "application/json", "{\"error\":\"invalid_request\",\"error_description\":\"bad subject token\"}".getBytes(StandardCharsets.UTF_8));
            return;
        }
        String token = "tok-" + counter.incrementAndGet();
        tokens.add(token);
        ObjectNode r = Json.object().put("access_token", token).put("token_type", "Bearer").put("expires_in", 300);
        send(ex, 200, "application/json", Json.toBytes(r));
    }

    private void resource(HttpExchange ex, String method, String path, String query, byte[] body) throws IOException {
        if (path.endsWith(".meta")) {
            linkset(ex, method, path.substring(0, path.length() - 5), body);
            return;
        }
        Res r = store.get(path);
        if (r == null) {
            send(ex, 404, "text/plain", "not found".getBytes(StandardCharsets.UTF_8));
            return;
        }
        String etag = "\"v" + r.version + "\"";
        switch (method) {
            case "GET", "HEAD" -> {
                addLinks(ex, path, r);
                ex.getResponseHeaders().add("ETag", etag);
                String inm = ex.getRequestHeaders().getFirst("If-None-Match");
                if (inm != null && inm.equals(etag)) {
                    send(ex, 304, null, null);
                    return;
                }
                if (r.container) {
                    int page = query != null && query.startsWith("page=") ? Integer.parseInt(query.substring(5)) : 1;
                    int pages = Math.max(1, (r.children.size() + pageSize - 1) / pageSize);
                    ObjectNode c = Json.object();
                    c.put("@context", Lws.LWS_CONTEXT);
                    c.put("id", path);
                    c.put("type", "Container");
                    c.put("totalItems", r.children.size());
                    ArrayNode items = c.putArray("items");
                    for (String child : r.children.subList(Math.min((page - 1) * pageSize, r.children.size()), Math.min(page * pageSize, r.children.size()))) {
                        Res cr = store.get(child);
                        ObjectNode it = items.addObject();
                        it.put("id", child.substring(path.length()));
                        if (cr.container) {
                            it.put("type", "Container");
                        } else {
                            ArrayNode t = it.putArray("type").add("DataResource");
                            cr.types.forEach(t::add);
                            it.put("format", cr.contentType);
                            it.put("size", cr.body.length);
                            it.put("modified", "2026-10-05T12:00:00Z");
                        }
                    }
                    if (pages > 1) {
                        ex.getResponseHeaders().add("Link", "<" + path + "?page=1>; rel=\"first\"");
                        ex.getResponseHeaders().add("Link", "<" + path + "?page=" + pages + ">; rel=\"last\"");
                        if (page < pages) ex.getResponseHeaders().add("Link", "<" + path + "?page=" + (page + 1) + ">; rel=\"next\"");
                        if (page > 1) ex.getResponseHeaders().add("Link", "<" + path + "?page=" + (page - 1) + ">; rel=\"prev\"");
                    }
                    String accept = ex.getRequestHeaders().getFirst("Accept");
                    String ct = accept != null && accept.startsWith("application/json") ? "application/json" : "application/lws+json";
                    send(ex, 200, ct, method.equals("HEAD") ? null : Json.toBytes(c), method.equals("HEAD"));
                } else {
                    String range = ex.getRequestHeaders().getFirst("Range");
                    if (range != null && range.startsWith("bytes=")) {
                        String[] se = range.substring(6).split("-", -1);
                        int s = Integer.parseInt(se[0]);
                        int e = se[1].isEmpty() ? r.body.length - 1 : Math.min(Integer.parseInt(se[1]), r.body.length - 1);
                        ex.getResponseHeaders().add("Content-Range", "bytes " + s + "-" + e + "/" + r.body.length);
                        byte[] part = java.util.Arrays.copyOfRange(r.body, s, e + 1);
                        send(ex, 206, r.contentType, part);
                        return;
                    }
                    send(ex, 200, r.contentType, method.equals("HEAD") ? null : r.body, method.equals("HEAD"));
                }
            }
            case "POST" -> {
                if (!r.container) {
                    send(ex, 405, null, null);
                    return;
                }
                List<String> links = ex.getRequestHeaders().getOrDefault("Link", List.of());
                boolean container = links.stream().anyMatch(l -> l.contains(Lws.Type.CONTAINER));
                String slug = ex.getRequestHeaders().getFirst("Slug");
                String name = slug != null ? URLDecoder.decode(slug, StandardCharsets.UTF_8).replaceAll("[^A-Za-z0-9._-]", "-") : "res-" + counter.incrementAndGet();
                String child = path + name + (container ? "/" : "");
                while (store.containsKey(child)) child = path + name + "-" + counter.incrementAndGet() + (container ? "/" : "");
                Res nr = new Res(container);
                if (path.startsWith("/notifications/") || path.startsWith("/access/")) {
                    nr = new Res(false);
                    nr.contentType = "application/lws+json";
                    nr.body = body;
                } else if (!container) {
                    nr.contentType = ex.getRequestHeaders().getFirst("Content-Type");
                    nr.body = body;
                    for (String l : links) {
                        for (com.ebremer.lws.http.Link link : com.ebremer.lws.http.LinkHeader.parse(l, URI.create(base + path))) {
                            if (link.rel().equals("type")) nr.types.add(link.href().toString());
                        }
                    }
                }
                store.put(child, nr);
                r.children.add(child);
                r.version++;
                if (path.equals("/notifications/")) {
                    ObjectNode s = Json.object();
                    s.putArray("@context").add(Lws.LWS_CONTEXT);
                    s.put("type", "WebhookSubscription");
                    s.put("subscription", base + child);
                    JsonNode req = Json.parse(body);
                    if (req.has("expires")) s.set("expires", req.get("expires"));
                    nr.body = Json.toBytes(s);
                    ex.getResponseHeaders().add("Location", base + child);
                    send(ex, 200, "application/lws+json", Json.toBytes(s));
                    return;
                }
                ex.getResponseHeaders().add("Location", child);
                addLinks(ex, child, nr);
                send(ex, 201, null, null);
            }
            case "PUT" -> {
                if (r.container) {
                    send(ex, 405, null, null);
                    return;
                }
                String im = ex.getRequestHeaders().getFirst("If-Match");
                if (im != null && !im.equals(etag)) {
                    send(ex, 412, null, null);
                    return;
                }
                r.body = body;
                r.contentType = ex.getRequestHeaders().getFirst("Content-Type");
                r.version++;
                ex.getResponseHeaders().add("ETag", "\"v" + r.version + "\"");
                send(ex, 204, null, null);
            }
            case "PATCH" -> {
                if (!Lws.MediaType.JSON_PATCH.equals(ex.getRequestHeaders().getFirst("Content-Type"))) {
                    ex.getResponseHeaders().add("Accept-Patch", Lws.MediaType.JSON_PATCH);
                    send(ex, 415, null, null);
                    return;
                }
                String im = ex.getRequestHeaders().getFirst("If-Match");
                if (im != null && !im.equals(etag)) {
                    send(ex, 412, null, null);
                    return;
                }
                r.body = Json.toBytes(applyPatch(Json.parse(r.body), Json.parse(body)));
                r.version++;
                ex.getResponseHeaders().add("ETag", "\"v" + r.version + "\"");
                send(ex, 204, null, null);
            }
            case "DELETE" -> {
                boolean recursive = "infinity".equals(ex.getRequestHeaders().getFirst("Depth"));
                if (r.container && !r.children.isEmpty() && !recursive) {
                    send(ex, 409, "text/plain", "container not empty".getBytes(StandardCharsets.UTF_8));
                    return;
                }
                removeTree(path);
                for (Res p : store.values()) p.children.remove(path);
                send(ex, 204, null, null);
            }
            default -> send(ex, 405, null, null);
        }
    }

    private void removeTree(String path) {
        Res r = store.remove(path);
        if (r != null) for (String c : new ArrayList<>(r.children)) removeTree(c);
    }

    private void addLinks(HttpExchange ex, String path, Res r) {
        ex.getResponseHeaders().add("Link", "<" + path + ".meta>; rel=\"linkset\"; type=\"application/linkset+json\"");
        int cut = path.endsWith("/") ? path.lastIndexOf('/', path.length() - 2) : path.lastIndexOf('/');
        if (!path.equals("/root/")) ex.getResponseHeaders().add("Link", "<" + path.substring(0, cut + 1) + ">; rel=\"up\"");
        ex.getResponseHeaders().add("Link", "<" + (r.container ? Lws.Type.CONTAINER : Lws.Type.DATA_RESOURCE) + ">; rel=\"type\"");
        for (String t : r.types) ex.getResponseHeaders().add("Link", "<" + t + ">; rel=\"type\"");
        ex.getResponseHeaders().add("Link", "<" + base + "/>; rel=\"" + Lws.Rel.STORAGE + "\"");
    }

    private void linkset(HttpExchange ex, String method, String resourcePath, byte[] body) throws IOException {
        Res r = store.get(resourcePath);
        if (r == null) {
            send(ex, 404, null, null);
            return;
        }
        if (r.linkset == null) {
            r.linkset = Json.object();
            r.linkset.putArray("linkset").addObject().put("anchor", base + resourcePath);
        }
        String etag = "\"ls" + r.linkset.toString().hashCode() + "\"";
        ex.getResponseHeaders().add("Allow", "GET, HEAD, PATCH");
        ex.getResponseHeaders().add("Accept-Patch", Lws.MediaType.JSON_PATCH);
        switch (method) {
            case "GET", "HEAD" -> {
                ex.getResponseHeaders().add("ETag", etag);
                send(ex, 200, Lws.MediaType.LINKSET_JSON, Json.toBytes(r.linkset), method.equals("HEAD"));
            }
            case "PATCH" -> {
                String im = ex.getRequestHeaders().getFirst("If-Match");
                if (im != null && !im.equals(etag)) {
                    send(ex, 412, null, null);
                    return;
                }
                r.linkset = (ObjectNode) applyPatch(r.linkset, Json.parse(body));
                send(ex, 204, null, null);
            }
            default -> send(ex, 405, null, null);
        }
    }

    private void typeIndex(HttpExchange ex) throws IOException {
        List<String> types = new ArrayList<>();
        synchronized (store) {
            for (Res r : store.values()) for (String t : r.types) if (!types.contains(t)) types.add(t);
        }
        types.add(Lws.Type.CONTAINER);
        types.add(Lws.Type.DATA_RESOURCE);
        ObjectNode o = Json.object();
        o.put("@context", Lws.LWS_CONTEXT);
        o.put("type", "TypeIndex");
        o.put("totalItems", types.size());
        ArrayNode items = o.putArray("items");
        types.forEach(t -> items.addObject().put("id", t));
        ex.getResponseHeaders().add("Cache-Control", "private");
        send(ex, 200, "application/lws+json", Json.toBytes(o));
    }

    private void search(HttpExchange ex, String method, byte[] body, String query) throws IOException {
        if (method.equals("OPTIONS")) {
            ex.getResponseHeaders().add("Allow", "OPTIONS, QUERY");
            ex.getResponseHeaders().add("Accept-Query", "application/lws-query+json");
            send(ex, 204, null, null);
            return;
        }
        if (method.equals("QUERY")) {
            if (!Lws.MediaType.LWS_QUERY_JSON.equals(ex.getRequestHeaders().getFirst("Content-Type"))) {
                ex.getResponseHeaders().add("Accept-Query", "application/lws-query+json");
                send(ex, 415, null, null);
                return;
            }
            JsonNode filter = Json.parse(body);
            List<String> matches = new ArrayList<>();
            synchronized (store) {
                for (Map.Entry<String, Res> e : store.entrySet()) {
                    boolean all = true;
                    for (JsonNode g : filter.path("type")) {
                        boolean any = false;
                        if (g.isTextual()) any = e.getValue().types.contains(g.textValue());
                        else for (JsonNode o : g) any |= e.getValue().types.contains(o.textValue());
                        all &= any;
                    }
                    if (all && !e.getValue().types.isEmpty()) matches.add(e.getKey());
                }
            }
            searchPage(ex, matches, 1);
            return;
        }
        if (method.equals("GET") && query != null && query.startsWith("cursor=")) {
            // second page: everything remaining (deterministic for the test)
            searchPage(ex, lastMatches, 2);
            return;
        }
        send(ex, 405, null, null);
    }

    private volatile List<String> lastMatches = List.of();

    private void searchPage(HttpExchange ex, List<String> matches, int page) throws IOException {
        lastMatches = matches;
        ObjectNode o = Json.object();
        o.put("@context", Lws.LWS_CONTEXT);
        o.put("type", "ContainerPage");
        o.put("totalItems", matches.size());
        ArrayNode items = o.putArray("items");
        List<String> slice = page == 1 ? matches.subList(0, Math.min(1, matches.size())) : matches.subList(Math.min(1, matches.size()), matches.size());
        for (String m : slice) items.addObject().put("id", base + m).putArray("type").add("DataResource");
        if (page == 1 && matches.size() > 1) ex.getResponseHeaders().add("Link", "<" + base + "/types/search?cursor=abc>; rel=\"next\"");
        ex.getResponseHeaders().add("Cache-Control", "private");
        send(ex, 200, "application/lws+json", Json.toBytes(o));
    }

    /** Minimal JSON Patch: add (object member or array '-'), replace, remove, test. */
    static JsonNode applyPatch(JsonNode doc, JsonNode patch) {
        JsonNode target = doc.deepCopy();
        for (JsonNode op : patch) {
            String path = op.path("path").asText();
            List<String> seg = com.ebremer.lws.patch.JsonPointer.segments(path);
            JsonNode parent = target;
            for (int i = 0; i < seg.size() - 1; i++) {
                parent = parent.isArray() ? parent.get(Integer.parseInt(seg.get(i))) : parent.get(seg.get(i));
                if (parent == null) throw new IllegalArgumentException("path not found " + path);
            }
            String last = seg.get(seg.size() - 1);
            switch (op.path("op").asText()) {
                case "add", "replace" -> {
                    if (parent.isArray()) {
                        if (last.equals("-")) ((ArrayNode) parent).add(op.get("value"));
                        else ((ArrayNode) parent).insert(Integer.parseInt(last), op.get("value"));
                    } else {
                        ((ObjectNode) parent).set(last, op.get("value"));
                    }
                }
                case "remove" -> {
                    if (parent.isArray()) ((ArrayNode) parent).remove(Integer.parseInt(last));
                    else ((ObjectNode) parent).remove(last);
                }
                case "test" -> {
                    if (!op.get("value").equals(parent.get(last))) throw new IllegalStateException("test failed");
                }
                default -> throw new IllegalArgumentException("unsupported op");
            }
        }
        return target;
    }

    private static void send(HttpExchange ex, int status, String contentType, byte[] body) throws IOException {
        send(ex, status, contentType, body, false);
    }

    private static void send(HttpExchange ex, int status, String contentType, byte[] body, boolean head) throws IOException {
        if (contentType != null) ex.getResponseHeaders().set("Content-Type", contentType);
        if (body == null || body.length == 0 || head || ex.getRequestMethod().equals("HEAD")) {
            ex.sendResponseHeaders(status, -1);
        } else {
            ex.sendResponseHeaders(status, body.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(body);
            }
        }
        ex.close();
    }

    private static byte[] readAll(InputStream in) throws IOException {
        try (in) {
            return in.readAllBytes();
        }
    }
}
