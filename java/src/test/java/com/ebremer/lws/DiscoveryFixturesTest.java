// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import com.ebremer.lws.auth.OpenIdCredentials;
import com.ebremer.lws.auth.TokenExchangeAuthenticator;
import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * The authorization flow after a {@code 401} ({@code conformance/fixtures/discovery.json}), run through the
 * {@link TokenExchangeAuthenticator} against one loopback listener reached as two origins:
 * {@code http://127.0.0.1:<port>} ({A}) and {@code http://localhost:<port>} ({B}), told apart by the
 * {@code Host} header.
 */
class DiscoveryFixturesTest {

    /** A request the server saw: method, absolute URL, {@code Authorization} and body. */
    private record Seen(String method, String url, String authorization, String body) {}

    /** Answers as the fixture's description says, for one case. */
    private static final class CaseServer implements AutoCloseable {
        final HttpServer server;
        final String a;
        final String b;
        final List<Seen> seen = Collections.synchronizedList(new ArrayList<>());
        volatile JsonNode testCase;
        volatile JsonNode tokenResponse;
        final Set<String> later = Collections.synchronizedSet(new HashSet<>());

        CaseServer() throws IOException {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0);
            int port = server.getAddress().getPort();
            a = "http://127.0.0.1:" + port;
            b = "http://localhost:" + port;
            server.createContext("/", this::handle);
            server.start();
        }

        /** The fixture text with {A} and {B} replaced by this server's two origins. */
        JsonNode substitute(JsonNode n) {
            return Json.parse(Json.toString(n).replace("{A}", a).replace("{B}", b));
        }

        @Override
        public void close() {
            server.stop(0);
        }

        private void handle(HttpExchange ex) throws IOException {
            String method = ex.getRequestMethod();
            String query = ex.getRequestURI().getRawQuery();
            String url = "http://" + ex.getRequestHeaders().getFirst("Host") + ex.getRequestURI().getRawPath()
                    + (query != null ? "?" + query : "");
            String authorization = ex.getRequestHeaders().getFirst("Authorization");
            String body;
            try (var in = ex.getRequestBody()) {
                body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            seen.add(new Seen(method, url, authorization, body));
            JsonNode document = testCase.get("documents").get(url);
            if (url.equals(testCase.get("request").asText())) {
                if ("Bearer token-1".equals(authorization)) {
                    send(ex, 200, Map.of("Content-Type", "text/plain"), "ok".getBytes(StandardCharsets.UTF_8));
                } else {
                    Map<String, String> headers = new HashMap<>();
                    testCase.get("challenge").properties().forEach(h -> headers.put(h.getKey(), h.getValue().asText()));
                    send(ex, 401, headers, null);
                }
            } else if (later.contains(url)) {
                send(ex, 200, Map.of("Content-Type", "text/plain"), "ok".getBytes(StandardCharsets.UTF_8));
            } else if (method.equals("GET") && document != null) {
                Map<String, String> headers = new HashMap<>();
                document.get("headers").properties().forEach(h -> headers.put(h.getKey(), h.getValue().asText()));
                JsonNode json = document.get("body");
                send(ex, document.get("status").asInt(), headers, json.isNull() ? null : Json.toBytes(json));
            } else if (method.equals("POST") && url.equals(a + "/as/token")) {
                send(ex, 200, Map.of("Content-Type", "application/json"), Json.toBytes(tokenResponse));
            } else {
                send(ex, 404, Map.of(), null);
            }
        }

        private static void send(HttpExchange ex, int status, Map<String, String> headers, byte[] body) throws IOException {
            headers.forEach((k, v) -> ex.getResponseHeaders().add(k, v));
            if (body == null) {
                ex.sendResponseHeaders(status, -1);
            } else {
                ex.sendResponseHeaders(status, body.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(body);
                }
            }
            ex.close();
        }

        List<Seen> tokenRequests() {
            synchronized (seen) {
                return seen.stream().filter(s -> s.method().equals("POST") && s.url().equals(a + "/as/token")).toList();
            }
        }
    }

    @TestFactory
    Stream<DynamicTest> discovery() {
        JsonNode fixture = Fixtures.json("discovery.json");
        List<JsonNode> cases = new ArrayList<>();
        fixture.get("cases").forEach(cases::add);
        return cases.stream().map(raw -> dynamicTest(raw.get("name").asText(), () -> {
            try (CaseServer server = new CaseServer()) {
                JsonNode c = server.substitute(raw);
                server.testCase = c;
                server.tokenResponse = fixture.get("tokenResponse");
                LwsClient client = LwsClient.builder()
                        .authenticator(TokenExchangeAuthenticator.of(OpenIdCredentials.of("id-token-1")))
                        .build();
                URI request = URI.create(c.get("request").asText());
                JsonNode expected = c.get("expected");
                switch (expected.get("outcome").asText()) {
                    case "ok" -> {
                        assertEquals("ok", client.read(request).text());
                        Seen last = server.seen.get(server.seen.size() - 1);
                        assertEquals(request.toString(), last.url(), "the request is retried");
                        assertEquals("Bearer token-1", last.authorization(), "the retry carries the token");
                    }
                    case "AuthenticationError" -> assertThrows(AuthenticationException.class, () -> client.read(request));
                    case "UnauthorizedError" -> assertThrows(UnauthorizedException.class, () -> client.read(request));
                    default -> fail("unknown outcome " + expected.get("outcome"));
                }

                List<Seen> tokens = server.tokenRequests();
                JsonNode tokenRequest = expected.get("tokenRequest");
                if (tokenRequest.isNull()) {
                    assertEquals(List.of(), tokens, "no token request");
                } else {
                    assertEquals(1, tokens.size(), "one token request");
                    assertEquals(tokenRequest.get("endpoint").asText(), tokens.get(0).url());
                    assertEquals(tokenRequest.get("resource").asText(), form(tokens.get(0).body()).get("resource"));
                }
                for (JsonNode n : expected.get("notFetched")) {
                    synchronized (server.seen) {
                        assertFalse(server.seen.stream().anyMatch(s -> s.url().equals(n.asText())), n.asText() + " was requested");
                    }
                }

                for (JsonNode then : expected.path("then")) {
                    String url = then.get("request").asText();
                    server.later.add(url);
                    int before = server.seen.size();
                    assertEquals("ok", client.read(URI.create(url)).text());
                    assertEquals(before + 1, server.seen.size(), url + " in one request");
                    Seen s = server.seen.get(before);
                    assertEquals(then.get("sendsToken").asBoolean() ? "Bearer token-1" : null, s.authorization(), url);
                }
                if (expected.get("outcome").asText().equals("ok")) {
                    // The URL again: inside the token's scope it carries the token up front, outside it its 401
                    // reuses the cached token.
                    assertEquals("ok", client.read(request).text());
                    assertEquals(1, server.tokenRequests().size(), "no second token request");
                }
            }
        }));
    }

    private static Map<String, String> form(String body) {
        Map<String, String> out = new HashMap<>();
        for (String kv : body.split("&")) {
            int i = kv.indexOf('=');
            if (i > 0) {
                out.put(URLDecoder.decode(kv.substring(0, i), StandardCharsets.UTF_8),
                        URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8));
            }
        }
        return out;
    }
}
