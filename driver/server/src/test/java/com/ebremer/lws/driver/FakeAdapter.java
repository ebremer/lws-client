// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * An adapter for the tests: it speaks lws-driver/1 but drives no library. It answers {@code read},
 * {@code create}, {@code delete} and {@code verify_notification} with canned results, so that the server's
 * plumbing can be tested without any language toolchain.
 */
public final class FakeAdapter {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private FakeAdapter() {
    }

    public static void main(String[] args) throws Exception {
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        System.setOut(System.err);
        System.err.println("fake adapter started");
        ObjectNode hello = JSON.createObjectNode();
        ObjectNode h = hello.putObject("hello");
        h.put("protocol", "lws-driver/1");
        h.put("language", "fake");
        h.put("library", "lws-client-fake/0.0.1");
        List.of("configure", "read", "create", "delete", "verify_notification", "shutdown").forEach(h.putArray("operations")::add);
        out.println(JSON.writeValueAsString(hello));

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            JsonNode request = JSON.readTree(line);
            long id = request.get("id").asLong();
            String op = request.get("op").asString();
            JsonNode a = request.path("args");
            ObjectNode response = JSON.createObjectNode();
            response.put("id", id);
            switch (op) {
                case "configure" -> {
                    if (a.path("auth").path("type").asString().equals("explode")) {
                        error(response, "InvalidArguments", 0, "unknown auth type 'explode'");
                    } else {
                        ObjectNode result = ok(response);
                        result.put("library", "lws-client-fake/0.0.1");
                        if (a.path("auth").path("type").asString().equals("didKey")) {
                            result.put("agent", "did:key:zFake");
                            result.put("kid", "did:key:zFake#zFake");
                        }
                    }
                }
                case "read" -> {
                    String url = a.path("url").asString();
                    if (url.isEmpty()) {
                        error(response, "InvalidArguments", 0, "missing argument 'url'");
                    } else if (url.endsWith("/missing")) {
                        error(response, "NotFoundError", 404, "GET " + url + " -> 404");
                    } else {
                        ObjectNode result = ok(response);
                        ObjectNode metadata = result.putObject("metadata");
                        metadata.put("url", url);
                        metadata.put("status", 200);
                        result.put("notModified", false);
                        result.putObject("body").put("text", "hello " + url);
                    }
                }
                case "create" -> {
                    ObjectNode result = ok(response);
                    result.put("location", a.path("container").asString() + a.path("slug").asString("x"));
                    result.set("echo", a);
                }
                case "delete" -> {
                    if (a.path("url").asString().contains("slow")) {
                        Thread.sleep(30_000);
                    }
                    ok(response);
                }
                case "verify_notification" -> {
                    String body = new String(Base64.getDecoder().decode(a.path("bodyBase64").asString()), StandardCharsets.UTF_8);
                    if (body.contains("forged")) {
                        error(response, "SignatureVerificationError", 0, "signature does not verify");
                    } else {
                        ObjectNode result = ok(response);
                        result.put("storage", "https://storage.example/");
                        result.put("keyid", "https://storage.example/#key");
                        result.put("inboxUrl", a.path("url").asString());
                        result.set("headers", a.path("headers"));
                        result.putArray("activities");
                    }
                }
                case "shutdown" -> ok(response);
                default -> error(response, "Unsupported", 0, "unknown operation '" + op + "'");
            }
            out.println(JSON.writeValueAsString(response));
            if (op.equals("shutdown")) {
                return;
            }
        }
    }

    private static ObjectNode ok(ObjectNode response) {
        response.put("ok", true);
        return response.putObject("result");
    }

    private static void error(ObjectNode response, String kind, int status, String message) {
        response.put("ok", false);
        ObjectNode error = response.putObject("error");
        error.put("kind", kind);
        if (status > 0) {
            error.put("status", status);
        }
        error.put("message", message);
    }
}
