// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.mcp;

import com.ebremer.lws.driver.DriverException;
import com.ebremer.lws.driver.DriverProperties;
import com.ebremer.lws.driver.adapter.AdapterProcess;
import com.ebremer.lws.driver.adapter.Commands;
import com.ebremer.lws.driver.adapter.Hello;
import com.ebremer.lws.driver.clients.ClientRegistry;
import com.ebremer.lws.driver.clients.DriverClient;
import com.ebremer.lws.driver.clients.Inbox;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The driver's own tools: which languages it can drive, starting and stopping clients, their logs, and their
 * inboxes. The LWS operations themselves are {@link OperationTools}.
 */
@Component
public class DriverTools {

    private final ClientRegistry clients;
    private final OperationCatalog catalog;
    private final DriverProperties properties;
    private final JsonMapper json;

    public DriverTools(ClientRegistry clients, OperationCatalog catalog, DriverProperties properties, JsonMapper json) {
        this.clients = clients;
        this.catalog = catalog;
        this.properties = properties;
        this.json = json;
    }

    @McpTool(name = "list_languages", title = "List the languages",
            description = "The languages the driver can drive, and whether each one's adapter is built and ready. With"
                    + " probe, each available adapter is started once to report its library and the operations it lacks.",
            annotations = @McpTool.McpAnnotations(readOnlyHint = true, idempotentHint = true, openWorldHint = false))
    public CallToolResult listLanguages(
            @McpToolParam(description = "Start each available adapter to read its hello.", required = false) Boolean probe) {
        return run(() -> {
            ObjectNode result = json.createObjectNode();
            ArrayNode list = result.putArray("languages");
            clients.languages().entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(e -> {
                DriverProperties.Language language = e.getValue();
                ObjectNode entry = list.addObject();
                entry.put("language", e.getKey());
                if (language.description() != null) {
                    entry.put("description", language.description());
                }
                entry.put("command", String.join(" ", language.command()));
                List<String> missing = Commands.missing(language.command(), properties.homeDirectory());
                entry.put("available", missing.isEmpty());
                if (!missing.isEmpty()) {
                    ArrayNode m = entry.putArray("missing");
                    missing.forEach(m::add);
                }
                if (Boolean.TRUE.equals(probe) && missing.isEmpty()) {
                    try (AdapterProcess adapter = clients.probe(e.getKey())) {
                        Hello hello = adapter.hello();
                        entry.put("library", hello.library());
                        ArrayNode unsupported = entry.putArray("unsupported");
                        catalog.names().stream().filter(op -> !hello.supports(op)).forEach(unsupported::add);
                    } catch (DriverException ex) {
                        entry.put("available", false);
                        entry.put("probeError", ex.getMessage());
                    }
                }
            });
            return result;
        });
    }

    @McpTool(name = "start_client", title = "Start a client",
            description = "Start a client: the given language's lws-client, in an adapter process of its own, with one"
                    + " identity. authType none sends no credentials; bearer sends token (only inside realm, when given);"
                    + " openid exchanges idToken at the storage's authorization server; selfSigned signs credentials for"
                    + " agent with privateJwk (kid defaults to the JWK's kid); didKey makes a fresh did:key identity."
                    + " Returns the client id that the operation tools take.",
            annotations = @McpTool.McpAnnotations(readOnlyHint = false, destructiveHint = false, openWorldHint = false))
    public CallToolResult startClient(
            @McpToolParam(description = "The language: java, js, python, go, rust, cpp, csharp or wasm (see list_languages).") String language,
            @McpToolParam(description = "none, bearer, openid, selfSigned or didKey; default none.", required = false) String authType,
            @McpToolParam(description = "bearer: the access token.", required = false) String token,
            @McpToolParam(description = "bearer: send the token only to URLs inside this realm.", required = false) String realm,
            @McpToolParam(description = "openid: the ID Token to exchange.", required = false) String idToken,
            @McpToolParam(description = "selfSigned: the agent's URL, whose identity document lists the key.", required = false) String agent,
            @McpToolParam(description = "selfSigned: the private key, a JWK (EC P-256 or OKP Ed25519).", required = false) Map<String, Object> privateJwk,
            @McpToolParam(description = "selfSigned: the key id for the JWT header; defaults to the JWK's kid.", required = false) String kid,
            @McpToolParam(description = "didKey: ES256 (default) or EdDSA.", required = false) String algorithm,
            @McpToolParam(description = "Allow an authorization server on plain http (testing only).", required = false) Boolean allowInsecureHttp,
            @McpToolParam(description = "The User-Agent header.", required = false) String userAgent,
            @McpToolParam(description = "The per-request timeout, in seconds.", required = false) Integer timeoutSeconds,
            @McpToolParam(description = "Extra headers on every request.", required = false) Map<String, String> headers,
            @McpToolParam(description = "A name for the client, shown in list_clients.", required = false) String label) {
        return run(() -> {
            ObjectNode configuration = json.createObjectNode();
            ObjectNode auth = configuration.putObject("auth");
            auth.put("type", authType == null || authType.isBlank() ? "none" : authType);
            putIfPresent(auth, "token", token);
            putIfPresent(auth, "realm", realm);
            putIfPresent(auth, "idToken", idToken);
            putIfPresent(auth, "agent", agent);
            if (privateJwk != null) {
                auth.set("privateJwk", json.valueToTree(privateJwk));
            }
            putIfPresent(auth, "kid", kid);
            putIfPresent(auth, "algorithm", algorithm);
            if (allowInsecureHttp != null) {
                configuration.put("allowInsecureHttp", allowInsecureHttp);
            }
            putIfPresent(configuration, "userAgent", userAgent);
            if (timeoutSeconds != null) {
                configuration.put("timeoutSeconds", timeoutSeconds);
            }
            if (headers != null) {
                configuration.set("headers", json.valueToTree(headers));
            }
            return describe(clients.start(language, configuration, label));
        });
    }

    @McpTool(name = "list_clients", title = "List the clients",
            description = "The clients the driver runs, with their language, library, identity and inbox.",
            annotations = @McpTool.McpAnnotations(readOnlyHint = true, idempotentHint = true, openWorldHint = false))
    public CallToolResult listClients() {
        return run(() -> {
            ObjectNode result = json.createObjectNode();
            ArrayNode list = result.putArray("clients");
            clients.clients().forEach(c -> list.add(describe(c)));
            return result;
        });
    }

    @McpTool(name = "stop_client", title = "Stop a client",
            description = "Stop a client and its adapter. Its inbox stops with it.",
            annotations = @McpTool.McpAnnotations(readOnlyHint = false, destructiveHint = true, idempotentHint = false,
                    openWorldHint = false))
    public CallToolResult stopClient(@McpToolParam(description = "The client id.") String client) {
        return run(() -> {
            clients.stop(client);
            ObjectNode result = json.createObjectNode();
            result.put("stopped", client);
            return result;
        });
    }

    @McpTool(name = "client_log", title = "Read a client's log",
            description = "The last lines the client's adapter wrote to stderr, and the driver's notes about it.",
            annotations = @McpTool.McpAnnotations(readOnlyHint = true, idempotentHint = true, openWorldHint = false))
    public CallToolResult clientLog(
            @McpToolParam(description = "The client id.") String client,
            @McpToolParam(description = "How many lines, at most (default 200).", required = false) Integer lines) {
        return run(() -> {
            ObjectNode result = json.createObjectNode();
            result.put("client", client);
            ArrayNode list = result.putArray("lines");
            clients.log(client, lines == null ? 200 : Math.max(0, lines)).forEach(list::add);
            return result;
        });
    }

    @McpTool(name = "open_inbox", title = "Open a client's inbox",
            description = "Give the client a webhook inbox on the driver's HTTP server. Notifications delivered to it are"
                    + " verified with the client's own library, answered 202 when they verify and 401 when they do not,"
                    + " and kept for inbox_deliveries. subscribe uses it when no inbox is given. The storage must be able"
                    + " to reach the driver at its public base URL (lws.driver.public-base-url).",
            annotations = @McpTool.McpAnnotations(readOnlyHint = false, destructiveHint = false, idempotentHint = true,
                    openWorldHint = false))
    public CallToolResult openInbox(
            @McpToolParam(description = "The client id.") String client,
            @McpToolParam(description = "Accept notifications from these storages only.", required = false) List<String> trustedStorages) {
        return run(() -> {
            Inbox inbox = clients.openInbox(client, trustedStorages == null ? List.of() : trustedStorages);
            ObjectNode result = json.createObjectNode();
            result.put("client", client);
            result.put("inbox", inbox.url());
            return result;
        });
    }

    @McpTool(name = "inbox_deliveries", title = "Read a client's inbox",
            description = "The notifications delivered to the client's inbox, oldest first: each one's headers, body, whether"
                    + " the client's verifier accepted it, the status the inbox answered, and the verifier's result.",
            annotations = @McpTool.McpAnnotations(readOnlyHint = true, idempotentHint = true, openWorldHint = false))
    public CallToolResult inboxDeliveries(
            @McpToolParam(description = "The client id.") String client,
            @McpToolParam(description = "Only deliveries after this sequence number.", required = false) Long after) {
        return run(() -> {
            DriverClient c = clients.get(client);
            Inbox inbox = c.inbox();
            if (inbox == null) {
                throw new DriverException("client " + client + " has no inbox; open one with open_inbox");
            }
            ObjectNode result = json.createObjectNode();
            result.put("client", client);
            result.put("inbox", inbox.url());
            ArrayNode list = result.putArray("deliveries");
            for (Inbox.Delivery d : inbox.deliveries(after == null ? 0 : after)) {
                ObjectNode entry = list.addObject();
                entry.put("sequence", d.sequence());
                entry.put("received", d.received().toString());
                entry.put("method", d.method());
                entry.set("headers", json.valueToTree(d.headers()));
                entry.put("body", d.body());
                entry.put("bodyBytes", d.bodyBytes());
                entry.put("verified", d.verified());
                entry.put("answer", d.answer());
                entry.set("outcome", d.outcome());
            }
            return result;
        });
    }

    private ObjectNode describe(DriverClient client) {
        ObjectNode entry = json.createObjectNode();
        entry.put("client", client.id());
        entry.put("language", client.language());
        if (client.label() != null) {
            entry.put("label", client.label());
        }
        entry.put("library", client.hello().library());
        if (client.configured().has("agent")) {
            entry.set("agent", client.configured().get("agent"));
        }
        if (client.configured().has("kid")) {
            entry.set("kid", client.configured().get("kid"));
        }
        ArrayNode unsupported = entry.putArray("unsupported");
        catalog.names().stream().filter(op -> !client.hello().supports(op)).forEach(unsupported::add);
        entry.put("created", client.created().toString());
        entry.put("lastUsed", client.lastUsed().toString());
        if (client.inbox() != null) {
            entry.put("inbox", client.inbox().url());
        }
        return entry;
    }

    private CallToolResult run(Supplier<ObjectNode> body) {
        try {
            return ToolResults.of(json, body.get());
        } catch (DriverException e) {
            return ToolResults.failure(e.getMessage());
        }
    }

    private static void putIfPresent(ObjectNode node, String name, String value) {
        if (value != null && !value.isBlank()) {
            node.put(name, value);
        }
    }
}
