// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.clients;

import com.ebremer.lws.driver.DriverException;
import com.ebremer.lws.driver.DriverProperties;
import com.ebremer.lws.driver.adapter.AdapterProcess;
import jakarta.annotation.PreDestroy;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/** The clients the driver runs, and the operations it sends them. */
@Service
public class ClientRegistry {

    /** The arguments that name a URL the client requests, and so must be inside the allowed targets. */
    private static final Set<String> TARGET_ARGUMENTS = Set.of("url", "container", "parent", "linksetUrl", "serviceUrl");
    private static final int BODY_KEPT = 64 * 1024;

    private static final Logger LOG = LoggerFactory.getLogger(ClientRegistry.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final DriverProperties properties;
    private final JsonMapper json;
    private final Environment environment;
    private final Map<String, DriverClient> clients = new ConcurrentHashMap<>();

    public ClientRegistry(DriverProperties properties, JsonMapper json, Environment environment) {
        this.properties = properties;
        this.json = json;
        this.environment = environment;
    }

    /** The languages configured, by name. */
    public Map<String, DriverProperties.Language> languages() {
        return properties.languages();
    }

    /** Starts a language's adapter on its own, reads its hello, and stops it. */
    public AdapterProcess probe(String language) {
        return startAdapter(language, language + "-probe");
    }

    /**
     * Starts a client: a new adapter for {@code language}, configured with {@code configuration} (the
     * {@code configure} arguments of driver/PROTOCOL.md).
     *
     * @throws DriverException when the language is unknown, the adapter will not start, or configure fails
     */
    public DriverClient start(String language, ObjectNode configuration, String label) {
        if (clients.size() >= properties.maxClients()) {
            throw new DriverException("the driver already runs " + clients.size() + " clients, its limit"
                    + " (lws.driver.max-clients); stop one first");
        }
        String id = language + "-" + HexFormat.of().formatHex(randomBytes(4));
        AdapterProcess adapter = startAdapter(language, id);
        try {
            ObjectNode response = adapter.call("configure", configuration, properties.operationTimeout());
            if (!response.path("ok").asBoolean()) {
                throw new DriverException("configure failed: " + response.get("error"));
            }
            DriverClient client = new DriverClient(id, language, label, configuration, (ObjectNode) response.get("result"), adapter);
            clients.put(id, client);
            LOG.info("started {} ({}{})", id, adapter.hello().library(), label == null ? "" : ", " + label);
            return client;
        } catch (RuntimeException e) {
            adapter.close();
            throw e;
        }
    }

    public DriverClient get(String id) {
        DriverClient client = id == null ? null : clients.get(id);
        if (client == null) {
            throw new DriverException("no client " + id + "; start one with start_client, or see list_clients");
        }
        return client;
    }

    public Collection<DriverClient> clients() {
        List<DriverClient> list = new ArrayList<>(clients.values());
        list.sort(Comparator.comparing(DriverClient::created));
        return list;
    }

    public void stop(String id) {
        DriverClient client = clients.remove(id);
        if (client == null) {
            throw new DriverException("no client " + id);
        }
        close(client);
    }

    /**
     * Sends one operation to a client and returns its response, {@code {"ok": …, "result" | "error": …}}. An
     * operation the client's adapter does not implement is an {@code Unsupported} outcome, without asking it.
     */
    public ObjectNode call(String id, String op, ObjectNode args) {
        DriverClient client = get(id);
        client.touch();
        if (!client.hello().supports(op)) {
            ObjectNode response = json.createObjectNode();
            response.put("ok", false);
            ObjectNode error = response.putObject("error");
            error.put("kind", "Unsupported");
            error.put("message", "the " + client.language() + " adapter does not implement " + op);
            return response;
        }
        checkTargets(args);
        if (op.equals("subscribe") && !args.hasNonNull("inbox")) {
            Inbox inbox = client.inbox();
            if (inbox == null) {
                throw new DriverException("subscribe needs an inbox: pass one, or open the client's own with open_inbox");
            }
            args.put("inbox", inbox.url());
        }
        return client.adapter().call(op, args, properties.operationTimeout());
    }

    /** The client's adapter log, the last {@code lines} lines. */
    public List<String> log(String id, int lines) {
        return get(id).adapter().log(lines);
    }

    /**
     * Opens the client's inbox, or returns the one it has. Deliveries to its URL are verified with the client's
     * own library and recorded.
     */
    public Inbox openInbox(String id, List<String> trustedStorages) {
        DriverClient client = get(id);
        synchronized (client) {
            if (client.inbox() == null) {
                String key = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(18));
                String url = baseUrl() + "/inbox/" + client.id() + "/" + key;
                client.inbox(new Inbox(key, url, trustedStorages, () -> startVerifier(client)));
            }
            return client.inbox();
        }
    }

    /**
     * Takes one delivery to a client's inbox: verifies it with the client's library and records it.
     *
     * @return the delivery, with the status to answer it with, or null when there is no such inbox
     */
    public Inbox.Delivery deliver(String id, String key, String method, Map<String, List<String>> headers, byte[] body) {
        DriverClient client = clients.get(id);
        Inbox inbox = client == null ? null : client.inbox();
        if (inbox == null || !MessageDigest.isEqual(
                inbox.key().getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8))) {
            return null;
        }
        ObjectNode args = json.createObjectNode();
        args.put("method", method);
        args.put("url", inbox.url());
        ObjectNode headerArgs = args.putObject("headers");
        headers.forEach((name, values) -> {
            ArrayNode list = headerArgs.putArray(name);
            values.forEach(list::add);
        });
        args.put("bodyBase64", Base64.getEncoder().encodeToString(body));
        if (!inbox.trustedStorages().isEmpty()) {
            ArrayNode trusted = args.putArray("trustedStorages");
            inbox.trustedStorages().forEach(trusted::add);
        }
        ObjectNode outcome;
        int answer;
        try {
            outcome = inbox.verifier().call("verify_notification", args, properties.operationTimeout());
            boolean verified = outcome.path("ok").asBoolean();
            answer = verified ? 202 : "SignatureVerificationError".equals(outcome.path("error").path("kind").asString()) ? 401 : 400;
        } catch (DriverException e) {
            outcome = json.createObjectNode();
            outcome.put("ok", false);
            ObjectNode error = outcome.putObject("error");
            error.put("kind", "DriverError");
            error.put("message", e.getMessage());
            answer = 503;
        }
        String text = new String(body, StandardCharsets.UTF_8);
        if (text.length() > BODY_KEPT) {
            text = text.substring(0, BODY_KEPT);
        }
        return inbox.record(method, headers, text, body.length, answer == 202, answer, outcome);
    }

    /** Stops clients that have not been used for {@code lws.driver.idle-timeout}. */
    @Scheduled(fixedDelay = 60_000)
    void stopIdle() {
        Instant cutoff = Instant.now().minus(properties.idleTimeout());
        for (DriverClient client : clients.values()) {
            if (client.lastUsed().isBefore(cutoff) && clients.remove(client.id(), client)) {
                LOG.info("stopping {}: unused for {}", client.id(), properties.idleTimeout());
                close(client);
            }
        }
    }

    @PreDestroy
    void stopAll() {
        for (String id : List.copyOf(clients.keySet())) {
            DriverClient client = clients.remove(id);
            if (client != null) {
                close(client);
            }
        }
    }

    private void close(DriverClient client) {
        Inbox inbox = client.inbox();
        if (inbox != null) {
            inbox.close();
        }
        client.adapter().close();
        LOG.info("stopped {}", client.id());
    }

    private AdapterProcess startAdapter(String language, String name) {
        DriverProperties.Language config = properties.languages().get(language);
        if (config == null) {
            throw new DriverException("no language " + language + "; the driver has " + String.join(", ",
                    properties.languages().keySet().stream().sorted().toList()));
        }
        return AdapterProcess.start(name, config.command(), properties.homeDirectory(), config.environment(), json,
                properties.startupTimeout());
    }

    private AdapterProcess startVerifier(DriverClient client) {
        AdapterProcess verifier = startAdapter(client.language(), client.id() + "-inbox");
        ObjectNode response = verifier.call("configure", client.configuration().deepCopy(), properties.operationTimeout());
        if (!response.path("ok").asBoolean()) {
            verifier.close();
            throw new DriverException("configure failed for the inbox verifier: " + response.get("error"));
        }
        return verifier;
    }

    private void checkTargets(ObjectNode args) {
        if (properties.allowedTargets().isEmpty()) {
            return;
        }
        for (String name : TARGET_ARGUMENTS) {
            JsonNode value = args.get(name);
            if (value != null && value.isString()) {
                String url = value.asString();
                if (properties.allowedTargets().stream().noneMatch(url::startsWith)) {
                    throw new DriverException(name + " " + url + " is outside the targets this driver may address"
                            + " (lws.driver.allowed-targets)");
                }
            }
        }
    }

    private String baseUrl() {
        if (properties.publicBaseUrl() != null && !properties.publicBaseUrl().isBlank()) {
            return properties.publicBaseUrl().replaceAll("/+$", "");
        }
        String port = environment.getProperty("local.server.port");
        if (port == null) {
            throw new DriverException("an inbox needs the driver's HTTP server, which is not running (stdio mode?)");
        }
        String host = environment.getProperty("server.address", "127.0.0.1");
        if (host.equals("0.0.0.0") || host.equals("::")) {
            host = "127.0.0.1";
        }
        return "http://" + (host.contains(":") ? "[" + host + "]" : host) + ":" + port;
    }

    private static byte[] randomBytes(int n) {
        byte[] bytes = new byte[n];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}
