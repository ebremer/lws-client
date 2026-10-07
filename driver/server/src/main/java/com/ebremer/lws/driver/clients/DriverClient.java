// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.clients;

import com.ebremer.lws.driver.adapter.AdapterProcess;
import com.ebremer.lws.driver.adapter.Hello;
import java.time.Instant;
import tools.jackson.databind.node.ObjectNode;

/**
 * A client the driver runs: one language's lws-client, configured once, in an adapter process of its own.
 */
public final class DriverClient {

    private final String id;
    private final String language;
    private final String label;
    private final Instant created;
    private final ObjectNode configuration;
    private final ObjectNode configured;
    private final AdapterProcess adapter;
    private volatile Instant lastUsed;
    private volatile Inbox inbox;

    DriverClient(String id, String language, String label, ObjectNode configuration, ObjectNode configured,
            AdapterProcess adapter) {
        this.id = id;
        this.language = language;
        this.label = label;
        this.created = Instant.now();
        this.lastUsed = created;
        this.configuration = configuration;
        this.configured = configured;
        this.adapter = adapter;
    }

    public String id() {
        return id;
    }

    public String language() {
        return language;
    }

    /** A name the caller gave the client, or null. */
    public String label() {
        return label;
    }

    public Instant created() {
        return created;
    }

    public Instant lastUsed() {
        return lastUsed;
    }

    void touch() {
        lastUsed = Instant.now();
    }

    public Hello hello() {
        return adapter.hello();
    }

    /** The {@code configure} arguments the client was started with. */
    ObjectNode configuration() {
        return configuration;
    }

    /** The {@code configure} result: the library, and the agent and key id of a self-signed identity. */
    public ObjectNode configured() {
        return configured;
    }

    AdapterProcess adapter() {
        return adapter;
    }

    /** The client's inbox, or null until one is opened. */
    public Inbox inbox() {
        return inbox;
    }

    void inbox(Inbox inbox) {
        this.inbox = inbox;
    }
}
