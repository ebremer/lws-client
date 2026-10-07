// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.clients;

import com.ebremer.lws.driver.adapter.AdapterProcess;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import tools.jackson.databind.node.ObjectNode;

/**
 * A client's webhook inbox. The driver's HTTP server receives the deliveries; the client's own library
 * verifies them, in an adapter process of its own so that a delivery that arrives while the client is busy
 * never waits for it.
 */
public final class Inbox {

    private static final int KEPT = 200;

    private final String key;
    private final String url;
    private final List<String> trustedStorages;
    private final Supplier<AdapterProcess> verifierFactory;
    private final Deque<Delivery> deliveries = new ArrayDeque<>();
    private long sequence;
    private AdapterProcess verifier;

    Inbox(String key, String url, List<String> trustedStorages, Supplier<AdapterProcess> verifierFactory) {
        this.key = key;
        this.url = url;
        this.trustedStorages = List.copyOf(trustedStorages);
        this.verifierFactory = verifierFactory;
    }

    /** The secret path segment that tells this inbox's deliveries from guesses. */
    public String key() {
        return key;
    }

    /** The inbox URL, as a subscription registers it. */
    public String url() {
        return url;
    }

    /** Storages whose notifications the verifier accepts; empty accepts any. */
    public List<String> trustedStorages() {
        return trustedStorages;
    }

    /** The adapter that verifies deliveries, started on first use. */
    synchronized AdapterProcess verifier() {
        if (verifier == null || !verifier.isAlive()) {
            verifier = verifierFactory.get();
        }
        return verifier;
    }

    synchronized void close() {
        if (verifier != null) {
            verifier.close();
            verifier = null;
        }
    }

    synchronized Delivery record(String method, Map<String, List<String>> headers, String body, int bodyBytes,
            boolean verified, int answer, ObjectNode outcome) {
        Delivery delivery = new Delivery(++sequence, Instant.now(), method, headers, body, bodyBytes, verified, answer, outcome);
        if (deliveries.size() == KEPT) {
            deliveries.removeFirst();
        }
        deliveries.addLast(delivery);
        return delivery;
    }

    /** The deliveries after sequence number {@code after}, oldest first. */
    public synchronized List<Delivery> deliveries(long after) {
        List<Delivery> list = new ArrayList<>();
        for (Delivery d : deliveries) {
            if (d.sequence() > after) {
                list.add(d);
            }
        }
        return list;
    }

    /**
     * One notification delivery, and what became of it.
     *
     * @param sequence its number, counting from 1
     * @param body the body as text, cut to 64 KiB
     * @param bodyBytes the body's length in bytes
     * @param verified whether the client's verifier accepted it
     * @param answer the status the inbox answered with
     * @param outcome the verifier's response: the verified notification, or the error
     */
    public record Delivery(long sequence, Instant received, String method, Map<String, List<String>> headers, String body,
            int bodyBytes, boolean verified, int answer, ObjectNode outcome) {
    }
}
