// SPDX-License-Identifier: MIT
package com.ebremer.lws.notify;

import com.ebremer.lws.LwsProtocolException;
import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.time.Instant;
import java.util.Optional;

/**
 * A subscription as returned by the notification service.
 *
 * @param type the subscription type ({@code WebhookSubscription})
 * @param subscription the URL managing the subscription (GET to inspect, DELETE to cancel)
 * @param expires when it expires, if parseable
 * @param expiresRaw the {@code expires} value as sent
 * @param raw the JSON document
 */
public record Subscription(String type, URI subscription, Optional<Instant> expires, Optional<String> expiresRaw, ObjectNode raw) {
    /**
     * Parses a subscription document; {@code location} (the {@code Location} header, or the request URL)
     * is used when the body lacks a {@code subscription} member.
     */
    public static Subscription parse(JsonNode json, URI base, URI location) {
        ObjectNode o = Json.requireObject(json, "Subscription");
        URI sub = Json.uri(o, "subscription", base);
        if (sub == null) sub = location;
        if (sub == null) throw new LwsProtocolException("Subscription response has no subscription URL");
        String exp = Json.text(o, "expires");
        String type = Json.stringOrArray(o.get("type")).stream().findFirst().orElse(null);
        return new Subscription(type, sub, Json.instant(exp), Optional.ofNullable(exp), o);
    }
}
