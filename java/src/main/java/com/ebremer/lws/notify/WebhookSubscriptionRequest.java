// SPDX-License-Identifier: MIT
package com.ebremer.lws.notify;

import com.ebremer.lws.Lws;
import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A webhook subscription request ({@code lws10-notifications-webhook}). A container topic covers the
 * container and everything transitively contained in it.
 *
 * @param topics the resources to watch
 * @param inbox where the server POSTs notifications
 * @param expires when the subscription should expire
 */
public record WebhookSubscriptionRequest(List<URI> topics, URI inbox, Optional<Instant> expires) {
    public WebhookSubscriptionRequest {
        topics = List.copyOf(topics);
        if (topics.isEmpty()) throw new IllegalArgumentException("At least one topic is required");
        Objects.requireNonNull(inbox, "inbox");
        expires = expires == null ? Optional.empty() : expires;
    }

    /** A request without expiry. */
    public static WebhookSubscriptionRequest of(URI inbox, URI... topics) {
        return new WebhookSubscriptionRequest(List.of(topics), inbox, Optional.empty());
    }

    /** Returns a copy expiring at {@code expires}. */
    public WebhookSubscriptionRequest withExpires(Instant expires) {
        return new WebhookSubscriptionRequest(topics, inbox, Optional.of(expires));
    }

    /** The {@code application/lws+json} request body. */
    public ObjectNode toJson() {
        ObjectNode o = Json.object();
        o.putArray("@context").add(Lws.LWS_CONTEXT);
        o.put("type", Lws.Subscription.WEBHOOK);
        ArrayNode t = o.putArray("topic");
        for (URI u : topics) t.add(u.toString());
        o.put("inbox", inbox.toString());
        expires.ifPresent(e -> o.put("expires", e.toString()));
        return o;
    }
}
