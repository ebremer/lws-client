// SPDX-License-Identifier: MIT
package com.ebremer.lws.notify;

import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

/**
 * Adapter for receiving webhooks with the JDK's built-in {@code com.sun.net.httpserver} server. Using
 * this class requires the {@code jdk.httpserver} module (optional for the rest of the library).
 */
public final class HttpExchangeWebhooks {
    private HttpExchangeWebhooks() {}

    /**
     * Reads and verifies the delivery in {@code exchange}. The response is left to the caller (answer
     * {@code 2xx} on success).
     *
     * @param inboxUrl the inbox URL as registered in the subscription
     */
    public static VerifiedNotification verify(WebhookVerifier verifier, HttpExchange exchange, URI inboxUrl) throws IOException {
        byte[] body;
        try (InputStream in = exchange.getRequestBody()) {
            body = in.readAllBytes();
        }
        return verifier.verify(exchange.getRequestMethod(), inboxUrl, exchange.getRequestHeaders(), body);
    }
}
