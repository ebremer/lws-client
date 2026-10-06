// SPDX-License-Identifier: MIT
package com.ebremer.lws.examples;

import com.ebremer.lws.LwsClient;
import com.ebremer.lws.SignatureVerificationException;
import com.ebremer.lws.StorageDescription;
import com.ebremer.lws.auth.KeyPairs;
import com.ebremer.lws.auth.SelfSignedCredentials;
import com.ebremer.lws.auth.TokenExchangeAuthenticator;
import com.ebremer.lws.notify.HttpExchangeWebhooks;
import com.ebremer.lws.notify.Notification;
import com.ebremer.lws.notify.Subscription;
import com.ebremer.lws.notify.VerifiedNotification;
import com.ebremer.lws.notify.WebhookSubscriptionRequest;
import com.ebremer.lws.notify.WebhookVerifier;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.List;

/**
 * Receives and verifies webhook notifications (RFC 9421 signatures) for changes in a storage root.
 *
 * <pre>
 * java ... com.ebremer.lws.examples.WebhookReceiver http://localhost:8787/root/ 9090
 * </pre>
 */
public final class WebhookReceiver {
    public static void main(String[] args) throws Exception {
        URI start = URI.create(args.length > 0 ? args[0] : "http://localhost:8787/root/");
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 9090;

        LwsClient client = LwsClient.builder()
                .authenticator(TokenExchangeAuthenticator.of(SelfSignedCredentials.didKey(KeyPairs.generateP256())))
                .build();
        StorageDescription storage = client.discoverStorage(start);

        // The verifier fetches the storage description to find the signing key named by the keyid.
        WebhookVerifier verifier = WebhookVerifier.builder()
                .client(client)
                .trustedStorages(List.of(storage.id()))
                .build();

        URI inbox = URI.create("http://127.0.0.1:" + port + "/inbox");
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/inbox", exchange -> {
            try {
                VerifiedNotification v = HttpExchangeWebhooks.verify(verifier, exchange, inbox);
                for (Notification.Activity a : v.notification().activities()) {
                    System.out.println(a.types() + " " + a.object().id() + " (signed by " + v.keyId() + ")");
                }
                exchange.sendResponseHeaders(204, -1);
            } catch (SignatureVerificationException e) {
                System.err.println("Rejected delivery: " + e.getMessage());
                exchange.sendResponseHeaders(401, -1);
            } finally {
                exchange.close();
            }
        });
        server.start();

        Subscription sub = client.subscribe(storage, WebhookSubscriptionRequest.of(inbox, storage.storageRoot()));
        System.out.println("Subscribed: " + sub.subscription() + " — change something in " + storage.storageRoot());
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            client.unsubscribe(sub.subscription());
            server.stop(0);
        }));
    }
}
