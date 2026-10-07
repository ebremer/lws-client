// SPDX-License-Identifier: MIT
// A webhook inbox on the JDK's built-in HTTP server: subscribes to a container, then verifies every delivery
// (RFC 9421 signature and Content-Digest, keys from the storage description) before trusting it.
//
//   ./gradlew -q webhookReceiver --args="http://localhost:8787/root/ 8790"
package com.ebremer.lws.kotlin.examples

import com.ebremer.lws.kotlin.LwsClient
import com.ebremer.lws.kotlin.SignatureVerificationException
import com.ebremer.lws.kotlin.auth.SelfSignedCredentials
import com.ebremer.lws.kotlin.auth.SigningKey
import com.ebremer.lws.kotlin.auth.TokenExchangeAuthenticator
import com.ebremer.lws.kotlin.notify.WebhookSubscriptionRequest
import com.ebremer.lws.kotlin.notify.WebhookVerifier
import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.runBlocking
import java.net.InetSocketAddress
import java.net.URI

fun main(args: Array<String>) = runBlocking {
    val start = URI(args.getOrNull(0) ?: "http://localhost:8787/root/")
    val port = args.getOrNull(1)?.toInt() ?: 8790
    val client = LwsClient(authenticator = TokenExchangeAuthenticator(SelfSignedCredentials.didKey(SigningKey.generateP256())))
    val storage = client.discoverStorage(start)
    // The inbox URL exactly as registered: the signature covers it, so it is what deliveries are verified against.
    val inbox = URI("http://127.0.0.1:$port/inbox")
    val verifier = WebhookVerifier(client, trustedStorages = listOf(storage.id))

    val server = HttpServer.create(InetSocketAddress("127.0.0.1", port), 0)
    server.createContext("/inbox") { exchange ->
        val status = runBlocking {
            try {
                val verified = verifier.verifyExchange(exchange, inbox)
                for (a in verified.notification.activities) println("${a.types.joinToString()} ${a.`object`.id} (from ${verified.storage})")
                204
            } catch (e: SignatureVerificationException) {
                System.err.println("Rejected a delivery: ${e.message}")
                401
            }
        }
        exchange.sendResponseHeaders(status, -1)
        exchange.close()
    }
    server.start()

    val service = storage.notificationService() ?: error("The storage has no notification service")
    val subscription = client.subscribe(service, WebhookSubscriptionRequest(listOf(storage.storageRoot()), inbox))
    println("Subscribed ${subscription.url}; waiting for deliveries on $inbox (Ctrl-C to stop)")
    Runtime.getRuntime().addShutdownHook(Thread { runBlocking { client.unsubscribe(subscription.url) } })
}
