// SPDX-License-Identifier: MIT
// Self-signed identities for bots and server-side agents (lws10-authn-ssi-cid):
//  * did:key: the identifier is derived from the public key, so there is nothing to publish;
//  * an HTTPS agent: publish the printed controlled identifier document at the agent URL.
//
//   ./gradlew -q selfSignedAuth
package com.ebremer.lws.kotlin.examples

import com.ebremer.lws.kotlin.LwsClient
import com.ebremer.lws.kotlin.auth.ControlledIdentifierDocument
import com.ebremer.lws.kotlin.auth.DidKey
import com.ebremer.lws.kotlin.auth.Jwt
import com.ebremer.lws.kotlin.auth.SelfSignedCredentials
import com.ebremer.lws.kotlin.auth.SigningKey
import com.ebremer.lws.kotlin.auth.TokenExchangeAuthenticator
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import java.net.URI

private val pretty = Json { prettyPrint = true }

fun main() {
    // 1. did:key. Persist the private JWK to keep the same identity across runs.
    val key = SigningKey.generateP256()
    println("did:key agent : ${DidKey.did(key.publicKey)}")
    println("private JWK   : ${key.jwk()}   (keep it secret)")
    val didKey = SelfSignedCredentials.didKey(key)
    // Reload it later with: SelfSignedCredentials.didKey(SigningKey.fromJwk(savedPrivateJwk))

    // 2. An HTTPS agent identifier with an Ed25519 key.
    val agent = "https://bot.example/id"
    val edKey = SigningKey.generateEd25519()
    val https = SelfSignedCredentials.forAgent(agent, edKey, "https://bot.example/id#key-1")
    println("Publish at $agent:")
    println(pretty.encodeToString(JsonElement.serializer(), ControlledIdentifierDocument.create(agent, edKey.publicKey, "key-1")))

    // Either credential plugs into the LWS token exchange flow.
    val authenticator = TokenExchangeAuthenticator(
        didKey,
        // Optional: only send credentials to authorization servers you trust.
        authorizationServerFilter = { server, _ -> server.startsWith("https://") || URI(server).host in setOf("localhost", "127.0.0.1") },
    )
    LwsClient(authenticator = authenticator)
    println("Client ready: the did:key agent signs with ${didKey.algorithm}, the HTTPS agent with ${https.algorithm}")

    // The credential is a short-lived JWT; this is what the authorization server receives.
    val jwt = didKey.createToken("https://as.example")
    println("Example credential claims: ${Jwt.decodeClaims(jwt)}")
}
