// SPDX-License-Identifier: MIT
package com.ebremer.lws.examples;

import com.ebremer.lws.LwsClient;
import com.ebremer.lws.auth.ControlledIdentifiers;
import com.ebremer.lws.auth.DidKey;
import com.ebremer.lws.auth.Jwk;
import com.ebremer.lws.auth.KeyPairs;
import com.ebremer.lws.auth.SelfSignedCredentials;
import com.ebremer.lws.auth.TokenExchangeAuthenticator;
import java.net.URI;
import java.security.KeyPair;

/**
 * Self-signed identities for bots and server-side agents ({@code lws10-authn-ssi-cid}).
 *
 * <ul>
 *   <li>{@code did:key}: the identifier is derived from the public key — nothing to publish.</li>
 *   <li>HTTPS agent: publish the printed controlled identifier document at the agent URL.</li>
 * </ul>
 */
public final class SelfSignedAuth {
    public static void main(String[] args) {
        // 1. did:key — persist the private JWK to keep the same identity across runs.
        KeyPair keys = KeyPairs.generateP256();
        System.out.println("did:key agent : " + DidKey.fromPublicKey(keys.getPublic()));
        System.out.println("private JWK   : " + Jwk.fromKeyPair(keys) + "   (keep secret)");
        SelfSignedCredentials didKey = SelfSignedCredentials.didKey(keys);

        // Reload later with: SelfSignedCredentials.didKey(Jwk.toKeyPair(savedPrivateJwk))

        // 2. An HTTPS agent identifier with an Ed25519 key.
        URI agent = URI.create("https://bot.example/id");
        KeyPair edKeys = KeyPairs.generateEd25519();
        SelfSignedCredentials https = SelfSignedCredentials.forAgent(agent, edKeys.getPrivate(), "key-1");
        System.out.println("Publish at " + agent + ":\n" + ControlledIdentifiers.document(agent, edKeys.getPublic(), "key-1").toPrettyString());

        // Either credential plugs into the LWS token exchange flow.
        LwsClient client = LwsClient.builder()
                .authenticator(TokenExchangeAuthenticator.builder(didKey)
                        // Optional: only send credentials to authorization servers you trust.
                        .authorizationServerFilter((as, realm) -> true)
                        .build())
                .build();
        System.out.println("Client ready: " + client.authenticator().isPresent() + ", https agent alg " + https.algorithm());
    }
}
