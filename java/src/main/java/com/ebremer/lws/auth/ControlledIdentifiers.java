// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import com.ebremer.lws.Lws;
import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.security.PublicKey;

/**
 * Builds the W3C Controlled Identifier (CID) document an agent publishes at its identifier URL so that
 * authorization servers can validate its self-signed credentials ({@code lws10-authn-ssi-cid}).
 */
public final class ControlledIdentifiers {
    private ControlledIdentifiers() {}

    /**
     * A CID document with one {@code JsonWebKey} verification method in the {@code authentication}
     * relationship. The method id is {@code agent#kid} (or {@code kid} itself if it is already a URI).
     */
    public static ObjectNode document(URI agent, PublicKey key, String kid) {
        return document(agent, Jwk.fromPublicKey(key), kid);
    }

    /** Like {@link #document(URI, PublicKey, String)} for a public JWK. */
    public static ObjectNode document(URI agent, ObjectNode publicJwk, String kid) {
        ObjectNode jwk = publicJwk.deepCopy();
        jwk.remove("d");
        jwk.put("kid", kid);
        if (!jwk.has("alg")) {
            jwk.put("alg", switch (jwk.path("kty").asText()) {
                case "OKP" -> "EdDSA";
                case "EC" -> switch (jwk.path("crv").asText()) {
                    case "P-384" -> "ES384";
                    case "P-521" -> "ES512";
                    default -> "ES256";
                };
                default -> "RS256";
            });
        }
        String agentId = agent.toString();
        String methodId = kid.contains(":") ? kid : agentId + "#" + kid;
        ObjectNode doc = Json.object();
        doc.putArray("@context").add(Lws.CID_CONTEXT);
        doc.put("id", agentId);
        ArrayNode authn = doc.putArray("authentication");
        ObjectNode vm = authn.addObject();
        vm.put("id", methodId);
        vm.put("type", "JsonWebKey");
        vm.put("controller", agentId);
        vm.set("publicKeyJwk", jwk);
        return doc;
    }
}
