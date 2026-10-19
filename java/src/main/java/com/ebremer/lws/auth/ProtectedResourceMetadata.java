// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import com.ebremer.lws.LwsProtocolException;
import com.ebremer.lws.internal.Json;
import com.ebremer.lws.internal.Uris;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

/**
 * OAuth 2.0 protected resource metadata (RFC 9728), named by the {@code resource_metadata} parameter of a
 * {@code 401}'s challenge: the resource it describes and the authorization servers that issue tokens for it.
 *
 * @param resource the resource identifier, as sent (the requested URL, not the storage)
 * @param authorizationServers the issuer identifiers of {@code authorization_servers}, in order (never empty)
 * @param raw the JSON document
 */
public record ProtectedResourceMetadata(String resource, List<String> authorizationServers, ObjectNode raw) {
    public ProtectedResourceMetadata {
        authorizationServers = List.copyOf(authorizationServers);
    }

    /**
     * Parses a metadata document. {@code resource} must be a string (RFC 9728) and
     * {@code authorization_servers} a non-empty array of strings (lws10-core makes it REQUIRED).
     *
     * @throws LwsProtocolException if the document is not valid protected resource metadata
     */
    public static ProtectedResourceMetadata parse(JsonNode json) {
        ObjectNode o = Json.requireObject(json, "Protected resource metadata");
        JsonNode resource = o.get("resource");
        if (resource == null || !resource.isTextual()) {
            throw new LwsProtocolException("Protected resource metadata has no resource string");
        }
        JsonNode servers = o.get("authorization_servers");
        if (servers == null || !servers.isArray() || servers.isEmpty()) {
            throw new LwsProtocolException("Protected resource metadata has no authorization_servers");
        }
        List<String> issuers = new ArrayList<>();
        for (JsonNode s : servers) {
            if (!s.isTextual()) throw new LwsProtocolException("Protected resource metadata authorization_servers holds a non-string");
            issuers.add(s.textValue());
        }
        return new ProtectedResourceMetadata(resource.textValue(), issuers, o);
    }

    /**
     * Whether {@link #resource()} is identical to {@code requested} (RFC 9728 section 3.3): scheme and host
     * compared case-insensitively and a default port dropped on both, and nothing else.
     */
    public boolean describes(URI requested) {
        try {
            return Uris.sameResource(new URI(resource), requested);
        } catch (URISyntaxException e) {
            return false;
        }
    }
}
