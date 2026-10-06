// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import com.ebremer.lws.Lws;
import com.ebremer.lws.LwsProtocolException;
import com.ebremer.lws.internal.Json;
import com.ebremer.lws.internal.Uris;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.util.List;
import java.util.Optional;

/**
 * Authorization server metadata (RFC 8414) served at {@code /.well-known/lws-configuration}.
 *
 * @param issuer the issuer identifier
 * @param tokenEndpoint the token endpoint
 * @param jwksUri the JWK set URI, if any
 * @param grantTypesSupported supported grant types
 * @param subjectTokenTypesSupported supported {@code subject_token_type} values (empty if not advertised)
 * @param subjectIdentifierTypesSupported supported subject identifier types (defaults to {@code ["https"]})
 * @param raw the JSON document
 */
public record AuthorizationServerMetadata(String issuer, URI tokenEndpoint, Optional<URI> jwksUri,
                                          List<String> grantTypesSupported, List<String> subjectTokenTypesSupported,
                                          List<String> subjectIdentifierTypesSupported, ObjectNode raw) {
    public AuthorizationServerMetadata {
        grantTypesSupported = List.copyOf(grantTypesSupported);
        subjectTokenTypesSupported = List.copyOf(subjectTokenTypesSupported);
        subjectIdentifierTypesSupported = List.copyOf(subjectIdentifierTypesSupported);
    }

    /** Parses a metadata document retrieved from {@code base}. */
    public static AuthorizationServerMetadata parse(JsonNode json, URI base) {
        ObjectNode o = Json.requireObject(json, "Authorization server metadata");
        String issuer = Json.text(o, "issuer");
        if (issuer == null) throw new LwsProtocolException("Authorization server metadata has no issuer");
        URI token = Json.uri(o, "token_endpoint", base);
        if (token == null) throw new LwsProtocolException("Authorization server metadata has no token_endpoint");
        List<String> idTypes = Json.stringOrArray(o.get("subject_identifier_types_supported"));
        return new AuthorizationServerMetadata(issuer, token, Optional.ofNullable(Json.uri(o, "jwks_uri", base)),
                Json.stringOrArray(o.get("grant_types_supported")),
                Json.stringOrArray(o.get("subject_token_types_supported")),
                idTypes.isEmpty() ? List.of("https") : idTypes, o);
    }

    /**
     * The metadata URL for an issuer (RFC 8414 section 3.1): {@code https://as.example} →
     * {@code https://as.example/.well-known/lws-configuration}; {@code https://as.example/t1} →
     * {@code https://as.example/.well-known/lws-configuration/t1}.
     */
    public static URI metadataUrl(URI issuer) {
        String path = issuer.getRawPath() == null ? "" : issuer.getRawPath();
        if (path.endsWith("/")) path = path.substring(0, path.length() - 1);
        StringBuilder sb = new StringBuilder();
        sb.append(issuer.getScheme()).append("://").append(issuer.getRawAuthority())
                .append(Lws.WELL_KNOWN_LWS_CONFIGURATION).append(path);
        return Uris.parse(sb.toString());
    }

    /** Whether the server advertises support for {@code tokenType} (true when it advertises nothing). */
    public boolean supportsSubjectTokenType(String tokenType) {
        return subjectTokenTypesSupported.isEmpty() || subjectTokenTypesSupported.contains(tokenType);
    }
}
