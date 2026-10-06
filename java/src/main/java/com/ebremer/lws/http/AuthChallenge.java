// SPDX-License-Identifier: MIT
package com.ebremer.lws.http;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * One challenge from a {@code WWW-Authenticate} header (RFC 9110 section 11.6.1).
 *
 * @param scheme the authentication scheme as sent (compare case-insensitively)
 * @param params auth-params with lower-case names and unquoted values
 * @param token68 the token68 credential form, or null
 */
public record AuthChallenge(String scheme, Map<String, String> params, String token68) {
    public AuthChallenge {
        params = params == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(params));
    }

    /** Whether the scheme equals {@code s}, ignoring case. */
    public boolean isScheme(String s) {
        return scheme.equalsIgnoreCase(s);
    }

    /** A parameter by (case-insensitive) name. */
    public Optional<String> param(String name) {
        return Optional.ofNullable(params.get(name.toLowerCase(Locale.ROOT)));
    }

    /** The token68 value, if this challenge uses that form. */
    public Optional<String> token68Value() {
        return Optional.ofNullable(token68);
    }

    /** LWS: the authorization server issuer ({@code as_uri}). */
    public Optional<URI> asUri() {
        return param("as_uri").flatMap(AuthChallenge::uri);
    }

    /** LWS: the protection scope ({@code realm}). */
    public Optional<URI> realm() {
        return param("realm").flatMap(AuthChallenge::uri);
    }

    /** The {@code error} parameter (e.g. {@code invalid_token}). */
    public Optional<String> error() {
        return param("error");
    }

    /** The {@code error_description} parameter. */
    public Optional<String> errorDescription() {
        return param("error_description");
    }

    private static Optional<URI> uri(String s) {
        try {
            return Optional.of(new URI(s));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
