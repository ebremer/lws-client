// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import com.ebremer.lws.AuthenticationException;
import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * An access token issued by an authorization server.
 *
 * @param value the token
 * @param tokenType the token type (always {@code Bearer} for LWS)
 * @param expiresAt when the token expires
 * @param scope the granted scope, if any
 */
public record AccessToken(String value, String tokenType, Instant expiresAt, Optional<String> scope) {
    /** Default lifetime when neither {@code expires_in} nor a JWT {@code exp} is available. */
    public static final Duration DEFAULT_LIFETIME = Duration.ofSeconds(300);

    /**
     * Parses a token endpoint success response (RFC 6749 section 5.1). The expiry is taken from
     * {@code expires_in}, else from the JWT {@code exp} claim of the token, else {@link #DEFAULT_LIFETIME}.
     */
    public static AccessToken fromTokenResponse(JsonNode json, Instant now) {
        String token = Json.text(json, "access_token");
        if (token == null || token.isEmpty()) throw new AuthenticationException("Token response has no access_token");
        String type = Json.text(json, "token_type");
        if (type == null || !type.equalsIgnoreCase("Bearer")) {
            throw new AuthenticationException("Unsupported token_type: " + type);
        }
        Instant expires;
        JsonNode ei = json.get("expires_in");
        if (ei != null && ei.isNumber()) {
            expires = now.plusSeconds(ei.asLong());
        } else {
            expires = Jwt.expiration(token).orElse(now.plus(DEFAULT_LIFETIME));
        }
        return new AccessToken(token, "Bearer", expires, Optional.ofNullable(Json.text(json, "scope")));
    }

    /** Whether the token is still usable at {@code now}, keeping {@code skew} in reserve. */
    public boolean isValid(Instant now, Duration skew) {
        return now.plus(skew).isBefore(expiresAt);
    }

    @Override
    public String toString() {
        return "AccessToken[" + tokenType + ", expiresAt=" + expiresAt + "]";
    }
}
