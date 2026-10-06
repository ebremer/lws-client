// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

/**
 * Pluggable request authentication for {@link com.ebremer.lws.LwsClient}.
 *
 * <p>The client calls {@link #authorize} before sending every request attempt. When a request is
 * answered with {@code 401 Unauthorized} it calls {@link #handleChallenge}; returning {@code true}
 * makes the client re-send the request once (calling {@code authorize} again first).
 *
 * <p>Provided implementations: {@link TokenExchangeAuthenticator} (the LWS OAuth 2.0 token exchange flow)
 * and {@link BearerTokenAuthenticator} (a known access token). Implementations must be thread-safe.
 */
public interface Authenticator {
    /** Adds credentials (typically an {@code Authorization} header) to an outgoing request. */
    void authorize(AuthRequest request);

    /**
     * Reacts to a {@code 401} response, e.g. by obtaining a token.
     *
     * @return whether the request should be retried
     */
    boolean handleChallenge(AuthRequest request, AuthResponse response);
}
