// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

/**
 * Pluggable request authentication for {@link com.ebremer.lws.LwsClient}.
 *
 * <p>The client calls {@link #authorize} before sending every request attempt. When a request is
 * answered with {@code 401 Unauthorized} it calls {@link #handleChallenge}; returning {@code true}
 * makes the client re-send the request once (calling {@code authorize} again first, then applying the
 * headers {@code handleChallenge} set on the request, to that retry only).
 *
 * <p>Provided implementations: {@link TokenExchangeAuthenticator} (the LWS OAuth 2.0 token exchange flow)
 * and {@link BearerTokenAuthenticator} (a known access token). Implementations must be thread-safe.
 */
public interface Authenticator {
    /** Adds credentials (typically an {@code Authorization} header) to an outgoing request. */
    void authorize(AuthRequest request);

    /**
     * Reacts to a {@code 401} response, e.g. by obtaining a token. Headers set on {@code request} here are
     * sent with the retry (and not with any redirect it leads to).
     *
     * @return whether the request should be retried
     */
    boolean handleChallenge(AuthRequest request, AuthResponse response);
}
