// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import com.ebremer.lws.internal.Uris;
import java.net.URI;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Sends a known access token as {@code Authorization: Bearer …}, optionally only to URLs inside a realm
 * (recommended, so the token never leaks to other servers).
 */
public final class BearerTokenAuthenticator implements Authenticator {
    private final Supplier<String> token;
    private final URI realm;

    private BearerTokenAuthenticator(Supplier<String> token, URI realm) {
        this.token = Objects.requireNonNull(token, "token");
        this.realm = realm;
    }

    /** Sends {@code token} to every URL inside {@code realm}. */
    public static BearerTokenAuthenticator of(String token, URI realm) {
        Objects.requireNonNull(token, "token");
        return new BearerTokenAuthenticator(() -> token, Objects.requireNonNull(realm, "realm"));
    }

    /** Sends a token from {@code supplier} (asked per request) to every URL inside {@code realm}. */
    public static BearerTokenAuthenticator of(Supplier<String> supplier, URI realm) {
        return new BearerTokenAuthenticator(supplier, Objects.requireNonNull(realm, "realm"));
    }

    /** Sends {@code token} to every URL. Only use with a client dedicated to one trusted server. */
    public static BearerTokenAuthenticator unrestricted(String token) {
        Objects.requireNonNull(token, "token");
        return new BearerTokenAuthenticator(() -> token, null);
    }

    @Override
    public void authorize(AuthRequest request) {
        if (realm == null || Uris.contains(realm, request.uri())) {
            String t = token.get();
            if (t != null) request.setHeader("Authorization", "Bearer " + t);
        }
    }

    @Override
    public boolean handleChallenge(AuthRequest request, AuthResponse response) {
        return false;
    }
}
