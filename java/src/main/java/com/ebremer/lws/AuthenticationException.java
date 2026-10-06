// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import java.util.Optional;

/**
 * Obtaining an access token failed: the challenge realm did not contain the request URI, the
 * authorization server was untrusted or insecure, its metadata was invalid, or the token exchange was
 * rejected (in which case {@link #error()} carries the OAuth {@code error} code).
 */
public class AuthenticationException extends LwsException {
    private final String error;
    private final String errorDescription;

    public AuthenticationException(String message) {
        this(message, null, null, null);
    }

    public AuthenticationException(String message, Throwable cause) {
        this(message, null, null, cause);
    }

    public AuthenticationException(String message, String error, String errorDescription, Throwable cause) {
        super(message, cause);
        this.error = error;
        this.errorDescription = errorDescription;
    }

    /** The OAuth 2.0 {@code error} code (RFC 6749 section 5.2), when the token endpoint returned one. */
    public Optional<String> error() {
        return Optional.ofNullable(error);
    }

    /** The OAuth 2.0 {@code error_description}, when present. */
    public Optional<String> errorDescription() {
        return Optional.ofNullable(errorDescription);
    }
}
