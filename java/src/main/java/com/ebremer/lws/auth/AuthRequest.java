// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import java.net.URI;
import java.util.Optional;

/** A request attempt as seen by an {@link Authenticator}: target, method and mutable headers. */
public interface AuthRequest {
    /** The request method. */
    String method();

    /** The request URI. */
    URI uri();

    /** The current value of a header (case-insensitive name). */
    Optional<String> header(String name);

    /** Sets (replaces) a header. */
    void setHeader(String name, String value);

    /** Removes a header. */
    void removeHeader(String name);
}
