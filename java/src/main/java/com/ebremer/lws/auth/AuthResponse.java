// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import com.ebremer.lws.http.AuthChallenge;
import com.ebremer.lws.http.WwwAuthenticate;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.util.List;

/**
 * A {@code 401} response passed to {@link Authenticator#handleChallenge}.
 *
 * @param uri the request URI
 * @param status the status code
 * @param headers the response headers
 */
public record AuthResponse(URI uri, int status, HttpHeaders headers) {
    /** The parsed {@code WWW-Authenticate} challenges. */
    public List<AuthChallenge> challenges() {
        return WwwAuthenticate.parse(headers.allValues("www-authenticate"));
    }
}
