// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.http.AuthChallenge;
import com.ebremer.lws.http.ProblemDetails;
import com.ebremer.lws.http.WwwAuthenticate;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.util.List;

/**
 * {@code 401 Unauthorized} remained after authentication handling (LWS <em>unknown requester</em>).
 * The parsed {@code WWW-Authenticate} challenges tell which authorization server to use.
 */
public class UnauthorizedException extends HttpStatusException {
    public UnauthorizedException(String method, URI uri, int status, HttpHeaders headers, ProblemDetails problem, String body) {
        super(method, uri, status, headers, problem, body);
    }

    /** The challenges from the {@code WWW-Authenticate} response header. */
    public List<AuthChallenge> challenges() {
        return WwwAuthenticate.parse(headers().allValues("www-authenticate"));
    }
}
