// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.http.ProblemDetails;
import java.net.URI;
import java.net.http.HttpHeaders;

/** {@code 403 Forbidden}: the requester is known but not permitted (LWS <em>not permitted</em>). */
public class ForbiddenException extends HttpStatusException {
    public ForbiddenException(String method, URI uri, int status, HttpHeaders headers, ProblemDetails problem, String body) {
        super(method, uri, status, headers, problem, body);
    }
}
