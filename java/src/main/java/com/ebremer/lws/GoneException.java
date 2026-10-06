// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.http.ProblemDetails;
import java.net.URI;
import java.net.http.HttpHeaders;

/** {@code 410 Gone}: the target was permanently removed, or a pagination link expired. */
public class GoneException extends HttpStatusException {
    public GoneException(String method, URI uri, int status, HttpHeaders headers, ProblemDetails problem, String body) {
        super(method, uri, status, headers, problem, body);
    }
}
