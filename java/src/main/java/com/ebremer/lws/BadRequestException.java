// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.http.ProblemDetails;
import java.net.URI;
import java.net.http.HttpHeaders;

/** {@code 400 Bad Request}: the request was invalid. */
public class BadRequestException extends HttpStatusException {
    public BadRequestException(String method, URI uri, int status, HttpHeaders headers, ProblemDetails problem, String body) {
        super(method, uri, status, headers, problem, body);
    }
}
