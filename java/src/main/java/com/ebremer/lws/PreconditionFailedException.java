// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.http.ProblemDetails;
import java.net.URI;
import java.net.http.HttpHeaders;

/** {@code 412 Precondition Failed}: an {@code If-Match}/{@code If-None-Match} condition did not hold. */
public class PreconditionFailedException extends HttpStatusException {
    public PreconditionFailedException(String method, URI uri, int status, HttpHeaders headers, ProblemDetails problem, String body) {
        super(method, uri, status, headers, problem, body);
    }
}
