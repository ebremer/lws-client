// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.http.ProblemDetails;
import java.net.URI;
import java.net.http.HttpHeaders;

/** {@code 422 Unprocessable Content}: the request was understood but cannot be processed. */
public class UnprocessableContentException extends HttpStatusException {
    public UnprocessableContentException(String method, URI uri, int status, HttpHeaders headers, ProblemDetails problem, String body) {
        super(method, uri, status, headers, problem, body);
    }
}
