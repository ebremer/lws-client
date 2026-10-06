// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.http.ProblemDetails;
import java.net.URI;
import java.net.http.HttpHeaders;

/** {@code 507 Insufficient Storage}: a storage quota was exceeded. */
public class InsufficientStorageException extends HttpStatusException {
    public InsufficientStorageException(String method, URI uri, int status, HttpHeaders headers, ProblemDetails problem, String body) {
        super(method, uri, status, headers, problem, body);
    }
}
