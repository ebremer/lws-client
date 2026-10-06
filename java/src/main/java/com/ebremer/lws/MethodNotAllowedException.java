// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.http.ProblemDetails;
import com.ebremer.lws.internal.HeaderLists;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.util.List;

/** {@code 405 Method Not Allowed}; {@link #allow()} lists the methods the resource supports. */
public class MethodNotAllowedException extends HttpStatusException {
    public MethodNotAllowedException(String method, URI uri, int status, HttpHeaders headers, ProblemDetails problem, String body) {
        super(method, uri, status, headers, problem, body);
    }

    /** The methods from the {@code Allow} header. */
    public List<String> allow() {
        return HeaderLists.tokens(headers().allValues("allow"));
    }
}
