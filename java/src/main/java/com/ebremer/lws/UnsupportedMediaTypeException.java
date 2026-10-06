// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.http.ProblemDetails;
import com.ebremer.lws.internal.HeaderLists;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.util.List;

/**
 * {@code 415 Unsupported Media Type}. For PATCH requests {@link #acceptPatch()} lists the supported patch
 * formats; for QUERY requests {@link #acceptQuery()} lists the supported query formats.
 */
public class UnsupportedMediaTypeException extends HttpStatusException {
    public UnsupportedMediaTypeException(String method, URI uri, int status, HttpHeaders headers, ProblemDetails problem, String body) {
        super(method, uri, status, headers, problem, body);
    }

    /** Media types from the {@code Accept-Patch} header. */
    public List<String> acceptPatch() {
        return HeaderLists.mediaTypes(headers().allValues("accept-patch"));
    }

    /** Media types from the {@code Accept-Query} header (RFC 10008). */
    public List<String> acceptQuery() {
        return HeaderLists.mediaTypes(headers().allValues("accept-query"));
    }
}
