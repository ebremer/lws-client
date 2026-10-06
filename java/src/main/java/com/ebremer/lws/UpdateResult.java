// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import java.util.Optional;

/**
 * The outcome of an update (PUT) or patch (PATCH).
 *
 * @param status {@code 200} or {@code 204} (or another 2xx)
 * @param metadata the response metadata
 * @param body the response body, if the server returned a representation
 */
public record UpdateResult(int status, ResourceMetadata metadata, byte[] body) {
    public UpdateResult {
        body = body == null ? new byte[0] : body;
    }

    /** The new entity tag, when the server returned one. */
    public Optional<String> etag() {
        return metadata.etag();
    }

    @Override
    public String toString() {
        return "UpdateResult[" + metadata.url() + ", status=" + status + "]";
    }
}
