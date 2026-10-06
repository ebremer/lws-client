// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import java.net.URI;
import java.util.Optional;

/**
 * The outcome of a create operation.
 *
 * @param location the absolute URI of the new resource ({@code Location})
 * @param metadata the {@code 201} response metadata (links to linkset, parent and type)
 * @param body the response body, often empty
 */
public record CreateResult(URI location, ResourceMetadata metadata, byte[] body) {
    public CreateResult {
        body = body == null ? new byte[0] : body;
    }

    /** The linkset of the new resource, when announced. */
    public Optional<URI> linkset() {
        return metadata.linkset();
    }

    /** The entity tag of the new resource, when announced. */
    public Optional<String> etag() {
        return metadata.etag();
    }

    @Override
    public String toString() {
        return "CreateResult[" + location + "]";
    }
}
