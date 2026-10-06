// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import java.net.URI;
import java.util.List;
import java.util.Optional;

/**
 * A retrieved linkset resource: its URL, entity tag and content, plus what the server allows.
 *
 * @param url the linkset resource URL — pass it to {@code updateLinkset} / {@code patchLinkset}
 * @param linkset the parsed linkset
 * @param metadata the response metadata
 */
public record LinksetDocument(URI url, Linkset linkset, ResourceMetadata metadata) {
    /** The entity tag — use it as {@code ifMatch} for conditional updates. */
    public Optional<String> etag() {
        return metadata.etag();
    }

    /** Methods allowed on the linkset resource. */
    public List<String> allow() {
        return metadata.allow();
    }

    /** Patch formats accepted by the linkset resource. */
    public List<String> acceptPatch() {
        return metadata.acceptPatch();
    }

    /** Whether the server advertises {@code PUT} for full replacement. */
    public boolean supportsPut() {
        return allow().stream().anyMatch(m -> m.equalsIgnoreCase("PUT"));
    }
}
