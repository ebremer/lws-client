// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.internal.HeaderLists;
import com.ebremer.lws.internal.Json;
import com.ebremer.lws.internal.Uris;
import java.net.URI;
import java.util.Optional;

/**
 * The outcome of a move (lws10-core "Moving Resources").
 *
 * @param status {@code 200} or {@code 204} (or another 2xx)
 * @param location the absolute URL of the resource after the move
 * @param linkset the absolute URL of its linkset after the move
 * @param identifierPreserved whether the resource kept its URL ({@code location} is the URL moved)
 * @param metadata the response metadata
 * @param document the linkset in a {@code 200}'s body, if the server returned one
 */
public record MoveResult(int status, URI location, URI linkset, boolean identifierPreserved, ResourceMetadata metadata,
                         Optional<Linkset> document) {
    /**
     * Reads the answer to the patch that moved {@code resource}, sent to the linkset at {@code metadata.url()}.
     * A storage that keeps identifiers answers {@code 204}, or {@code 200} with the linkset: {@code location} is
     * {@code resource}. One that does not answers {@code 200} with the updated linkset, whose {@code anchor} is
     * the new identifier, and {@code Content-Location}, the linkset's new URL: {@code location} is the anchor of
     * the body's first context with an {@code up} link, resolved against {@code Content-Location} (else the
     * linkset URL), and {@code linkset} is {@code Content-Location}.
     *
     * @throws LwsProtocolException if a JSON body is not a linkset
     */
    public static MoveResult of(URI resource, ResourceMetadata metadata, byte[] body) {
        URI linkset = metadata.header("content-location").map(v -> Uris.resolveOrNull(metadata.url(), v)).orElse(null);
        if (linkset == null) linkset = metadata.url();
        URI location = resource;
        Optional<Linkset> document = Optional.empty();
        String ct = metadata.contentType().orElse(null);
        if (body != null && body.length > 0 && (ct == null || HeaderLists.isJson(ct))) {
            Linkset ls = Linkset.parse(Json.parse(body));
            document = Optional.of(ls);
            for (Linkset.LinkContext c : ls.contexts()) {
                if (c.targets(Lws.Rel.UP).isEmpty()) continue;
                URI anchor = c.anchor() == null ? null : Uris.resolveOrNull(linkset, c.anchor());
                if (anchor != null) location = anchor;
                break;
            }
        }
        return new MoveResult(metadata.status(), location, linkset, Uris.sameResource(location, resource), metadata, document);
    }

    /** The linkset's new entity tag, when the server returned one. */
    public Optional<String> etag() {
        return metadata.etag();
    }

    @Override
    public String toString() {
        return "MoveResult[" + location + ", status=" + status + "]";
    }
}
