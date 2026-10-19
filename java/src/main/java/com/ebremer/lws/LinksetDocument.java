// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.internal.Uris;
import com.ebremer.lws.patch.JsonPatch;
import com.ebremer.lws.patch.JsonPointer;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A retrieved linkset resource: its URL, entity tag and content, plus what the server allows. A move
 * ({@code LwsClient#move}) patches it with {@link #movePatch}.
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

    /**
     * The JSON Patch that moves {@code resource} into the container {@code destination} (lws10-core "Moving
     * Resources"): {@code test} that the resource's {@code up} link still holds the value read, and
     * {@code replace} it with {@code destination}. The resource's link context is the first whose
     * {@code anchor} resolves against {@link #url()} to {@code resource}, or the only one when it has no
     * anchor; its {@code up} link is its first {@code up} target with a string {@code href}.
     *
     * @throws LwsProtocolException if the linkset shows no {@code up} link of {@code resource} to replace
     */
    public JsonPatch movePatch(URI resource, URI destination) {
        Objects.requireNonNull(resource, "resource");
        if (!destination.isAbsolute()) throw new IllegalArgumentException("Destination " + destination + " is not an absolute URL");
        JsonNode contexts = linkset.toJson().get("linkset");
        for (int i = 0; i < contexts.size(); i++) {
            JsonNode anchor = contexts.get(i).get("anchor");
            boolean described = anchor == null ? contexts.size() == 1
                    : anchor.isTextual() && sameResource(Uris.resolveOrNull(url, anchor.textValue()), resource);
            if (!described) continue;
            JsonNode up = contexts.get(i).path(Lws.Rel.UP);
            for (int j = 0; up.isArray() && j < up.size(); j++) {
                JsonNode href = up.get(j).get("href");
                if (href == null || !href.isTextual()) continue;
                String pointer = JsonPointer.of("linkset", Integer.toString(i), Lws.Rel.UP, Integer.toString(j), "href");
                return JsonPatch.builder().test(pointer, href.textValue()).replace(pointer, destination.toString()).build();
            }
            break;
        }
        throw new LwsProtocolException("Linkset " + url + " has no up link of " + resource + " to replace");
    }

    private static boolean sameResource(URI a, URI b) {
        return a != null && Uris.sameResource(a, b);
    }
}
