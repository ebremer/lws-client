// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.http.Link;
import com.ebremer.lws.internal.Json;
import com.ebremer.lws.internal.Uris;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

/**
 * One page of a container listing (or of a type search result, whose {@code type} is
 * {@code ContainerPage}). {@code id}, {@code types} and {@code totalItems} describe the whole listing;
 * {@code items} only the current page. Follow {@link #next()} for more.
 *
 * @param id the absolute container URI (empty for synthetic search results)
 * @param types the raw {@code type} values of the listing
 * @param totalItems the (possibly approximate) number of members across all pages
 * @param items the members on this page
 * @param first the first page
 * @param next the next page
 * @param prev the previous page
 * @param last the last page
 * @param metadata the response metadata (ETag, links, …)
 * @param raw the JSON document
 */
public record ContainerPage(Optional<URI> id, List<String> types, OptionalLong totalItems, List<ContainedResource> items,
                            Optional<URI> first, Optional<URI> next, Optional<URI> prev, Optional<URI> last,
                            ResourceMetadata metadata, ObjectNode raw) {
    public ContainerPage {
        types = List.copyOf(types);
        items = List.copyOf(items);
    }

    /** Parses a container representation from a response body and its metadata. */
    public static ContainerPage parse(ObjectNode body, ResourceMetadata metadata) {
        URI base = metadata.url();
        String idText = Json.text(body, "id");
        // The page's own URL when the body names no id, as for a page of search results.
        Optional<URI> id = Optional.ofNullable(idText == null ? base : Uris.resolveOrNull(base, idText));
        JsonNode itemsNode = body.get("items");
        List<ContainedResource> items = new ArrayList<>();
        if (itemsNode != null && itemsNode.isArray()) {
            for (JsonNode n : itemsNode) items.add(ContainedResource.parse(n, base));
        } else if (itemsNode != null && !itemsNode.isNull()) {
            throw new LwsProtocolException("Container 'items' is not an array");
        }
        return new ContainerPage(id, Json.stringOrArray(body.get("type")), Json.optLong(body, "totalItems"), items,
                metadata.link(Lws.Rel.FIRST).map(Link::href), metadata.link(Lws.Rel.NEXT).map(Link::href),
                metadata.link(Lws.Rel.PREV).map(Link::href), metadata.link(Lws.Rel.LAST).map(Link::href),
                metadata, body);
    }

    /** Whether there is a next page. */
    public boolean hasNext() {
        return next.isPresent();
    }

    /** Whether the listing declares {@code type}. */
    public boolean hasType(String type) {
        return Lws.hasType(types, type);
    }

    /** Whether the listing is a container (from the body {@code type} or the {@code rel="type"} links). */
    public boolean isContainer() {
        return hasType(Lws.Type.CONTAINER) || metadata.isContainer();
    }

    /** The entity tag of this page. */
    public Optional<String> etag() {
        return metadata.etag();
    }
}
