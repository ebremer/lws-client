// SPDX-License-Identifier: MIT
package com.ebremer.lws.index;

import com.ebremer.lws.Lws;
import com.ebremer.lws.LwsProtocolException;
import com.ebremer.lws.ResourceMetadata;
import com.ebremer.lws.http.Link;
import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

/**
 * One page of a Type Index: the distinct resource types visible to the client.
 *
 * @param totalItems the number of types across all pages
 * @param types the type IRIs on this page
 * @param first the first page
 * @param next the next page
 * @param prev the previous page
 * @param last the last page
 * @param metadata the response metadata
 * @param raw the JSON document
 */
public record TypeIndexPage(OptionalLong totalItems, List<String> types, Optional<URI> first, Optional<URI> next,
                            Optional<URI> prev, Optional<URI> last, ResourceMetadata metadata, ObjectNode raw) {
    public TypeIndexPage {
        types = List.copyOf(types);
    }

    /** Parses a type index page. */
    public static TypeIndexPage parse(ObjectNode body, ResourceMetadata metadata) {
        List<String> types = new ArrayList<>();
        JsonNode items = body.get("items");
        if (items != null && items.isArray()) {
            for (JsonNode n : items) {
                String id = n.isTextual() ? n.textValue() : Json.text(n, "id");
                if (id != null) types.add(id);
            }
        } else if (items != null) {
            throw new LwsProtocolException("Type index 'items' is not an array");
        }
        return new TypeIndexPage(Json.optLong(body, "totalItems"), types,
                metadata.link(Lws.Rel.FIRST).map(Link::href), metadata.link(Lws.Rel.NEXT).map(Link::href),
                metadata.link(Lws.Rel.PREV).map(Link::href), metadata.link(Lws.Rel.LAST).map(Link::href), metadata, body);
    }

    /** Whether there is a next page. */
    public boolean hasNext() {
        return next.isPresent();
    }
}
