// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.internal.Json;
import com.ebremer.lws.internal.Uris;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

/**
 * One member of a container listing (or of a type search result).
 *
 * @param id the absolute URI of the member
 * @param types the raw type values
 * @param format the media type (required for data resources)
 * @param size the size in bytes
 * @param modified the last modification time, when parseable
 * @param modifiedRaw the {@code modified} value as sent
 * @param raw the JSON object
 */
public record ContainedResource(URI id, List<String> types, Optional<String> format, OptionalLong size,
                                Optional<Instant> modified, Optional<String> modifiedRaw, ObjectNode raw) {
    public ContainedResource {
        types = List.copyOf(types);
    }

    /** Parses a contained resource description, resolving its id against {@code base}. */
    public static ContainedResource parse(JsonNode node, URI base) {
        ObjectNode o = Json.requireObject(node, "Contained resource description");
        String idText = Json.text(o, "id");
        if (idText == null) throw new LwsProtocolException("Contained resource description without id");
        URI id = Uris.resolveOrNull(base, idText);
        if (id == null) throw new LwsProtocolException("Invalid contained resource id: " + idText);
        String modifiedRaw = Json.text(o, "modified");
        return new ContainedResource(id, Json.stringOrArray(o.get("type")),
                Optional.ofNullable(Json.text(o, "format")), Json.optLong(o, "size"),
                Json.instant(modifiedRaw), Optional.ofNullable(modifiedRaw), o);
    }

    /** Whether the member declares {@code type} (LWS short terms match their full IRIs). */
    public boolean hasType(String type) {
        return Lws.hasType(types, type);
    }

    /** Whether the member is a container. */
    public boolean isContainer() {
        return hasType(Lws.Type.CONTAINER);
    }

    /** Whether the member is a data resource. */
    public boolean isDataResource() {
        return hasType(Lws.Type.DATA_RESOURCE);
    }
}
