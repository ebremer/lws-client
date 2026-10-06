// SPDX-License-Identifier: MIT
package com.ebremer.lws.access;

import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.util.List;
import java.util.Objects;

/**
 * The resources an access policy applies to.
 *
 * @param type the target matcher ({@code StorageResource}, {@code Container}, {@code DataResource}, or an IRI)
 * @param values the target identifiers
 */
public record AccessTarget(String type, List<String> values) {
    public AccessTarget {
        Objects.requireNonNull(type, "type");
        values = List.copyOf(values);
        if (values.isEmpty()) throw new IllegalArgumentException("An access target needs at least one value");
    }

    /** Any Storage Resource among {@code resources}. */
    public static AccessTarget storageResources(URI... resources) {
        return new AccessTarget("StorageResource", List.of(resources).stream().map(URI::toString).toList());
    }

    /** Containers among {@code resources}. */
    public static AccessTarget containers(URI... resources) {
        return new AccessTarget("Container", List.of(resources).stream().map(URI::toString).toList());
    }

    /** Data resources among {@code resources}. */
    public static AccessTarget dataResources(URI... resources) {
        return new AccessTarget("DataResource", List.of(resources).stream().map(URI::toString).toList());
    }

    ObjectNode toJson() {
        ObjectNode o = Json.object();
        o.put("type", type);
        o.set("value", Json.stringArray(values));
        return o;
    }

    static AccessTarget parse(JsonNode n) {
        String type = Json.text(n, "type");
        return new AccessTarget(type == null ? "StorageResource" : type, Json.stringOrArray(n.get("value")));
    }
}
