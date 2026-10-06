// SPDX-License-Identifier: MIT
package com.ebremer.lws.http;

import com.ebremer.lws.internal.HeaderLists;
import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;

/**
 * RFC 9457 problem details attached to an error response.
 *
 * @param type the problem type URI reference
 * @param title short human-readable summary
 * @param status the HTTP status code in the document
 * @param detail human-readable explanation of this occurrence
 * @param instance URI reference identifying this occurrence
 * @param extensions all other members
 * @param raw the complete document
 */
public record ProblemDetails(Optional<String> type, Optional<String> title, OptionalInt status, Optional<String> detail,
                             Optional<String> instance, Map<String, JsonNode> extensions, ObjectNode raw) {

    private static final Set<String> STANDARD = Set.of("type", "title", "status", "detail", "instance");

    /**
     * Parses a problem document from an error response body. A body is accepted when the content type is
     * {@code application/problem+json}, or any JSON type whose object has a {@code type}, {@code title}
     * or {@code detail} member.
     */
    public static Optional<ProblemDetails> parse(String contentType, byte[] body) {
        if (body == null || body.length == 0 || !HeaderLists.isJson(contentType)) return Optional.empty();
        JsonNode node;
        try {
            node = Json.MAPPER.readTree(body);
        } catch (Exception e) {
            return Optional.empty();
        }
        if (node == null || !node.isObject()) return Optional.empty();
        boolean problemType = "application/problem+json".equals(HeaderLists.essence(contentType));
        if (!problemType && !(node.has("type") || node.has("title") || node.has("detail"))) return Optional.empty();
        return Optional.of(of((ObjectNode) node));
    }

    /** Builds problem details from a JSON object. */
    public static ProblemDetails of(ObjectNode node) {
        Map<String, JsonNode> ext = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> it = node.properties().iterator();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> e = it.next();
            if (!STANDARD.contains(e.getKey())) ext.put(e.getKey(), e.getValue());
        }
        JsonNode st = node.get("status");
        return new ProblemDetails(
                Optional.ofNullable(Json.text(node, "type")),
                Optional.ofNullable(Json.text(node, "title")),
                st != null && st.isIntegralNumber() ? OptionalInt.of(st.intValue()) : OptionalInt.empty(),
                Optional.ofNullable(Json.text(node, "detail")),
                Optional.ofNullable(Json.text(node, "instance")),
                Collections.unmodifiableMap(ext),
                node.deepCopy());
    }
}
