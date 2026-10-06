// SPDX-License-Identifier: MIT
package com.ebremer.lws.internal;

import com.ebremer.lws.LwsProtocolException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

/** Shared Jackson configuration and JSON helpers (internal). */
public final class Json {
    private Json() {}

    /** The shared, thread-safe mapper. */
    public static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    public static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    public static ObjectNode object() {
        return MAPPER.createObjectNode();
    }

    public static ArrayNode array() {
        return MAPPER.createArrayNode();
    }

    public static JsonNode parse(byte[] bytes) {
        try {
            return MAPPER.readTree(bytes);
        } catch (IOException e) {
            throw new LwsProtocolException("Response is not valid JSON: " + e.getMessage(), e);
        }
    }

    public static JsonNode parse(String text) {
        try {
            return MAPPER.readTree(text);
        } catch (IOException e) {
            throw new LwsProtocolException("Document is not valid JSON: " + e.getMessage(), e);
        }
    }

    public static ObjectNode parseObject(byte[] bytes, String what) {
        JsonNode node = parse(bytes);
        if (node == null || !node.isObject()) {
            throw new LwsProtocolException(what + " is not a JSON object");
        }
        return (ObjectNode) node;
    }

    public static ObjectNode requireObject(JsonNode node, String what) {
        if (node == null || !node.isObject()) {
            throw new LwsProtocolException(what + " is not a JSON object");
        }
        return (ObjectNode) node;
    }

    public static byte[] toBytes(JsonNode node) {
        try {
            return MAPPER.writeValueAsBytes(node);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String toString(JsonNode node) {
        try {
            return MAPPER.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    public static JsonNode valueToTree(Object value) {
        if (value == null) return NODES.nullNode();
        if (value instanceof JsonNode node) return node;
        return MAPPER.valueToTree(value);
    }

    /** Text of a string member, or null. */
    public static String text(JsonNode node, String field) {
        if (node == null) return null;
        JsonNode v = node.get(field);
        return v != null && v.isTextual() ? v.textValue() : null;
    }

    /** A JSON string or array of strings as a list ({@code "a"} becomes {@code ["a"]}). */
    public static List<String> stringOrArray(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) return List.of();
        if (node.isTextual()) return List.of(node.textValue());
        if (node.isArray()) {
            List<String> out = new ArrayList<>(node.size());
            for (JsonNode n : node) {
                if (n.isTextual()) out.add(n.textValue());
            }
            return Collections.unmodifiableList(out);
        }
        return List.of();
    }

    public static OptionalLong optLong(JsonNode node, String field) {
        if (node == null) return OptionalLong.empty();
        JsonNode v = node.get(field);
        if (v != null && v.isIntegralNumber()) return OptionalLong.of(v.longValue());
        if (v != null && v.isNumber()) return OptionalLong.of((long) v.doubleValue());
        return OptionalLong.empty();
    }

    /** Resolves a string member against {@code base}, or null if absent/invalid. */
    public static URI uri(JsonNode node, String field, URI base) {
        String s = text(node, field);
        if (s == null) return null;
        return Uris.resolveOrNull(base, s);
    }

    /** Lenient RFC 3339 / ISO 8601 date-time parsing; empty when unparseable. */
    public static Optional<Instant> instant(String value) {
        if (value == null) return Optional.empty();
        try {
            return Optional.of(OffsetDateTime.parse(value).toInstant());
        } catch (DateTimeParseException e) {
            try {
                return Optional.of(Instant.parse(value));
            } catch (DateTimeParseException e2) {
                return Optional.empty();
            }
        }
    }

    public static ArrayNode stringArray(List<String> values) {
        ArrayNode a = array();
        for (String v : values) a.add(v);
        return a;
    }
}
