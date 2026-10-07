// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.adapter;

import com.ebremer.lws.Body;
import com.ebremer.lws.index.TypeQuery;
import com.ebremer.lws.patch.JsonPatch;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Reads and validates request arguments (an absent member is missing or {@code null}), and rebuilds the
 * structured ones with the library's own types: bodies, JSON Patches and type queries.
 */
final class Args {
    /** The default {@code limit} of the lazy sequences. */
    static final long DEFAULT_LIMIT = 1000;

    private Args() {}

    /** A request body with the content type it implies. */
    record BodyArg(Body body, String contentType) {}

    static boolean absent(JsonNode value) {
        return value == null || value.isNull();
    }

    static String requiredString(JsonNode args, String name) {
        String value = optionalString(args, name);
        if (value == null) throw missing(name);
        return value;
    }

    static String optionalString(JsonNode args, String name) {
        JsonNode value = args.get(name);
        if (absent(value)) return null;
        if (!value.isTextual()) throw mustBe(name, "a string");
        return value.textValue();
    }

    static URI requiredUri(JsonNode args, String name) {
        return uri(requiredString(args, name), name);
    }

    static URI uri(String value, String name) {
        try {
            return new URI(value);
        } catch (URISyntaxException e) {
            throw AdapterException.invalid("argument '" + name + "' is not a URI: " + e.getMessage());
        }
    }

    static Boolean optionalBoolean(JsonNode args, String name) {
        JsonNode value = args.get(name);
        if (absent(value)) return null;
        if (!value.isBoolean()) throw mustBe(name, "a boolean");
        return value.booleanValue();
    }

    static Double optionalNumber(JsonNode args, String name) {
        JsonNode value = args.get(name);
        if (absent(value)) return null;
        if (!value.isNumber()) throw mustBe(name, "a number");
        return value.doubleValue();
    }

    static Long optionalInteger(JsonNode args, String name) {
        JsonNode value = args.get(name);
        if (absent(value)) return null;
        if (!isInteger(value)) throw mustBe(name, "an integer");
        return value.longValue();
    }

    static ObjectNode requiredObject(JsonNode args, String name) {
        ObjectNode value = optionalObject(args, name);
        if (value == null) throw missing(name);
        return value;
    }

    static ObjectNode optionalObject(JsonNode args, String name) {
        JsonNode value = args.get(name);
        if (absent(value)) return null;
        if (!value.isObject()) throw mustBe(name, "an object");
        return (ObjectNode) value;
    }

    static ArrayNode requiredArray(JsonNode args, String name) {
        ArrayNode value = optionalArray(args, name);
        if (value == null) throw missing(name);
        return value;
    }

    static ArrayNode optionalArray(JsonNode args, String name) {
        JsonNode value = args.get(name);
        if (absent(value)) return null;
        if (!value.isArray()) throw mustBe(name, "an array");
        return (ArrayNode) value;
    }

    /** The strings of an array argument. */
    static List<String> strings(JsonNode array, String name) {
        List<String> out = new ArrayList<>();
        for (JsonNode v : array) {
            if (!v.isTextual()) throw AdapterException.invalid("argument '" + name + "' must be a list of strings");
            out.add(v.textValue());
        }
        return out;
    }

    /** The URIs of an array argument. */
    static List<URI> uris(JsonNode array, String name) {
        List<URI> out = new ArrayList<>();
        for (String s : strings(array, name)) out.add(uri(s, name));
        return out;
    }

    /** Standard, padded base64. */
    static byte[] base64(String value, String name) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw AdapterException.invalid("argument '" + name + "' is not base64: " + e.getMessage());
        }
    }

    /** An RFC 3339 date-time. */
    static Instant instant(String value, String name) {
        try {
            return OffsetDateTime.parse(value).toInstant();
        } catch (DateTimeParseException e) {
            throw AdapterException.invalid("argument '" + name + "' is not an RFC 3339 date-time: " + value);
        }
    }

    /** The optional {@code limit} of a lazy sequence. */
    static long limit(JsonNode args) {
        JsonNode value = args.get("limit");
        if (absent(value)) return DEFAULT_LIMIT;
        if (!isInteger(value) || value.longValue() < 0) throw mustBe("limit", "a non-negative integer");
        return value.longValue();
    }

    /** A {@code body} argument as a library {@link Body}, with the content type it implies. */
    static BodyArg body(JsonNode body, String contentType) {
        if (absent(body)) return new BodyArg(Body.empty(), orDefault(contentType, "application/octet-stream"));
        if (!body.isObject()) throw mustBe("body", "an object");
        JsonNode text = body.get("text");
        if (text != null && text.isTextual()) return new BodyArg(Body.of(text.textValue()), orDefault(contentType, "text/plain"));
        JsonNode b64 = body.get("base64");
        if (b64 != null && b64.isTextual()) {
            return new BodyArg(Body.of(base64(b64.textValue(), "body.base64")), orDefault(contentType, "application/octet-stream"));
        }
        if (body.has("json")) return new BodyArg(Body.ofJson(body.get("json")), orDefault(contentType, "application/json"));
        throw AdapterException.invalid("argument 'body' must have text, base64 or json");
    }

    /** An RFC 6902 operations array, rebuilt with the library's {@link JsonPatch} builder. */
    static JsonPatch patch(JsonNode operations) {
        if (absent(operations) || !operations.isArray()) {
            throw AdapterException.invalid("argument 'patch' must be an array of operations");
        }
        JsonPatch.Builder patch = JsonPatch.builder();
        for (JsonNode op : operations) {
            if (!op.isObject() || !op.path("op").isTextual()) {
                throw AdapterException.invalid("a patch operation must be an object with an op");
            }
            String name = op.get("op").textValue();
            switch (name) {
                case "add" -> patch.add(pointer(op, "path", name), value(op, name));
                case "remove" -> patch.remove(pointer(op, "path", name));
                case "replace" -> patch.replace(pointer(op, "path", name), value(op, name));
                case "move" -> patch.move(pointer(op, "from", name), pointer(op, "path", name));
                case "copy" -> patch.copy(pointer(op, "from", name), pointer(op, "path", name));
                case "test" -> patch.test(pointer(op, "path", name), value(op, name));
                default -> throw AdapterException.invalid("unknown patch operation '" + name + "'");
            }
        }
        return patch.build();
    }

    /**
     * An {@code application/lws-query+json} document, rebuilt with the library's {@link TypeQuery} builder:
     * a string group is {@code allOf(iri)} and an array group {@code anyOf(iris…)}, on the key's relation.
     */
    static TypeQuery query(JsonNode query) {
        if (absent(query) || !query.isObject()) throw mustBe("query", "an object");
        TypeQuery.Builder q = TypeQuery.builder();
        for (Map.Entry<String, JsonNode> member : query.properties()) {
            String key = member.getKey();
            if (!member.getValue().isArray()) {
                throw AdapterException.invalid("query member '" + key + "' must be a list of groups");
            }
            for (JsonNode group : member.getValue()) {
                if (group.isTextual()) {
                    q.relationAllOf(key, group.textValue());
                } else if (group.isArray()) {
                    q.relationAnyOf(key, strings(group, "query." + key).toArray(new String[0]));
                } else {
                    throw AdapterException.invalid("a group of query member '" + key + "' must be an IRI or a list of IRIs");
                }
            }
        }
        return q.build();
    }

    private static String pointer(JsonNode op, String member, String name) {
        JsonNode value = op.get(member);
        if (value == null || !value.isTextual()) {
            throw AdapterException.invalid("patch operation '" + name + "' needs a string '" + member + "'");
        }
        return value.textValue();
    }

    /** The {@code value} member; JSON {@code null} is a value here, only a missing member is not. */
    private static JsonNode value(JsonNode op, String name) {
        JsonNode value = op.get("value");
        if (value == null) throw AdapterException.invalid("patch operation '" + name + "' needs a 'value'");
        return value;
    }

    private static boolean isInteger(JsonNode value) {
        if (value.isIntegralNumber()) return value.canConvertToLong();
        if (!value.isNumber()) return false;
        double d = value.doubleValue();
        return d == Math.rint(d) && Math.abs(d) < 0x1p63;
    }

    private static String orDefault(String value, String fallback) {
        return value != null ? value : fallback;
    }

    private static AdapterException missing(String name) {
        return AdapterException.invalid("missing argument '" + name + "'");
    }

    private static AdapterException mustBe(String name, String what) {
        return AdapterException.invalid("argument '" + name + "' must be " + what);
    }
}
