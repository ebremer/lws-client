// SPDX-License-Identifier: MIT
package com.ebremer.lws.patch;

import com.ebremer.lws.Lws;
import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * An immutable JSON Patch document (RFC 6902), the LWS baseline patch format
 * ({@code application/json-patch+json}).
 *
 * <pre>{@code
 * JsonPatch patch = JsonPatch.builder()
 *     .replace("/age", 31)
 *     .add("/city", "Boston")
 *     .build();
 * }</pre>
 */
public final class JsonPatch {
    /** The patch media type. */
    public static final String MEDIA_TYPE = Lws.MediaType.JSON_PATCH;

    /**
     * One patch operation.
     *
     * @param op the operation name ({@code add}, {@code remove}, {@code replace}, {@code move}, {@code copy}, {@code test})
     * @param path the target JSON Pointer
     * @param from the source pointer for {@code move}/{@code copy}, else null
     * @param value the value for {@code add}/{@code replace}/{@code test}, else null
     */
    public record Operation(String op, String path, String from, JsonNode value) {
        public Operation {
            Objects.requireNonNull(op, "op");
            Objects.requireNonNull(path, "path");
        }

        ObjectNode toJson() {
            ObjectNode o = Json.object();
            o.put("op", op);
            if (from != null) o.put("from", from);
            o.put("path", path);
            if (value != null) o.set("value", value);
            return o;
        }
    }

    private final List<Operation> operations;

    private JsonPatch(List<Operation> operations) {
        this.operations = List.copyOf(operations);
    }

    /** A new builder. */
    public static Builder builder() {
        return new Builder();
    }

    /** A patch from existing operations. */
    public static JsonPatch of(List<Operation> operations) {
        return new JsonPatch(operations);
    }

    /** The operations, in order. */
    public List<Operation> operations() {
        return operations;
    }

    /** The patch as a JSON array. */
    public ArrayNode toJson() {
        ArrayNode a = Json.array();
        for (Operation op : operations) a.add(op.toJson());
        return a;
    }

    /** The serialised patch document. */
    public byte[] toBytes() {
        return Json.toBytes(toJson());
    }

    @Override
    public String toString() {
        return Json.toString(toJson());
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof JsonPatch p && p.operations.equals(operations);
    }

    @Override
    public int hashCode() {
        return operations.hashCode();
    }

    /** Builder for {@link JsonPatch}. Values may be Jackson nodes or any Jackson-serialisable object. */
    public static final class Builder {
        private final List<Operation> ops = new ArrayList<>();

        private Builder() {}

        public Builder add(String path, Object value) {
            ops.add(new Operation("add", path, null, Json.valueToTree(value)));
            return this;
        }

        public Builder remove(String path) {
            ops.add(new Operation("remove", path, null, null));
            return this;
        }

        public Builder replace(String path, Object value) {
            ops.add(new Operation("replace", path, null, Json.valueToTree(value)));
            return this;
        }

        public Builder move(String from, String path) {
            ops.add(new Operation("move", path, from, null));
            return this;
        }

        public Builder copy(String from, String path) {
            ops.add(new Operation("copy", path, from, null));
            return this;
        }

        public Builder test(String path, Object value) {
            ops.add(new Operation("test", path, null, Json.valueToTree(value)));
            return this;
        }

        public JsonPatch build() {
            return new JsonPatch(ops);
        }
    }
}
