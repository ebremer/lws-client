// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.mcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The operations of driver/PROTOCOL.md section 4 that the driver offers as MCP tools, read from
 * {@code operations.json}: each one's name, description, hints and input schema.
 */
@Component
public class OperationCatalog {

    /** The argument every operation tool takes first: which client to use. */
    static final String CLIENT = "client";

    private final List<Operation> operations;

    public OperationCatalog(JsonMapper json) {
        try (InputStream in = new ClassPathResource("operations.json").getInputStream()) {
            this.operations = parse(json, json.readTree(in));
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read operations.json", e);
        }
    }

    public List<Operation> operations() {
        return operations;
    }

    /** The names of every operation, in the catalog's order. */
    public List<String> names() {
        return operations.stream().map(Operation::name).toList();
    }

    private static List<Operation> parse(JsonMapper json, JsonNode root) {
        JsonNode defs = root.required("defs");
        List<Operation> list = new ArrayList<>();
        for (JsonNode op : root.required("operations")) {
            ObjectNode schema = json.createObjectNode();
            schema.put("type", "object");
            ObjectNode properties = schema.putObject("properties");
            ObjectNode client = properties.putObject(CLIENT);
            client.put("type", "string");
            client.put("description", "The client to use: an id from start_client.");
            op.path("params").properties().forEach(e -> properties.set(e.getKey(), resolve(e.getValue(), defs)));
            ArrayNode required = schema.putArray("required");
            required.add(CLIENT);
            op.path("required").forEach(required::add);
            schema.put("additionalProperties", false);
            Map<String, Object> inputSchema = json.convertValue(schema, LinkedHashMap.class);
            list.add(new Operation(op.required("name").asString(), op.required("title").asString(),
                    op.required("description").asString(), op.path("readOnly").asBoolean(),
                    op.path("destructive").asBoolean(), op.path("idempotent").asBoolean() || op.path("readOnly").asBoolean(),
                    inputSchema));
        }
        return List.copyOf(list);
    }

    private static JsonNode resolve(JsonNode param, JsonNode defs) {
        JsonNode def = param.get("$def");
        if (def == null) {
            return param;
        }
        ObjectNode schema = ((ObjectNode) defs.required(def.asString())).deepCopy();
        if (param.has("description")) {
            schema.set("description", param.get("description"));
        }
        return schema;
    }

    /**
     * One operation.
     *
     * @param inputSchema the tool's JSON Schema: the client, then the operation's own arguments
     */
    public record Operation(String name, String title, String description, boolean readOnly, boolean destructive,
            boolean idempotent, Map<String, Object> inputSchema) {
    }
}
