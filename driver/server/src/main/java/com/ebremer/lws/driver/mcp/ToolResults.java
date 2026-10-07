// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.mcp;

import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import java.util.LinkedHashMap;
import java.util.Map;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Tool results: a JSON object as both text and structured content, or a driver failure. */
final class ToolResults {

    private ToolResults() {
    }

    /** A result: the object, as structured content and as its JSON text. */
    static CallToolResult of(JsonMapper json, JsonNode value) {
        @SuppressWarnings("unchecked")
        Map<String, Object> structured = json.convertValue(value, LinkedHashMap.class);
        return CallToolResult.builder()
                .addTextContent(json.writeValueAsString(value))
                .structuredContent(structured)
                .isError(false)
                .build();
    }

    /** A failure of the driver itself, which the caller sees as a tool error. */
    static CallToolResult failure(String message) {
        return CallToolResult.builder().addTextContent(message).isError(true).build();
    }
}
