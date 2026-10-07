// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.mcp;

import com.ebremer.lws.driver.DriverException;
import com.ebremer.lws.driver.clients.ClientRegistry;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.spec.McpSchema.ToolAnnotations;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The operation tools: one per operation of the catalog. Each passes its arguments, all but {@code client},
 * to the client's adapter unchanged and returns the adapter's response.
 */
@Configuration
public class OperationTools {

    @Bean
    public List<SyncToolSpecification> lwsOperationTools(OperationCatalog catalog, ClientRegistry clients, JsonMapper json) {
        return catalog.operations().stream().map(op -> spec(op, clients, json)).toList();
    }

    private static SyncToolSpecification spec(OperationCatalog.Operation op, ClientRegistry clients, JsonMapper json) {
        Tool tool = Tool.builder()
                .name(op.name())
                .title(op.title())
                .description(op.description())
                .inputSchema(op.inputSchema())
                .annotations(new ToolAnnotations(op.title(), op.readOnly(), op.destructive(), op.idempotent(), true, null))
                .build();
        return SyncToolSpecification.builder()
                .tool(tool)
                .callHandler((exchange, request) -> call(op.name(), request, clients, json))
                .build();
    }

    private static CallToolResult call(String op, CallToolRequest request, ClientRegistry clients, JsonMapper json) {
        Map<String, Object> arguments = request.arguments() == null ? new HashMap<>() : new HashMap<>(request.arguments());
        Object client = arguments.remove(OperationCatalog.CLIENT);
        if (!(client instanceof String id)) {
            return ToolResults.failure("missing argument 'client': an id from start_client");
        }
        try {
            ObjectNode args = json.valueToTree(arguments);
            return ToolResults.of(json, clients.call(id, op, args));
        } catch (DriverException e) {
            return ToolResults.failure(e.getMessage());
        }
    }
}
