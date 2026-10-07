// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** An MCP client of the driver, as Touchstone would be one: Streamable HTTP, optionally with a bearer token. */
final class McpTestClient implements AutoCloseable {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final McpSyncClient client;

    McpTestClient(int port, String token) {
        HttpRequest.Builder requests = HttpRequest.newBuilder();
        if (token != null) {
            requests.header("Authorization", "Bearer " + token);
        }
        HttpClientStreamableHttpTransport transport = HttpClientStreamableHttpTransport.builder("http://127.0.0.1:" + port)
                .endpoint("/mcp")
                .requestBuilder(requests)
                .build();
        client = McpClient.sync(transport).requestTimeout(Duration.ofSeconds(120)).build();
        client.initialize();
    }

    List<Tool> tools() {
        return client.listTools().tools();
    }

    CallToolResult raw(String tool, Map<String, Object> arguments) {
        return client.callTool(new CallToolRequest(tool, arguments));
    }

    /** Calls a tool that must succeed, and returns its result's JSON. */
    JsonNode call(String tool, Map<String, Object> arguments) {
        CallToolResult result = raw(tool, arguments);
        if (Boolean.TRUE.equals(result.isError())) {
            throw new AssertionError(tool + " failed: " + text(result));
        }
        return JSON.readTree(text(result));
    }

    /** Calls a tool that must fail as a tool error, and returns its message. */
    String failure(String tool, Map<String, Object> arguments) {
        CallToolResult result = raw(tool, arguments);
        if (!Boolean.TRUE.equals(result.isError())) {
            throw new AssertionError(tool + " should have failed, but returned " + text(result));
        }
        return text(result);
    }

    static String text(CallToolResult result) {
        return result.content().stream().filter(TextContent.class::isInstance).map(c -> ((TextContent) c).text())
                .findFirst().orElse("");
    }

    @Override
    public void close() {
        client.closeGracefully();
    }
}
