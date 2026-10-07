// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ebremer.lws.driver.web.McpAccessFilter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** The MCP endpoint's guard: the bearer token, browser origins, and the refusal to listen openly without a token. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"lws.driver.token=s3cret-token", "lws.driver.allowed-origins=https://trusted.example",
            "lws.driver.allowed-targets=https://storage.example/"})
class McpAccessTest {

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        FakeLanguage.register(registry);
    }

    @LocalServerPort
    int port;

    @Test
    void theMcpEndpointNeedsTheToken() throws Exception {
        HttpClient http = HttpClient.newHttpClient();
        String initialize = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\","
                + "\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"}}}";
        HttpResponse<String> none = http.send(request(initialize).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(none.statusCode()).isEqualTo(401);
        assertThat(none.headers().firstValue("WWW-Authenticate")).hasValueSatisfying(v -> assertThat(v).startsWith("Bearer"));
        HttpResponse<String> wrong = http.send(request(initialize).header("Authorization", "Bearer s3cret-tokem").build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(wrong.statusCode()).isEqualTo(401);
        HttpResponse<String> browser = http.send(request(initialize).header("Authorization", "Bearer s3cret-token")
                .header("Origin", "https://evil.example").build(), HttpResponse.BodyHandlers.ofString());
        assertThat(browser.statusCode()).isEqualTo(403);

        try (McpTestClient mcp = new McpTestClient(port, "s3cret-token")) {
            assertThat(mcp.tools()).isNotEmpty();
            String client = mcp.call("start_client", Map.of("language", "fake")).get("client").asString();
            assertThat(mcp.call("read", Map.of("client", client, "url", "https://storage.example/a")).get("ok").asBoolean()).isTrue();
            assertThat(mcp.failure("read", Map.of("client", client, "url", "https://elsewhere.example/a")))
                    .contains("outside the targets");
            mcp.call("stop_client", Map.of("client", client));
        }
    }

    @Test
    void anOpenListenerNeedsAToken() {
        DriverProperties open = new DriverProperties(".", Map.of(), null, null, null, null,
                java.time.Duration.ofSeconds(1), java.time.Duration.ofSeconds(1), 1, java.time.Duration.ofSeconds(1));
        assertThatThrownBy(() -> new McpAccessFilter(open, "0.0.0.0")).hasMessageContaining("without lws.driver.token");
        assertThatThrownBy(() -> new McpAccessFilter(open, "")).hasMessageContaining("every interface");
        new McpAccessFilter(open, "127.0.0.1");
        new McpAccessFilter(open, "::1");
    }

    private HttpRequest.Builder request(String body) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/mcp"))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString(body));
    }
}
