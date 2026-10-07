// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver;

import static org.assertj.core.api.Assertions.assertThat;

import io.modelcontextprotocol.spec.McpSchema.Tool;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.JsonNode;

/** The driver over MCP, with the fake adapter: tools, clients, outcomes, failures and the inbox. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"lws.driver.operation-timeout=5s", "lws.driver.max-clients=3"})
class DriverMcpTest {

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        FakeLanguage.register(registry);
    }

    @LocalServerPort
    int port;

    McpTestClient mcp;

    @BeforeEach
    void connect() {
        mcp = new McpTestClient(port, null);
    }

    @AfterEach
    void disconnect() {
        for (JsonNode c : mcp.call("list_clients", Map.of()).get("clients")) {
            mcp.call("stop_client", Map.of("client", c.get("client").asString()));
        }
        mcp.close();
    }

    @Test
    @SuppressWarnings("unchecked")
    void theToolsAreTheDriversOwnAndOnePerOperation() {
        List<String> names = mcp.tools().stream().map(Tool::name).toList();
        assertThat(names).contains("list_languages", "start_client", "list_clients", "stop_client", "client_log",
                "open_inbox", "inbox_deliveries");
        assertThat(names).containsAll(OperationCatalogTest.PROTOCOL_OPERATIONS);
        Tool read = mcp.tools().stream().filter(t -> t.name().equals("read")).findFirst().orElseThrow();
        assertThat((List<String>) read.inputSchema().get("required")).containsExactly("client", "url");
        assertThat((Map<String, Object>) read.inputSchema().get("properties")).containsKeys("client", "url", "ifNoneMatch", "rangeStart");
        assertThat(read.annotations().readOnlyHint()).isTrue();
        Tool delete = mcp.tools().stream().filter(t -> t.name().equals("delete")).findFirst().orElseThrow();
        assertThat(delete.annotations().destructiveHint()).isTrue();
    }

    @Test
    void aClientRunsOperationsAndReportsOutcomes() {
        JsonNode started = mcp.call("start_client", Map.of("language", "fake", "authType", "didKey", "label", "alice"));
        String client = started.get("client").asString();
        assertThat(client).startsWith("fake-");
        assertThat(started.get("library").asString()).isEqualTo("lws-client-fake/0.0.1");
        assertThat(started.get("agent").asString()).isEqualTo("did:key:zFake");
        assertThat(started.get("unsupported")).extracting(JsonNode::asString).contains("patch", "subscribe");

        JsonNode read = mcp.call("read", Map.of("client", client, "url", "https://storage.example/a.txt"));
        assertThat(read.get("ok").asBoolean()).isTrue();
        assertThat(read.at("/result/body/text").asString()).isEqualTo("hello https://storage.example/a.txt");

        JsonNode missing = mcp.call("read", Map.of("client", client, "url", "https://storage.example/missing"));
        assertThat(missing.get("ok").asBoolean()).isFalse();
        assertThat(missing.at("/error/kind").asString()).isEqualTo("NotFoundError");
        assertThat(missing.at("/error/status").asInt()).isEqualTo(404);

        JsonNode unsupported = mcp.call("patch", Map.of("client", client, "url", "https://storage.example/a.json",
                "patch", List.of(Map.of("op", "remove", "path", "/a"))));
        assertThat(unsupported.at("/error/kind").asString()).isEqualTo("Unsupported");

        JsonNode created = mcp.call("create", Map.of("client", client, "container", "https://storage.example/c/",
                "slug", "x.json", "body", Map.of("json", Map.of("n", 1)), "types", List.of("https://schema.org/Thing")));
        assertThat(created.at("/result/location").asString()).isEqualTo("https://storage.example/c/x.json");
        assertThat(created.at("/result/echo/body/json/n").asInt()).isEqualTo(1);
        assertThat(created.at("/result/echo/types/0").asString()).isEqualTo("https://schema.org/Thing");
        assertThat(created.at("/result/echo/client").isMissingNode()).isTrue();

        JsonNode clients = mcp.call("list_clients", Map.of()).get("clients");
        assertThat(clients).hasSize(1);
        assertThat(clients.get(0).get("label").asString()).isEqualTo("alice");
        assertThat(mcp.call("client_log", Map.of("client", client)).get("lines"))
                .extracting(JsonNode::asString).contains("fake adapter started");
    }

    @Test
    void driverFailuresAreToolErrors() {
        assertThat(mcp.failure("read", Map.of("client", "fake-nope", "url", "https://storage.example/"))).contains("no client fake-nope");
        assertThat(mcp.failure("start_client", Map.of("language", "cobol"))).contains("no language cobol");
        assertThat(mcp.failure("start_client", Map.of("language", "fake", "authType", "explode"))).contains("configure failed");
        assertThat(mcp.call("list_clients", Map.of()).get("clients")).isEmpty();
    }

    @Test
    void anAdapterThatDoesNotAnswerIsStopped() {
        String client = mcp.call("start_client", Map.of("language", "fake")).get("client").asString();
        assertThat(mcp.failure("delete", Map.of("client", client, "url", "https://storage.example/slow")))
                .contains("gave no answer to delete within 5 s");
        assertThat(mcp.failure("read", Map.of("client", client, "url", "https://storage.example/a")))
                .contains("not running");
    }

    @Test
    void theClientLimitHolds() {
        for (int i = 0; i < 3; i++) {
            mcp.call("start_client", Map.of("language", "fake"));
        }
        assertThat(mcp.failure("start_client", Map.of("language", "fake"))).contains("its limit");
    }

    @Test
    void theInboxVerifiesDeliveriesWithTheClientsLibrary() throws Exception {
        String client = mcp.call("start_client", Map.of("language", "fake")).get("client").asString();
        assertThat(mcp.failure("inbox_deliveries", Map.of("client", client))).contains("has no inbox");
        String inbox = mcp.call("open_inbox", Map.of("client", client)).get("inbox").asString();
        assertThat(inbox).startsWith("http://127.0.0.1:" + port + "/inbox/" + client + "/");
        assertThat(mcp.call("open_inbox", Map.of("client", client)).get("inbox").asString()).isEqualTo(inbox);

        HttpClient http = HttpClient.newHttpClient();
        assertThat(post(http, inbox, "{\"type\": \"Notification\"}").statusCode()).isEqualTo(202);
        assertThat(post(http, inbox, "{\"type\": \"Notification\", \"forged\": true}").statusCode()).isEqualTo(401);
        assertThat(post(http, inbox.substring(0, inbox.lastIndexOf('/') + 1) + "wrong-key", "{}").statusCode()).isEqualTo(404);

        JsonNode deliveries = mcp.call("inbox_deliveries", Map.of("client", client)).get("deliveries");
        assertThat(deliveries).hasSize(2);
        JsonNode first = deliveries.get(0);
        assertThat(first.get("verified").asBoolean()).isTrue();
        assertThat(first.get("answer").asInt()).isEqualTo(202);
        assertThat(first.at("/outcome/result/inboxUrl").asString()).isEqualTo(inbox);
        assertThat(first.at("/outcome/result/headers/x-test/0").asString()).isEqualTo("yes");
        assertThat(first.at("/headers/content-type/0").asString()).isEqualTo("application/lws+json");
        JsonNode second = deliveries.get(1);
        assertThat(second.get("verified").asBoolean()).isFalse();
        assertThat(second.at("/outcome/error/kind").asString()).isEqualTo("SignatureVerificationError");
        assertThat(mcp.call("inbox_deliveries", Map.of("client", client, "after", 1)).get("deliveries")).hasSize(1);
    }

    @Test
    void listLanguagesSaysWhichAdaptersAreReady() {
        JsonNode languages = mcp.call("list_languages", Map.of("probe", true)).get("languages");
        JsonNode fake = null;
        for (JsonNode l : languages) {
            if (l.get("language").asString().equals("fake")) {
                fake = l;
            }
        }
        assertThat(fake).isNotNull();
        assertThat(fake.get("available").asBoolean()).isTrue();
        assertThat(fake.get("library").asString()).isEqualTo("lws-client-fake/0.0.1");
        assertThat(fake.get("unsupported")).extracting(JsonNode::asString).contains("patch").doesNotContain("read");
        assertThat(languages).extracting(l -> l.get("language").asString()).contains("java", "js", "python", "go", "rust", "cpp", "csharp", "swift", "php", "kotlin", "wasm");
    }

    private static HttpResponse<String> post(HttpClient http, String url, String body) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/lws+json")
                .header("X-Test", "yes")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }
}
