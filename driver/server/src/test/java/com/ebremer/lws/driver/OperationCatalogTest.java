// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver;

import static org.assertj.core.api.Assertions.assertThat;

import com.ebremer.lws.driver.mcp.OperationCatalog;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

/** The catalog covers PROTOCOL.md section 4, and each tool's schema is well formed. */
class OperationCatalogTest {

    /** The operations of PROTOCOL.md section 4 that are tools: all but configure and shutdown. */
    static final List<String> PROTOCOL_OPERATIONS = List.of("discover_storage", "get_storage_description", "head", "read",
            "read_container", "list_container", "create", "create_container", "update", "patch", "delete", "linkset_url",
            "read_linkset", "update_linkset", "patch_linkset", "subscribe", "list_subscriptions", "get_subscription",
            "unsubscribe", "verify_notification", "request_access", "get_access_request", "list_access_requests",
            "cancel_access_request", "grant_access", "get_access_grant", "list_access_grants", "revoke_access_grant",
            "read_type_index", "list_types", "search_types", "search_all", "accepted_query_formats");

    private final OperationCatalog catalog = new OperationCatalog(JsonMapper.builder().build());

    @Test
    void everyProtocolOperationIsATool() {
        assertThat(catalog.names()).containsExactlyElementsOf(PROTOCOL_OPERATIONS);
    }

    @Test
    void theProtocolDocumentListsTheSameOperations() throws Exception {
        String protocol = Files.readString(Path.of(System.getProperty("lws.driver.home", ".."), "PROTOCOL.md"));
        for (String op : PROTOCOL_OPERATIONS) {
            assertThat(protocol).contains("| `" + op + "` |");
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void eachSchemaTakesTheClientAndResolvesItsDefinitions() {
        for (OperationCatalog.Operation op : catalog.operations()) {
            Map<String, Object> schema = op.inputSchema();
            assertThat(schema.get("type")).isEqualTo("object");
            Map<String, Object> properties = (Map<String, Object>) schema.get("properties");
            assertThat(properties).containsKey("client");
            List<String> required = (List<String>) schema.get("required");
            assertThat(required.get(0)).isEqualTo("client");
            assertThat(properties.keySet()).containsAll(required);
            assertThat(schema.toString()).doesNotContain("$def");
            assertThat(op.description()).isNotBlank();
        }
    }
}
