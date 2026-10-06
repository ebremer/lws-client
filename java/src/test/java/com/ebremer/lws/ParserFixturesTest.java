// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import com.ebremer.lws.http.AuthChallenge;
import com.ebremer.lws.http.Link;
import com.ebremer.lws.http.LinkHeader;
import com.ebremer.lws.http.StructuredFields;
import com.ebremer.lws.http.StructuredFields.Bytes;
import com.ebremer.lws.http.StructuredFields.InnerList;
import com.ebremer.lws.http.StructuredFields.Item;
import com.ebremer.lws.http.StructuredFields.Member;
import com.ebremer.lws.http.StructuredFields.Token;
import com.ebremer.lws.http.WwwAuthenticate;
import com.ebremer.lws.index.TypeQuery;
import com.ebremer.lws.internal.Json;
import com.ebremer.lws.patch.JsonPatch;
import com.ebremer.lws.patch.JsonPointer;
import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigDecimal;
import java.net.URI;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/** Parser and builder tests driven by the shared conformance fixtures. */
class ParserFixturesTest {

    private static List<String> strings(JsonNode n) {
        List<String> out = new ArrayList<>();
        n.forEach(x -> out.add(x.textValue()));
        return out;
    }

    private static Map<String, String> stringMap(JsonNode n) {
        Map<String, String> out = new HashMap<>();
        Iterator<Map.Entry<String, JsonNode>> it = n.properties().iterator();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> e = it.next();
            out.put(e.getKey(), e.getValue().textValue());
        }
        return out;
    }

    private static Stream<JsonNode> cases(JsonNode fixture, String member) {
        List<JsonNode> out = new ArrayList<>();
        fixture.get(member).forEach(out::add);
        return out.stream();
    }

    @TestFactory
    Stream<DynamicTest> linkHeaders() {
        return cases(Fixtures.json("link-headers.json"), "cases").map(c -> dynamicTest(c.get("name").asText(), () -> {
            List<Link> links = LinkHeader.parse(strings(c.get("headers")), URI.create(c.get("base").asText()));
            JsonNode expected = c.get("expected");
            assertEquals(expected.size(), links.size(), "link count");
            for (int i = 0; i < links.size(); i++) {
                JsonNode e = expected.get(i);
                assertEquals(e.get("href").asText(), links.get(i).href().toString());
                assertEquals(e.get("rel").asText(), links.get(i).rel());
                assertEquals(stringMap(e.get("params")), links.get(i).params());
            }
        }));
    }

    @Test
    void linkSerializationRoundTrips() {
        Link l = new Link(URI.create("https://example.org/a"), "describedby", Map.of("title", "say \"hi\""));
        Link parsed = LinkHeader.parse(l.toHeaderValue(), URI.create("https://example.org/")).get(0);
        assertEquals(l, parsed);
    }

    @TestFactory
    Stream<DynamicTest> wwwAuthenticate() {
        return cases(Fixtures.json("www-authenticate.json"), "cases").map(c -> dynamicTest(c.get("name").asText(), () -> {
            List<AuthChallenge> chs = WwwAuthenticate.parse(strings(c.get("headers")));
            JsonNode expected = c.get("expected");
            assertEquals(expected.size(), chs.size(), "challenge count");
            for (int i = 0; i < chs.size(); i++) {
                JsonNode e = expected.get(i);
                assertEquals(e.get("scheme").asText().toLowerCase(Locale.ROOT), chs.get(i).scheme().toLowerCase(Locale.ROOT));
                assertEquals(stringMap(e.get("params")), chs.get(i).params());
                assertEquals(e.has("token68") ? e.get("token68").asText() : null, chs.get(i).token68());
            }
        }));
    }

    @Test
    void lwsChallengeAccessors() {
        AuthChallenge c = WwwAuthenticate.parse("Bearer as_uri=\"https://as.example\", realm=\"https://s.example/\", error=\"invalid_token\"").get(0);
        assertEquals(URI.create("https://as.example"), c.asUri().orElseThrow());
        assertEquals(URI.create("https://s.example/"), c.realm().orElseThrow());
        assertEquals("invalid_token", c.error().orElseThrow());
    }

    @TestFactory
    Stream<DynamicTest> structuredFields() {
        return cases(Fixtures.json("structured-fields.json"), "cases").map(c -> dynamicTest(c.get("name").asText(), () -> {
            String input = c.get("input").asText();
            if (c.path("error").asBoolean(false)) {
                assertThrows(IllegalArgumentException.class, () -> StructuredFields.parseDictionary(input));
                return;
            }
            Map<String, Member> dict = StructuredFields.parseDictionary(input);
            JsonNode expected = c.get("expected");
            assertEquals(expected.size(), dict.size());
            Iterator<Map.Entry<String, JsonNode>> it = expected.properties().iterator();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> e = it.next();
                Member m = dict.get(e.getKey());
                JsonNode em = e.getValue();
                if (em.has("innerList")) {
                    InnerList il = (InnerList) m;
                    assertEquals(em.get("innerList").size(), il.items().size());
                    for (int i = 0; i < il.items().size(); i++) {
                        assertItem(em.get("innerList").get(i), il.items().get(i));
                    }
                    assertParams(em.get("params"), il.params());
                } else {
                    assertItem(em, (Item) m);
                }
            }
            if (c.has("serialized")) {
                Iterator<Map.Entry<String, JsonNode>> s = c.get("serialized").properties().iterator();
                while (s.hasNext()) {
                    Map.Entry<String, JsonNode> e = s.next();
                    assertEquals(e.getValue().asText(), StructuredFields.serialize(dict.get(e.getKey())));
                }
            }
        }));
    }

    private static void assertItem(JsonNode expected, Item actual) {
        assertBare(expected.get("item"), actual.value());
        assertParams(expected.get("params"), actual.params());
    }

    private static void assertParams(JsonNode expected, Map<String, Object> actual) {
        assertEquals(expected.size(), actual.size());
        Iterator<Map.Entry<String, JsonNode>> it = expected.properties().iterator();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> e = it.next();
            assertBare(e.getValue(), actual.get(e.getKey()));
        }
    }

    private static void assertBare(JsonNode typed, Object actual) {
        String type = typed.fieldNames().next();
        JsonNode v = typed.get(type);
        switch (type) {
            case "string" -> assertEquals(v.asText(), actual);
            case "token" -> assertEquals(new Token(v.asText()), actual);
            case "integer" -> assertEquals(v.asLong(), actual);
            case "decimal" -> assertEquals(0, new BigDecimal(v.asText()).compareTo((BigDecimal) actual));
            case "boolean" -> assertEquals(v.asBoolean(), actual);
            case "bytes" -> assertEquals(new Bytes(Base64.getDecoder().decode(v.asText())), actual);
            default -> throw new AssertionError("unknown type " + type);
        }
    }

    @Test
    void jsonPointerAndPatch() {
        JsonNode f = Fixtures.json("json-patch.json");
        for (JsonNode e : f.get("pointerEscapes")) {
            assertEquals(e.get("escaped").asText(), JsonPointer.escape(e.get("segment").asText()));
            assertEquals(e.get("segment").asText(), JsonPointer.unescape(e.get("escaped").asText()));
        }
        for (JsonNode p : f.get("pointers")) {
            assertEquals(p.get("pointer").asText(), JsonPointer.of(strings(p.get("segments"))));
            assertEquals(strings(p.get("segments")), JsonPointer.segments(p.get("pointer").asText()));
        }
        JsonNode ops = f.get("patch").get("operations");
        JsonPatch patch = JsonPatch.builder()
                .add(ops.get(0).get("path").asText(), ops.get(0).get("value"))
                .remove(ops.get(1).get("path").asText())
                .replace(ops.get(2).get("path").asText(), "Alice")
                .move(ops.get(3).get("from").asText(), ops.get(3).get("path").asText())
                .copy(ops.get(4).get("from").asText(), ops.get(4).get("path").asText())
                .test(ops.get(5).get("path").asText(), 30)
                .build();
        assertEquals(ops, patch.toJson());
        assertEquals(ops, Json.parse(patch.toBytes()));
    }

    @TestFactory
    Stream<DynamicTest> typeQueries() {
        return cases(Fixtures.json("type-queries.json"), "cases").map(c -> dynamicTest(c.get("name").asText(), () -> {
            Runnable build = () -> {
                TypeQuery.Builder b = TypeQuery.builder();
                for (JsonNode step : c.get("steps")) {
                    String key = step.get("key").asText();
                    if (step.has("allOf")) {
                        String[] v = strings(step.get("allOf")).toArray(String[]::new);
                        if (key.equals("type")) b.allOf(v);
                        else b.relationAllOf(key, v);
                    } else {
                        String[] v = strings(step.get("anyOf")).toArray(String[]::new);
                        if (key.equals("type")) b.anyOf(v);
                        else b.relationAnyOf(key, v);
                    }
                }
                assertEquals(c.get("json"), b.build().toJson());
            };
            if (c.path("error").asBoolean(false)) {
                assertThrows(IllegalArgumentException.class, build::run);
            } else {
                build.run();
            }
        }));
    }

    @Test
    void typeMatching() {
        assertTrue(Lws.typeMatches("Container", Lws.Type.CONTAINER));
        assertTrue(Lws.typeMatches("lws:DataResource", "DataResource"));
        assertTrue(!Lws.typeMatches("http://example.org/Container", Lws.Type.CONTAINER));
    }

    @Test
    void slugEncoding() {
        assertEquals("hello.txt", LwsClient.encodeSlug("hello.txt"));
        assertEquals("caf%C3%A9 100%25", LwsClient.encodeSlug("café 100%"));
    }
}
