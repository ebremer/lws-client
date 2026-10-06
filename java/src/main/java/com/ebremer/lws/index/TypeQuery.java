// SPDX-License-Identifier: MIT
package com.ebremer.lws.index;

import com.ebremer.lws.Lws;
import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * A Type Search filter ({@code application/lws-query+json}) in conjunctive normal form: every group must
 * match (AND), and a group matches when any of its IRIs matches (OR).
 *
 * <pre>{@code
 * // (schema:Person OR foaf:Person) AND lws:DataResource
 * TypeQuery q = TypeQuery.builder()
 *     .anyOf("https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person")
 *     .allOf("https://www.w3.org/ns/lws#DataResource")
 *     .build();
 * }</pre>
 *
 * Besides {@code type}, servers may index descriptive link relations, filtered with
 * {@link Builder#relationAllOf} / {@link Builder#relationAnyOf}. An empty query matches everything.
 */
public final class TypeQuery {
    /** The query media type. */
    public static final String MEDIA_TYPE = Lws.MediaType.LWS_QUERY_JSON;
    private static final Pattern ABSOLUTE_IRI = Pattern.compile("^[A-Za-z][A-Za-z0-9+.-]*:[^\\s<>\"{}|\\\\^`]+$");

    private final Map<String, List<List<String>>> filters;

    private TypeQuery(Map<String, List<List<String>>> filters) {
        Map<String, List<List<String>>> copy = new LinkedHashMap<>();
        filters.forEach((k, v) -> {
            List<List<String>> groups = new ArrayList<>();
            v.forEach(g -> groups.add(List.copyOf(g)));
            copy.put(k, Collections.unmodifiableList(groups));
        });
        this.filters = Collections.unmodifiableMap(copy);
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Resources having all of {@code types}. */
    public static TypeQuery allOf(String... types) {
        return builder().allOf(types).build();
    }

    /** Resources having any of {@code types}. */
    public static TypeQuery anyOf(String... types) {
        return builder().anyOf(types).build();
    }

    /** The filter groups per key ({@code type} or a relation). */
    public Map<String, List<List<String>>> filters() {
        return filters;
    }

    /** The filter document. One-element OR groups are serialised as plain strings. */
    public ObjectNode toJson() {
        ObjectNode o = Json.object();
        filters.forEach((key, groups) -> {
            ArrayNode a = o.putArray(key);
            for (List<String> g : groups) {
                if (g.size() == 1) a.add(g.get(0));
                else a.add(Json.stringArray(g));
            }
        });
        return o;
    }

    /** The serialised filter document. */
    public byte[] toBytes() {
        return Json.toBytes(toJson());
    }

    @Override
    public String toString() {
        return Json.toString(toJson());
    }

    /** Whether {@code iri} is an absolute IRI (scheme followed by a non-empty remainder). */
    public static boolean isAbsoluteIri(String iri) {
        return iri != null && ABSOLUTE_IRI.matcher(iri).matches();
    }

    /** Builder for {@link TypeQuery}; validation mirrors the server's {@code 400} rules. */
    public static final class Builder {
        private final Map<String, List<List<String>>> filters = new LinkedHashMap<>();

        private Builder() {}

        /** Each type becomes its own AND group. */
        public Builder allOf(String... types) {
            return relationAllOf("type", types);
        }

        /** One OR group of types (must not be empty). */
        public Builder anyOf(String... types) {
            return relationAnyOf("type", types);
        }

        /** Each target of {@code relation} becomes its own AND group. */
        public Builder relationAllOf(String relation, String... targets) {
            for (String t : targets) group(relation, List.of(validate(t)));
            return this;
        }

        /** One OR group of {@code relation} targets (must not be empty). */
        public Builder relationAnyOf(String relation, String... targets) {
            if (targets.length == 0) throw new IllegalArgumentException("An OR group must not be empty");
            List<String> g = new ArrayList<>();
            for (String t : targets) g.add(validate(t));
            group(relation, g);
            return this;
        }

        private void group(String relation, List<String> group) {
            if (relation == null || relation.isEmpty() || relation.startsWith("@")) {
                throw new IllegalArgumentException("Invalid filter key: " + relation);
            }
            List<List<String>> groups = filters.computeIfAbsent(relation, k -> new ArrayList<>());
            if (!groups.contains(group)) groups.add(group);
        }

        private static String validate(String iri) {
            if (!isAbsoluteIri(iri)) throw new IllegalArgumentException("Not an absolute IRI: " + iri);
            return iri;
        }

        public TypeQuery build() {
            return new TypeQuery(filters);
        }
    }
}
