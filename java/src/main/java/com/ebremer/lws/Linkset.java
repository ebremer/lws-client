// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.http.Link;
import com.ebremer.lws.internal.Json;
import com.ebremer.lws.internal.Uris;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * An immutable linkset document ({@code application/linkset+json}, RFC 9264) holding a resource's
 * metadata links. Mutators return modified copies; unknown members are preserved on round trip.
 *
 * <pre>{@code
 * Linkset updated = linkset.add(anchor, "license", URI.create("https://creativecommons.org/licenses/by/4.0/"));
 * }</pre>
 *
 * @param contexts the link context objects
 */
public record Linkset(List<LinkContext> contexts) {
    public Linkset {
        contexts = List.copyOf(contexts);
    }

    /** An empty linkset. */
    public static Linkset empty() {
        return new Linkset(List.of());
    }

    /** Parses an {@code application/linkset+json} document. */
    public static Linkset parse(JsonNode json) {
        ObjectNode o = Json.requireObject(json, "Linkset");
        JsonNode ls = o.get("linkset");
        if (ls == null || !ls.isArray()) throw new LwsProtocolException("Linkset document has no 'linkset' array");
        List<LinkContext> contexts = new ArrayList<>();
        for (JsonNode c : ls) {
            if (!c.isObject()) throw new LwsProtocolException("Linkset context is not an object");
            contexts.add(LinkContext.parse((ObjectNode) c));
        }
        return new Linkset(contexts);
    }

    /** The {@code application/linkset+json} serialisation. */
    public ObjectNode toJson() {
        ObjectNode o = Json.object();
        ArrayNode a = o.putArray("linkset");
        for (LinkContext c : contexts) a.add(c.toJson());
        return o;
    }

    /** Every link, flattened; targets are resolved against their anchor. */
    public List<Link> links() {
        List<Link> out = new ArrayList<>();
        for (LinkContext c : contexts) {
            URI anchor = c.anchor() == null ? null : Uris.resolveOrNull(null, c.anchor());
            for (Map.Entry<String, List<LinkTarget>> e : c.relations().entrySet()) {
                for (LinkTarget t : e.getValue()) {
                    URI href = Uris.resolveOrNull(anchor, t.href());
                    if (href == null) continue;
                    Map<String, String> params = new LinkedHashMap<>();
                    if (c.anchor() != null) params.put("anchor", c.anchor());
                    Iterator<Map.Entry<String, JsonNode>> it = t.attributes().properties().iterator();
                    while (it.hasNext()) {
                        Map.Entry<String, JsonNode> a = it.next();
                        if (a.getValue().isTextual()) params.put(a.getKey(), a.getValue().textValue());
                    }
                    out.add(new Link(href, e.getKey(), params));
                }
            }
        }
        return out;
    }

    /** The targets of {@code rel} across all contexts. */
    public List<LinkTarget> targets(String rel) {
        List<LinkTarget> out = new ArrayList<>();
        for (LinkContext c : contexts) out.addAll(c.targets(rel));
        return out;
    }

    /** The targets of {@code rel} for one anchor. */
    public List<LinkTarget> targets(String anchor, String rel) {
        return context(anchor).map(c -> c.targets(rel)).orElse(List.of());
    }

    /** The context object for {@code anchor}. */
    public Optional<LinkContext> context(String anchor) {
        for (LinkContext c : contexts) {
            if (Objects.equals(c.anchor(), anchor)) return Optional.of(c);
        }
        return Optional.empty();
    }

    /** Returns a copy with a link added (creating the context for {@code anchor} if needed). */
    public Linkset add(String anchor, String rel, String href, Map<String, ?> attributes) {
        ObjectNode attrs = Json.object();
        if (attributes != null) attributes.forEach((k, v) -> attrs.set(k, Json.valueToTree(v)));
        LinkTarget target = new LinkTarget(href, attrs);
        List<LinkContext> out = new ArrayList<>(contexts);
        for (int i = 0; i < out.size(); i++) {
            LinkContext c = out.get(i);
            if (Objects.equals(c.anchor(), anchor)) {
                out.set(i, c.with(rel, target));
                return new Linkset(out);
            }
        }
        out.add(new LinkContext(anchor, Map.of(rel, List.of(target)), Json.object()));
        return new Linkset(out);
    }

    /** Returns a copy with a link added. */
    public Linkset add(String anchor, String rel, URI href) {
        return add(anchor, rel, href.toString(), Map.of());
    }

    /**
     * Returns a copy without the links of {@code rel} for {@code anchor}; when {@code href} is non-null only
     * that target is removed. Relations left empty are dropped.
     */
    public Linkset remove(String anchor, String rel, String href) {
        List<LinkContext> out = new ArrayList<>();
        for (LinkContext c : contexts) {
            out.add(Objects.equals(c.anchor(), anchor) ? c.without(rel, href) : c);
        }
        return new Linkset(out);
    }

    /**
     * One link context object of a linkset.
     *
     * @param anchor the context URI as written
     * @param relations relation type → targets, in document order
     * @param extra unknown members other than relations (preserved)
     */
    public record LinkContext(String anchor, Map<String, List<LinkTarget>> relations, ObjectNode extra) {
        public LinkContext {
            Map<String, List<LinkTarget>> copy = new LinkedHashMap<>();
            relations.forEach((k, v) -> copy.put(k, List.copyOf(v)));
            relations = Collections.unmodifiableMap(copy);
            extra = extra == null ? Json.object() : extra;
        }

        static LinkContext parse(ObjectNode o) {
            Map<String, List<LinkTarget>> rels = new LinkedHashMap<>();
            ObjectNode extra = Json.object();
            String anchor = null;
            Iterator<Map.Entry<String, JsonNode>> it = o.properties().iterator();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> e = it.next();
                if (e.getKey().equals("anchor") && e.getValue().isTextual()) {
                    anchor = e.getValue().textValue();
                } else if (e.getValue().isArray()) {
                    List<LinkTarget> targets = new ArrayList<>();
                    boolean ok = true;
                    for (JsonNode t : e.getValue()) {
                        if (t.isObject() && t.get("href") != null && t.get("href").isTextual()) {
                            targets.add(LinkTarget.parse((ObjectNode) t));
                        } else {
                            ok = false;
                        }
                    }
                    if (ok) rels.put(e.getKey(), targets);
                    else extra.set(e.getKey(), e.getValue());
                } else {
                    extra.set(e.getKey(), e.getValue());
                }
            }
            return new LinkContext(anchor, rels, extra);
        }

        ObjectNode toJson() {
            ObjectNode o = Json.object();
            if (anchor != null) o.put("anchor", anchor);
            relations.forEach((rel, targets) -> {
                ArrayNode a = o.putArray(rel);
                for (LinkTarget t : targets) a.add(t.toJson());
            });
            o.setAll(extra);
            return o;
        }

        /** The targets of {@code rel}. */
        public List<LinkTarget> targets(String rel) {
            return relations.getOrDefault(rel, List.of());
        }

        LinkContext with(String rel, LinkTarget target) {
            Map<String, List<LinkTarget>> rels = new LinkedHashMap<>(relations);
            List<LinkTarget> list = new ArrayList<>(rels.getOrDefault(rel, List.of()));
            list.add(target);
            rels.put(rel, list);
            return new LinkContext(anchor, rels, extra);
        }

        LinkContext without(String rel, String href) {
            Map<String, List<LinkTarget>> rels = new LinkedHashMap<>(relations);
            if (href == null) {
                rels.remove(rel);
            } else {
                List<LinkTarget> list = new ArrayList<>(rels.getOrDefault(rel, List.of()));
                list.removeIf(t -> t.href().equals(href));
                if (list.isEmpty()) rels.remove(rel);
                else rels.put(rel, list);
            }
            return new LinkContext(anchor, rels, extra);
        }
    }

    /**
     * A link target object.
     *
     * @param href the target URI as written
     * @param attributes the target attributes ({@code type}, {@code title}, {@code hreflang}, {@code title*}, …)
     */
    public record LinkTarget(String href, ObjectNode attributes) {
        public LinkTarget {
            Objects.requireNonNull(href, "href");
            attributes = attributes == null ? Json.object() : attributes;
        }

        static LinkTarget parse(ObjectNode o) {
            ObjectNode attrs = o.deepCopy();
            attrs.remove("href");
            return new LinkTarget(o.get("href").textValue(), attrs);
        }

        ObjectNode toJson() {
            ObjectNode o = Json.object();
            o.put("href", href);
            o.setAll(attributes);
            return o;
        }

        /** A string attribute. */
        public Optional<String> attribute(String name) {
            JsonNode v = attributes.get(name);
            return v != null && v.isTextual() ? Optional.of(v.textValue()) : Optional.empty();
        }
    }
}
