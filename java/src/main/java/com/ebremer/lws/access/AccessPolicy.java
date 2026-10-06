// SPDX-License-Identifier: MIT
package com.ebremer.lws.access;

import com.ebremer.lws.Lws;
import com.ebremer.lws.LwsProtocolException;
import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * An access policy of the LWS Access Profile (ODRL-based): who ({@code assignee}) may do what
 * ({@code actions}) on which resources ({@code target}) under which {@code constraints}.
 *
 * @param types the policy types (includes {@code AccessPolicy})
 * @param actions {@code read}, {@code modify}, {@code create}, {@code delete}, …
 * @param assignee the agent ({@link Lws#PUBLIC_AGENT} for public access)
 * @param target the target resources
 * @param constraints the constraints (all must hold)
 */
public record AccessPolicy(List<String> types, List<String> actions, URI assignee, Optional<AccessTarget> target,
                           List<Constraint> constraints) {
    public AccessPolicy {
        types = List.copyOf(types);
        actions = List.copyOf(actions);
        constraints = List.copyOf(constraints);
        Objects.requireNonNull(assignee, "assignee");
        if (actions.isEmpty()) throw new IllegalArgumentException("An access policy needs at least one action");
    }

    public static Builder builder() {
        return new Builder();
    }

    ObjectNode toJson() {
        ObjectNode o = Json.object();
        o.set("type", Json.stringArray(types));
        o.set("action", Json.stringArray(actions));
        o.put("assignee", assignee.toString());
        target.ifPresent(t -> o.set("target", t.toJson()));
        if (!constraints.isEmpty()) {
            ArrayNode a = o.putArray("constraint");
            for (Constraint c : constraints) a.add(c.toJson());
        }
        return o;
    }

    static AccessPolicy parse(JsonNode n) {
        String assignee = Json.text(n, "assignee");
        if (assignee == null) throw new LwsProtocolException("Access policy has no assignee");
        List<Constraint> cs = new ArrayList<>();
        JsonNode c = n.get("constraint");
        if (c != null && c.isArray()) c.forEach(x -> cs.add(Constraint.parse(x)));
        JsonNode t = n.get("target");
        return new AccessPolicy(Json.stringOrArray(n.get("type")), Json.stringOrArray(n.get("action")), URI.create(assignee),
                t != null && t.isObject() ? Optional.of(AccessTarget.parse(t)) : Optional.empty(), cs);
    }

    /** Builder for {@link AccessPolicy}. */
    public static final class Builder {
        private final List<String> actions = new ArrayList<>();
        private URI assignee;
        private AccessTarget target;
        private final List<Constraint> constraints = new ArrayList<>();

        private Builder() {}

        /** Adds actions ({@code read}, {@code modify}, {@code create}, {@code delete}). */
        public Builder actions(String... actions) {
            this.actions.addAll(List.of(actions));
            return this;
        }

        public Builder assignee(URI assignee) {
            this.assignee = assignee;
            return this;
        }

        public Builder target(AccessTarget target) {
            this.target = target;
            return this;
        }

        public Builder constraint(Constraint constraint) {
            constraints.add(constraint);
            return this;
        }

        public AccessPolicy build() {
            if (assignee == null) throw new IllegalStateException("assignee is required");
            return new AccessPolicy(List.of(Lws.Type.ACCESS_POLICY), actions, assignee, Optional.ofNullable(target), constraints);
        }
    }
}
