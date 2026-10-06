// SPDX-License-Identifier: MIT
package com.ebremer.lws.access;

import com.ebremer.lws.Lws;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A request by an agent for access to resources of a storage.
 *
 * <pre>{@code
 * AccessRequest req = AccessRequest.builder()
 *     .storage(storageId)
 *     .inbox(URI.create("https://id.example/agent/inbox/"))
 *     .access(AccessPolicy.builder()
 *         .actions("read")
 *         .assignee(agent)
 *         .target(AccessTarget.storageResources(projects))
 *         .constraint(Constraint.purpose(URI.create("https://purpose.example/collaboration")))
 *         .build())
 *     .build();
 * }</pre>
 *
 * @param types the types (includes {@code AccessRequest})
 * @param storage the storage
 * @param inbox where to notify the requester
 * @param access the requested access
 * @param raw the JSON document when parsed from a server, else null
 */
public record AccessRequest(List<String> types, URI storage, Optional<URI> inbox, List<AccessPolicy> access, ObjectNode raw)
        implements AccessDocument {
    public AccessRequest {
        types = List.copyOf(types);
        access = List.copyOf(access);
        Objects.requireNonNull(storage, "storage");
        if (access.isEmpty()) throw new IllegalArgumentException("An access request needs at least one access policy");
    }

    /** Parses an access request document. */
    public static AccessRequest parse(JsonNode json) {
        Parts p = AccessDocument.parseParts(json, Lws.Type.ACCESS_REQUEST);
        return new AccessRequest(p.types(), p.storage(), p.inbox(), p.access(), p.raw());
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Builder for {@link AccessRequest}. */
    public static final class Builder {
        private URI storage;
        private URI inbox;
        private final List<AccessPolicy> access = new ArrayList<>();

        private Builder() {}

        public Builder storage(URI storage) {
            this.storage = storage;
            return this;
        }

        public Builder inbox(URI inbox) {
            this.inbox = inbox;
            return this;
        }

        public Builder access(AccessPolicy policy) {
            access.add(policy);
            return this;
        }

        public AccessRequest build() {
            if (storage == null) throw new IllegalStateException("storage is required");
            return new AccessRequest(List.of(Lws.Type.ACCESS_REQUEST), storage, Optional.ofNullable(inbox), access, null);
        }
    }
}
