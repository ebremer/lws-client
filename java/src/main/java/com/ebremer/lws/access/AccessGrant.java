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
 * A record, created by a storage controller, of access granted to an agent. Creating or revoking
 * (deleting) a grant makes the server adjust its access policies.
 *
 * @param types the types (includes {@code AccessGrant})
 * @param storage the storage
 * @param inbox where to notify about the grant
 * @param access the granted access
 * @param raw the JSON document when parsed from a server, else null
 */
public record AccessGrant(List<String> types, URI storage, Optional<URI> inbox, List<AccessPolicy> access, ObjectNode raw)
        implements AccessDocument {
    public AccessGrant {
        types = List.copyOf(types);
        access = List.copyOf(access);
        Objects.requireNonNull(storage, "storage");
        if (access.isEmpty()) throw new IllegalArgumentException("An access grant needs at least one access policy");
    }

    /** Parses an access grant document. */
    public static AccessGrant parse(JsonNode json) {
        Parts p = AccessDocument.parseParts(json, Lws.Type.ACCESS_GRANT);
        return new AccessGrant(p.types(), p.storage(), p.inbox(), p.access(), p.raw());
    }

    /** A grant mirroring an access request (same storage, inbox and policies). */
    public static AccessGrant approving(AccessRequest request) {
        return new AccessGrant(List.of(Lws.Type.ACCESS_GRANT), request.storage(), request.inbox(), request.access(), null);
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Builder for {@link AccessGrant}. */
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

        public AccessGrant build() {
            if (storage == null) throw new IllegalStateException("storage is required");
            return new AccessGrant(List.of(Lws.Type.ACCESS_GRANT), storage, Optional.ofNullable(inbox), access, null);
        }
    }
}
