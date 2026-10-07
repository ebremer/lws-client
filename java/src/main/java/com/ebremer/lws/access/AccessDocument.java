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
import java.util.Optional;

/** Shared structure of {@link AccessRequest} and {@link AccessGrant}. */
public sealed interface AccessDocument permits AccessRequest, AccessGrant {
    /** The document types (includes {@code AccessRequest} or {@code AccessGrant}). */
    List<String> types();

    /** The storage the document is scoped to. */
    URI storage();

    /** Where notifications about this document are delivered. */
    Optional<URI> inbox();

    /** The requested or granted access. */
    List<AccessPolicy> access();

    /** The {@code application/lws+json} serialisation. */
    default ObjectNode toJson() {
        ObjectNode o = Json.object();
        o.putArray("@context").add(Lws.LWS_CONTEXT);
        o.set("type", Json.stringArray(types()));
        inbox().ifPresent(i -> o.put("inbox", i.toString()));
        o.put("storage", storage().toString());
        ArrayNode a = o.putArray("access");
        for (AccessPolicy p : access()) a.add(p.toJson());
        return o;
    }

    /** Parsed common members. */
    record Parts(List<String> types, URI storage, Optional<URI> inbox, List<AccessPolicy> access, ObjectNode raw) {}

    static Parts parseParts(JsonNode json, String requiredType) {
        try {
            return parsePartsChecked(json, requiredType);
        } catch (IllegalArgumentException e) {
            // A document from the server that breaks the model (a value that is not a URI, a policy with
            // no action, a target with no value) is the server's fault, not the caller's.
            throw new LwsProtocolException("Malformed " + requiredType + ": " + e.getMessage(), e);
        }
    }

    private static Parts parsePartsChecked(JsonNode json, String requiredType) {
        ObjectNode o = Json.requireObject(json, requiredType);
        List<String> types = Json.stringOrArray(o.get("type"));
        if (!Lws.hasType(types, requiredType)) throw new LwsProtocolException("Document type " + types + " does not include " + requiredType);
        String storage = Json.text(o, "storage");
        if (storage == null) throw new LwsProtocolException(requiredType + " has no storage");
        String inbox = Json.text(o, "inbox");
        List<AccessPolicy> policies = new ArrayList<>();
        JsonNode a = o.get("access");
        if (a != null && a.isArray()) a.forEach(p -> policies.add(AccessPolicy.parse(p)));
        else if (a != null && a.isObject()) policies.add(AccessPolicy.parse(a));
        if (policies.isEmpty()) throw new LwsProtocolException(requiredType + " has no access");
        return new Parts(types, URI.create(storage), Optional.ofNullable(inbox).map(URI::create), policies, o);
    }
}
