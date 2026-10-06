// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.internal.Json;
import com.ebremer.lws.internal.Uris;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * A storage description resource: a W3C Controlled Identifier document describing a storage, its
 * services (storage root, notifications, access requests/grants, type index/search, …), capabilities and
 * verification methods.
 *
 * @param id the canonical storage URI
 * @param types the raw {@code type} values (include {@code Storage})
 * @param services the advertised services
 * @param capabilities the advertised capabilities
 * @param verificationMethods the verification methods (e.g. webhook signing keys)
 * @param authentication the {@code authentication} relationship entries (strings or embedded objects)
 * @param raw the JSON document
 */
public record StorageDescription(URI id, List<String> types, List<Service> services, List<Capability> capabilities,
                                 List<VerificationMethod> verificationMethods, List<JsonNode> authentication,
                                 ObjectNode raw) {
    public StorageDescription {
        types = List.copyOf(types);
        services = List.copyOf(services);
        capabilities = List.copyOf(capabilities);
        verificationMethods = List.copyOf(verificationMethods);
        authentication = Collections.unmodifiableList(new ArrayList<>(authentication));
    }

    /**
     * Parses a storage description. Relative URIs are resolved against {@code base} (the URL it was
     * retrieved from).
     *
     * @throws LwsProtocolException if the document is not a storage description
     */
    public static StorageDescription parse(JsonNode json, URI base) {
        ObjectNode o = Json.requireObject(json, "Storage description");
        String idText = Json.text(o, "id");
        if (idText == null) throw new LwsProtocolException("Storage description has no id");
        URI id = Uris.resolveOrNull(base, idText);
        if (id == null) throw new LwsProtocolException("Storage description id is not a URI: " + idText);
        List<String> types = Json.stringOrArray(o.get("type"));
        if (!Lws.hasType(types, Lws.Type.STORAGE)) {
            throw new LwsProtocolException("Document type " + types + " does not include Storage");
        }
        List<Service> services = new ArrayList<>();
        JsonNode svc = o.get("service");
        if (svc != null && svc.isArray()) {
            for (JsonNode s : svc) {
                if (!s.isObject()) continue;
                URI endpoint = Json.uri(s, "serviceEndpoint", id);
                if (endpoint == null) continue;
                services.add(new Service(Optional.ofNullable(Json.uri(s, "id", id)),
                        Json.stringOrArray(s.get("type")), endpoint, (ObjectNode) s));
            }
        }
        List<Capability> capabilities = new ArrayList<>();
        JsonNode cap = o.get("capability");
        if (cap != null && cap.isArray()) {
            for (JsonNode c : cap) {
                if (c.isObject()) {
                    capabilities.add(new Capability(Optional.ofNullable(Json.uri(c, "id", id)),
                            Json.stringOrArray(c.get("type")), (ObjectNode) c));
                }
            }
        }
        List<VerificationMethod> vms = new ArrayList<>();
        JsonNode vm = o.get("verificationMethod");
        if (vm != null && vm.isArray()) {
            for (JsonNode v : vm) {
                if (v.isObject()) vms.add(VerificationMethod.parse((ObjectNode) v));
            }
        }
        List<JsonNode> authn = new ArrayList<>();
        JsonNode an = o.get("authentication");
        if (an != null && an.isArray()) an.forEach(authn::add);
        else if (an != null && (an.isTextual() || an.isObject())) authn.add(an);
        return new StorageDescription(id, types, services, capabilities, vms, authn, o);
    }

    /** The first service of the given type. */
    public Optional<Service> service(String type) {
        for (Service s : services) {
            if (s.hasType(type)) return Optional.of(s);
        }
        return Optional.empty();
    }

    /** All services of the given type. */
    public List<Service> services(String type) {
        List<Service> out = new ArrayList<>();
        for (Service s : services) {
            if (s.hasType(type)) out.add(s);
        }
        return out;
    }

    /** The first capability of the given type. */
    public Optional<Capability> capability(String type) {
        for (Capability c : capabilities) {
            if (Lws.hasType(c.types(), type)) return Optional.of(c);
        }
        return Optional.empty();
    }

    /**
     * The storage root container URI.
     *
     * @throws LwsProtocolException if the description has no {@code StorageRoot} service
     */
    public URI storageRoot() {
        return service(Lws.Service.STORAGE_ROOT).map(Service::serviceEndpoint)
                .orElseThrow(() -> new LwsProtocolException("Storage description " + id + " has no StorageRoot service"));
    }

    /** The notification service. */
    public Optional<Service> notificationService() {
        return service(Lws.Service.NOTIFICATION);
    }

    /** The access request service. */
    public Optional<Service> accessRequestService() {
        return service(Lws.Service.ACCESS_REQUEST);
    }

    /** The access grant service. */
    public Optional<Service> accessGrantService() {
        return service(Lws.Service.ACCESS_GRANT);
    }

    /** The type index service. */
    public Optional<Service> typeIndexService() {
        return service(Lws.Service.TYPE_INDEX);
    }

    /** The type search service. */
    public Optional<Service> typeSearchService() {
        return service(Lws.Service.TYPE_SEARCH);
    }

    /**
     * Finds a verification method by full id, by fragment ({@code #key} or {@code key}), or by an id that
     * resolves against the storage id to the requested id.
     */
    public Optional<VerificationMethod> verificationMethod(String idOrFragment) {
        for (VerificationMethod v : verificationMethods) {
            if (idMatches(v.id(), idOrFragment)) return Optional.of(v);
        }
        return Optional.empty();
    }

    /** Whether the verification method is referenced from the {@code authentication} relationship. */
    public boolean isAuthenticationMethod(VerificationMethod method) {
        for (JsonNode a : authentication) {
            String ref = a.isTextual() ? a.textValue() : Json.text(a, "id");
            if (ref != null && (ref.equals(method.id()) || sameId(ref, method.id()))) return true;
        }
        return false;
    }

    private boolean idMatches(String vmId, String wanted) {
        if (vmId == null || wanted == null) return false;
        if (vmId.equals(wanted)) return true;
        return sameId(vmId, wanted);
    }

    /** Compares two verification method references after resolving both against the storage id. */
    private boolean sameId(String a, String b) {
        URI ra = resolveRef(a);
        URI rb = resolveRef(b);
        return ra != null && ra.equals(rb);
    }

    private URI resolveRef(String ref) {
        if (ref == null) return null;
        String r = ref;
        if (!r.contains(":") && !r.startsWith("#") && !r.startsWith("/")) r = "#" + r; // bare fragment
        return Uris.resolveOrNull(id, r);
    }

    /**
     * A service object.
     *
     * @param id the optional service id
     * @param types the raw type values
     * @param serviceEndpoint the absolute endpoint URI
     * @param raw the JSON object (for extra members such as {@code subscriptionType} or {@code conformsTo})
     */
    public record Service(Optional<URI> id, List<String> types, URI serviceEndpoint, ObjectNode raw) {
        public Service {
            types = List.copyOf(types);
        }

        /** Whether the service declares {@code type}. */
        public boolean hasType(String type) {
            return Lws.hasType(types, type);
        }

        /** An extra member of the service object. */
        public Optional<JsonNode> property(String name) {
            return Optional.ofNullable(raw.get(name));
        }

        /** The {@code subscriptionType} values of a notification service. */
        public List<String> subscriptionTypes() {
            return Json.stringOrArray(raw.get("subscriptionType"));
        }

        /** The {@code conformsTo} values (access profiles). */
        public List<String> conformsTo() {
            return Json.stringOrArray(raw.get("conformsTo"));
        }
    }

    /**
     * A capability object.
     *
     * @param id the optional capability id
     * @param types the raw type values
     * @param raw the JSON object
     */
    public record Capability(Optional<URI> id, List<String> types, ObjectNode raw) {
        public Capability {
            types = List.copyOf(types);
        }

        /** An extra member of the capability object. */
        public Optional<JsonNode> property(String name) {
            return Optional.ofNullable(raw.get(name));
        }
    }

    /**
     * A verification method.
     *
     * @param id the id as written (may be relative, e.g. {@code #key-1})
     * @param type the method type (e.g. {@code JsonWebKey})
     * @param controller the controller
     * @param publicKeyJwk the public key as a JWK, or null
     * @param raw the JSON object
     */
    public record VerificationMethod(String id, String type, String controller, ObjectNode publicKeyJwk, ObjectNode raw) {
        static VerificationMethod parse(ObjectNode o) {
            JsonNode jwk = o.get("publicKeyJwk");
            return new VerificationMethod(Json.text(o, "id"), Json.text(o, "type"), Json.text(o, "controller"),
                    jwk != null && jwk.isObject() ? (ObjectNode) jwk : null, o);
        }
    }
}
