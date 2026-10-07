// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.adapter;

import com.ebremer.lws.ContainedResource;
import com.ebremer.lws.ContainerPage;
import com.ebremer.lws.CreateResult;
import com.ebremer.lws.LwsProtocolException;
import com.ebremer.lws.Resource;
import com.ebremer.lws.ResourceMetadata;
import com.ebremer.lws.StorageDescription;
import com.ebremer.lws.UpdateResult;
import com.ebremer.lws.http.Link;
import com.ebremer.lws.notify.Subscription;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.util.Base64;
import java.util.Collection;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.regex.Pattern;

/** The shared result shapes of PROTOCOL.md section 3.1, built from the library's own results. */
final class Results {
    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;
    /** Content types whose bodies are reported as text. */
    private static final Pattern TEXTUAL =
            Pattern.compile("^(text/|application/(json|xml|[^;]*\\+json|[^;]*\\+xml)\\b)", Pattern.CASE_INSENSITIVE);

    private Results() {}

    static ObjectNode object() {
        return NODES.objectNode();
    }

    static ArrayNode strings(Collection<String> values) {
        ArrayNode a = NODES.arrayNode();
        for (String v : values) a.add(v);
        return a;
    }

    /** Puts an optional member, omitting it when absent. */
    static void put(ObjectNode o, String name, Optional<?> value) {
        value.ifPresent(v -> o.put(name, v.toString()));
    }

    static void put(ObjectNode o, String name, OptionalLong value) {
        value.ifPresent(v -> o.put(name, v));
    }

    /** A response body: text for textual content types, else base64. */
    static ObjectNode body(Resource resource) {
        ObjectNode o = object();
        String contentType = resource.contentType().orElse(null);
        if (contentType != null && TEXTUAL.matcher(contentType.trim()).find()) {
            o.put("text", resource.text());
        } else {
            o.put("base64", Base64.getEncoder().encodeToString(resource.body()));
        }
        return o;
    }

    /** Metadata: the parsed response headers. */
    static ObjectNode metadata(ResourceMetadata m) {
        ObjectNode o = object();
        o.put("url", m.url().toString());
        o.put("status", m.status());
        put(o, "etag", m.etag());
        put(o, "lastModified", m.header("last-modified"));
        put(o, "contentType", m.contentType());
        put(o, "contentLength", m.contentLength());
        ArrayNode links = o.putArray("links");
        for (Link l : m.links()) {
            ObjectNode link = links.addObject();
            link.put("href", l.href().toString());
            link.put("rel", l.rel());
            ObjectNode params = link.putObject("params");
            l.params().forEach(params::put);
        }
        put(o, "linkset", m.linkset());
        put(o, "parent", m.parent());
        put(o, "storage", m.storage());
        o.set("types", strings(m.types()));
        o.set("allow", strings(m.allow()));
        o.set("acceptPatch", strings(m.acceptPatch()));
        return o;
    }

    /** Item: one member of a listing. */
    static ObjectNode item(ContainedResource i) {
        ObjectNode o = object();
        o.put("id", i.id().toString());
        o.set("types", strings(i.types()));
        put(o, "format", i.format());
        put(o, "size", i.size());
        put(o, "modified", i.modifiedRaw());
        return o;
    }

    /** Page: a container page or a page of search results. */
    static ObjectNode page(ContainerPage p) {
        ObjectNode o = object();
        put(o, "id", p.id());
        o.set("types", strings(p.types()));
        put(o, "totalItems", p.totalItems());
        ArrayNode items = o.putArray("items");
        for (ContainedResource i : p.items()) items.add(item(i));
        put(o, "first", p.first());
        put(o, "next", p.next());
        put(o, "prev", p.prev());
        put(o, "last", p.last());
        o.set("metadata", metadata(p.metadata()));
        return o;
    }

    /** Update: the result of a PUT or PATCH. */
    static ObjectNode update(UpdateResult u) {
        ObjectNode o = object();
        o.put("status", u.status());
        put(o, "etag", u.etag());
        o.set("metadata", metadata(u.metadata()));
        return o;
    }

    /** Created: the result of a create. */
    static ObjectNode created(CreateResult c) {
        ObjectNode o = object();
        o.put("location", c.location().toString());
        o.set("metadata", metadata(c.metadata()));
        return o;
    }

    /** Storage: a storage description; {@code storageRoot} is omitted when the library's {@code storageRoot()} fails. */
    static ObjectNode storage(StorageDescription s) {
        ObjectNode o = object();
        o.put("id", s.id().toString());
        o.set("types", strings(s.types()));
        URI storageRoot;
        try {
            storageRoot = s.storageRoot();
        } catch (LwsProtocolException e) {
            storageRoot = null;
        }
        put(o, "storageRoot", Optional.ofNullable(storageRoot));
        ArrayNode services = o.putArray("services");
        for (StorageDescription.Service svc : s.services()) {
            ObjectNode service = services.addObject();
            put(service, "id", svc.id());
            service.set("types", strings(svc.types()));
            service.put("serviceEndpoint", svc.serviceEndpoint().toString());
            if (svc.property("subscriptionType").isPresent()) service.set("subscriptionType", strings(svc.subscriptionTypes()));
        }
        ArrayNode methods = o.putArray("verificationMethods");
        for (StorageDescription.VerificationMethod vm : s.verificationMethods()) {
            ObjectNode method = methods.addObject();
            put(method, "id", Optional.ofNullable(vm.id()));
            put(method, "type", Optional.ofNullable(vm.type()));
            put(method, "controller", Optional.ofNullable(vm.controller()));
        }
        o.set("raw", s.raw());
        return o;
    }

    /** Subscription. */
    static ObjectNode subscription(Subscription s) {
        ObjectNode o = object();
        o.put("subscription", s.subscription().toString());
        ArrayNode types = o.putArray("types");
        if (s.type() != null) types.add(s.type());
        put(o, "expires", s.expiresRaw());
        o.set("raw", s.raw());
        return o;
    }
}
