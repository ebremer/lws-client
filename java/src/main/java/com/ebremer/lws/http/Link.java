// SPDX-License-Identifier: MIT
package com.ebremer.lws.http;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A typed web link (RFC 8288): an absolute target, one relation type, and target attributes.
 *
 * @param href the absolute link target
 * @param rel the relation type (registered names lower-case; extension relation URIs as-is)
 * @param params the target attributes, lower-case names, excluding {@code rel}
 */
public record Link(URI href, String rel, Map<String, String> params) {
    public Link {
        Objects.requireNonNull(href, "href");
        Objects.requireNonNull(rel, "rel");
        params = params == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(params));
    }

    /** A link without attributes. */
    public static Link of(URI href, String rel) {
        return new Link(href, rel, Map.of());
    }

    /** A link without attributes. */
    public static Link of(String href, String rel) {
        return new Link(URI.create(href), rel, Map.of());
    }

    /** A {@code rel="type"} link declaring a resource type. */
    public static Link type(String typeIri) {
        return of(typeIri, "type");
    }

    /** Returns a copy with an extra attribute. */
    public Link withParam(String name, String value) {
        Map<String, String> p = new LinkedHashMap<>(params);
        p.put(name.toLowerCase(java.util.Locale.ROOT), value);
        return new Link(href, rel, p);
    }

    /** A target attribute by (case-insensitive) name. */
    public Optional<String> param(String name) {
        return Optional.ofNullable(params.get(name.toLowerCase(java.util.Locale.ROOT)));
    }

    /** The {@code type} attribute (target media type hint). */
    public Optional<String> type() {
        return param("type");
    }

    /** The {@code anchor} attribute (link context override), unresolved. */
    public Optional<String> anchor() {
        return param("anchor");
    }

    /** Serialises this link as a {@code Link} header field value. */
    public String toHeaderValue() {
        return LinkHeader.format(this);
    }

    @Override
    public String toString() {
        return toHeaderValue();
    }
}
