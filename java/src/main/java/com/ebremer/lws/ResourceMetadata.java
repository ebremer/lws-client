// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.http.Link;
import com.ebremer.lws.http.LinkHeader;
import com.ebremer.lws.internal.HeaderLists;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

/**
 * Metadata of a Storage Resource, parsed from response headers.
 *
 * @param url the final request URL
 * @param status the HTTP status code
 * @param headers the raw response headers
 * @param links all {@code Link} header links, resolved against {@code url}
 */
public record ResourceMetadata(URI url, int status, HttpHeaders headers, List<Link> links) {
    public ResourceMetadata {
        links = List.copyOf(links);
    }

    /** Parses the metadata of a response. */
    public static ResourceMetadata of(URI url, int status, HttpHeaders headers) {
        return new ResourceMetadata(url, status, headers, LinkHeader.parse(headers.allValues("link"), url));
    }

    /** The first value of a header (case-insensitive name). */
    public Optional<String> header(String name) {
        return headers.firstValue(name);
    }

    /** The entity tag, verbatim including quotes and any {@code W/} prefix — send it back unchanged in {@code If-Match}. */
    public Optional<String> etag() {
        return headers.firstValue("etag");
    }

    /** The {@code Last-Modified} date. */
    public Optional<Instant> lastModified() {
        return headers.firstValue("last-modified").flatMap(ResourceMetadata::httpDate);
    }

    /** The {@code Content-Type} header value. */
    public Optional<String> contentType() {
        return headers.firstValue("content-type");
    }

    /** The {@code Content-Length}, when present. */
    public OptionalLong contentLength() {
        return headers.firstValueAsLong("content-length");
    }

    /** The first link with relation {@code rel}. */
    public Optional<Link> link(String rel) {
        return LinkHeader.first(links, rel);
    }

    /** All links with relation {@code rel}. */
    public List<Link> links(String rel) {
        return LinkHeader.all(links, rel);
    }

    /** The linkset resource ({@code rel="linkset"}). */
    public Optional<URI> linkset() {
        return link(Lws.Rel.LINKSET).map(Link::href);
    }

    /** The parent container ({@code rel="up"}). */
    public Optional<URI> parent() {
        return link(Lws.Rel.UP).map(Link::href);
    }

    /** The storage ({@code rel="https://www.w3.org/ns/lws#storage"}). */
    public Optional<URI> storage() {
        return link(Lws.Rel.STORAGE).map(Link::href);
    }

    /** The resource types ({@code rel="type"} targets). */
    public List<String> types() {
        List<String> out = new ArrayList<>();
        for (Link l : links(Lws.Rel.TYPE)) out.add(l.href().toString());
        return out;
    }

    /** Whether a {@code rel="type"} link declares {@code type}. */
    public boolean hasType(String type) {
        return Lws.hasType(types(), type);
    }

    /** Whether the resource is a container. */
    public boolean isContainer() {
        return hasType(Lws.Type.CONTAINER);
    }

    /** Whether the resource is a data resource. */
    public boolean isDataResource() {
        return hasType(Lws.Type.DATA_RESOURCE);
    }

    /** Methods from the {@code Allow} header. */
    public List<String> allow() {
        return HeaderLists.tokens(headers.allValues("allow"));
    }

    /** Patch formats from the {@code Accept-Patch} header. */
    public List<String> acceptPatch() {
        return HeaderLists.mediaTypes(headers.allValues("accept-patch"));
    }

    static Optional<Instant> httpDate(String value) {
        try {
            return Optional.of(ZonedDateTime.parse(value.trim(), DateTimeFormatter.RFC_1123_DATE_TIME).toInstant());
        } catch (DateTimeParseException e) {
            return Optional.empty();
        }
    }
}
