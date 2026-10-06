// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;

/**
 * The result of reading a resource: its metadata and content.
 *
 * <p>A conditional read answered with {@code 304 Not Modified} is not an error: {@link #notModified()} is
 * true and the body is empty. A {@code 206 Partial Content} answer exposes {@link #contentRange()}.
 *
 * @param metadata the response metadata
 * @param body the content (empty for {@code HEAD} and {@code 304})
 * @param notModified whether the server answered {@code 304 Not Modified}
 */
public record Resource(ResourceMetadata metadata, byte[] body, boolean notModified) {
    public Resource {
        body = body == null ? new byte[0] : body;
    }

    /** The final request URL. */
    public URI url() {
        return metadata.url();
    }

    /** The entity tag, verbatim. */
    public Optional<String> etag() {
        return metadata.etag();
    }

    /** The content type. */
    public Optional<String> contentType() {
        return metadata.contentType();
    }

    /** The {@code Content-Range} of a partial response. */
    public Optional<String> contentRange() {
        return metadata.header("content-range");
    }

    /** The HTTP status. */
    public int status() {
        return metadata.status();
    }

    /** The content bytes (a copy). */
    public byte[] bytes() {
        return body.clone();
    }

    /** The content decoded with the {@code charset} of the content type (default UTF-8). */
    public String text() {
        return new String(body, charset());
    }

    /** The content parsed as JSON. */
    public JsonNode json() {
        return Json.parse(body);
    }

    /** The content parsed as JSON and bound to {@code type} with Jackson. */
    public <T> T json(Class<T> type) {
        try {
            return Json.MAPPER.readValue(body, type);
        } catch (IOException e) {
            throw new LwsProtocolException("Cannot bind JSON content to " + type.getName() + ": " + e.getMessage(), e);
        }
    }

    private Charset charset() {
        String ct = metadata.contentType().orElse("");
        for (String part : ct.split(";")) {
            String p = part.trim();
            if (p.toLowerCase(Locale.ROOT).startsWith("charset=")) {
                String name = p.substring(8).trim().replace("\"", "");
                try {
                    return Charset.forName(name);
                } catch (Exception e) {
                    return StandardCharsets.UTF_8;
                }
            }
        }
        return StandardCharsets.UTF_8;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Resource r && r.metadata.equals(metadata) && java.util.Arrays.equals(r.body, body)
                && r.notModified == notModified;
    }

    @Override
    public int hashCode() {
        return metadata.hashCode() * 31 + java.util.Arrays.hashCode(body);
    }

    @Override
    public String toString() {
        return "Resource[" + metadata.url() + ", status=" + metadata.status() + ", " + body.length + " bytes]";
    }
}
