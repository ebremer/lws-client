// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

/**
 * A streamed read: metadata plus an open content stream. Close it (try-with-resources) when done.
 */
public final class ResourceStream implements AutoCloseable {
    private final ResourceMetadata metadata;
    private final InputStream body;
    private final boolean notModified;

    ResourceStream(ResourceMetadata metadata, InputStream body, boolean notModified) {
        this.metadata = metadata;
        this.body = body;
        this.notModified = notModified;
    }

    /** The response metadata. */
    public ResourceMetadata metadata() {
        return metadata;
    }

    /** The content stream. */
    public InputStream body() {
        return body;
    }

    /** Whether the server answered {@code 304 Not Modified}. */
    public boolean notModified() {
        return notModified;
    }

    @Override
    public void close() {
        try {
            body.close();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
