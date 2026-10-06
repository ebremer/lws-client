// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.internal.Json;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * A request body. Every body is <em>replayable</em> so that a request can be re-sent once after the
 * client obtained an access token: streams are therefore supplied through a {@link Supplier} that opens
 * a fresh stream per attempt.
 */
public final class Body {
    private static final Body EMPTY = new Body(BodyPublishers::noBody, 0);

    private final Supplier<BodyPublisher> publisher;
    private final long length;

    private Body(Supplier<BodyPublisher> publisher, long length) {
        this.publisher = publisher;
        this.length = length;
    }

    /** No body. */
    public static Body empty() {
        return EMPTY;
    }

    /** UTF-8 encoded text. */
    public static Body of(String text) {
        return of(text.getBytes(StandardCharsets.UTF_8));
    }

    /** Raw bytes (not copied — do not modify the array afterwards). */
    public static Body of(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        return new Body(() -> BodyPublishers.ofByteArray(bytes), bytes.length);
    }

    /** A Jackson node or any Jackson-serialisable value, serialised as JSON. */
    public static Body ofJson(Object value) {
        return of(Json.toBytes(Json.valueToTree(value)));
    }

    /** The contents of a file, streamed. */
    public static Body ofFile(Path file) {
        Objects.requireNonNull(file, "file");
        return new Body(() -> {
            try {
                return BodyPublishers.ofFile(file);
            } catch (FileNotFoundException e) {
                throw new UncheckedIOException(e);
            }
        }, -1);
    }

    /** A stream opened anew for every attempt. */
    public static Body ofInputStream(Supplier<? extends InputStream> streams) {
        Objects.requireNonNull(streams, "streams");
        return new Body(() -> BodyPublishers.ofInputStream(streams::get), -1);
    }

    /** A fresh publisher for one request attempt. */
    public BodyPublisher publisher() {
        return publisher.get();
    }

    /** Whether this is the empty body. */
    public boolean isEmpty() {
        return length == 0;
    }
}
