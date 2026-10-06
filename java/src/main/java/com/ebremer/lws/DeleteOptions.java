// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Options for deletes: optimistic concurrency and recursive container deletion ({@code Depth: infinity}). */
public final class DeleteOptions {
    /** Default options (unconditional, non-recursive). */
    public static final DeleteOptions DEFAULT = builder().build();

    private final String ifMatch;
    private final boolean recursive;
    private final Map<String, List<String>> headers;
    private final Duration timeout;

    private DeleteOptions(Builder b) {
        this.ifMatch = b.ifMatch;
        this.recursive = b.recursive;
        this.headers = RequestOptions.freeze(b.headers);
        this.timeout = b.timeout;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Recursively delete a container and everything in it. */
    public static DeleteOptions recursive() {
        return builder().recursive(true).build();
    }

    /** Only delete if the resource still has this ETag. */
    public static DeleteOptions ifMatch(String etag) {
        return builder().ifMatch(etag).build();
    }

    public Optional<String> ifMatchValue() {
        return Optional.ofNullable(ifMatch);
    }

    public boolean isRecursive() {
        return recursive;
    }

    public Map<String, List<String>> headers() {
        return headers;
    }

    public Optional<Duration> timeout() {
        return Optional.ofNullable(timeout);
    }

    /** Builder for {@link DeleteOptions}. */
    public static final class Builder {
        private String ifMatch;
        private boolean recursive;
        private final Map<String, List<String>> headers = new LinkedHashMap<>();
        private Duration timeout;

        private Builder() {}

        public Builder ifMatch(String etag) {
            this.ifMatch = etag;
            return this;
        }

        public Builder recursive(boolean recursive) {
            this.recursive = recursive;
            return this;
        }

        public Builder header(String name, String value) {
            RequestOptions.addHeader(headers, name, value);
            return this;
        }

        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        public DeleteOptions build() {
            return new DeleteOptions(this);
        }
    }
}
