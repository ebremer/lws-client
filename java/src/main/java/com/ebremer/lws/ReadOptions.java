// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Options for read operations: content negotiation, byte ranges, conditional requests and preferences.
 *
 * <pre>{@code
 * Resource r = client.read(uri, ReadOptions.ifNoneMatch(etag));
 * if (r.notModified()) { ... }
 * }</pre>
 */
public final class ReadOptions {
    /** Default options. */
    public static final ReadOptions DEFAULT = builder().build();

    private final String accept;
    private final String range;
    private final String ifNoneMatch;
    private final Instant ifModifiedSince;
    private final String prefer;
    private final Map<String, List<String>> headers;
    private final Duration timeout;

    private ReadOptions(Builder b) {
        this.accept = b.accept;
        this.range = b.range;
        this.ifNoneMatch = b.ifNoneMatch;
        this.ifModifiedSince = b.ifModifiedSince;
        this.prefer = b.prefer;
        this.headers = RequestOptions.freeze(b.headers);
        this.timeout = b.timeout;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Conditional read: answers {@code 304 Not Modified} (a non-error result) if the ETag still matches. */
    public static ReadOptions ifNoneMatch(String etag) {
        return builder().ifNoneMatch(etag).build();
    }

    /** Content negotiation. */
    public static ReadOptions accept(String mediaTypes) {
        return builder().accept(mediaTypes).build();
    }

    public Optional<String> acceptValue() {
        return Optional.ofNullable(accept);
    }

    /** The {@code Range} header value, e.g. {@code bytes=0-99}. */
    public Optional<String> range() {
        return Optional.ofNullable(range);
    }

    public Optional<String> ifNoneMatchValue() {
        return Optional.ofNullable(ifNoneMatch);
    }

    public Optional<Instant> ifModifiedSince() {
        return Optional.ofNullable(ifModifiedSince);
    }

    public Optional<String> prefer() {
        return Optional.ofNullable(prefer);
    }

    public Map<String, List<String>> headers() {
        return headers;
    }

    public Optional<Duration> timeout() {
        return Optional.ofNullable(timeout);
    }

    /** Builder for {@link ReadOptions}. */
    public static final class Builder {
        private String accept;
        private String range;
        private String ifNoneMatch;
        private Instant ifModifiedSince;
        private String prefer;
        private final Map<String, List<String>> headers = new LinkedHashMap<>();
        private Duration timeout;

        private Builder() {}

        /** The {@code Accept} header. */
        public Builder accept(String accept) {
            this.accept = accept;
            return this;
        }

        /** Requests bytes {@code start..end} inclusive ({@code end} null means "to the end"). */
        public Builder range(long start, Long end) {
            this.range = "bytes=" + start + "-" + (end == null ? "" : end.toString());
            return this;
        }

        /** Requests the last {@code length} bytes. */
        public Builder suffixRange(long length) {
            this.range = "bytes=-" + length;
            return this;
        }

        /** A raw {@code Range} header value. */
        public Builder range(String range) {
            this.range = range;
            return this;
        }

        public Builder ifNoneMatch(String etag) {
            this.ifNoneMatch = etag;
            return this;
        }

        public Builder ifModifiedSince(Instant instant) {
            this.ifModifiedSince = instant;
            return this;
        }

        /** The {@code Prefer} header (RFC 7240). */
        public Builder prefer(String prefer) {
            this.prefer = prefer;
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

        public ReadOptions build() {
            return new ReadOptions(this);
        }
    }
}
