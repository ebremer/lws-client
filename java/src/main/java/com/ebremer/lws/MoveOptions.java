// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Options for moves: the {@code If-Match} of the linkset patch (by default the linkset's ETag as read). */
public final class MoveOptions {
    /** Default options (conditional on the linkset's ETag when it has one). */
    public static final MoveOptions DEFAULT = builder().build();

    private final String ifMatch;
    private final Map<String, List<String>> headers;
    private final Duration timeout;

    private MoveOptions(Builder b) {
        this.ifMatch = b.ifMatch;
        this.headers = RequestOptions.freeze(b.headers);
        this.timeout = b.timeout;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Only move if the linkset still has this ETag, in place of the one read. */
    public static MoveOptions ifMatch(String etag) {
        return builder().ifMatch(etag).build();
    }

    public Optional<String> ifMatchValue() {
        return Optional.ofNullable(ifMatch);
    }

    /** Extra headers of the linkset patch. */
    public Map<String, List<String>> headers() {
        return headers;
    }

    public Optional<Duration> timeout() {
        return Optional.ofNullable(timeout);
    }

    /** Builder for {@link MoveOptions}. */
    public static final class Builder {
        private String ifMatch;
        private final Map<String, List<String>> headers = new LinkedHashMap<>();
        private Duration timeout;

        private Builder() {}

        public Builder ifMatch(String etag) {
            this.ifMatch = etag;
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

        public MoveOptions build() {
            return new MoveOptions(this);
        }
    }
}
