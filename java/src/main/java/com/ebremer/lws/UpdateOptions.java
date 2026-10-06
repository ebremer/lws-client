// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.http.Link;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Options for updates (PUT) and patches (PATCH): optimistic concurrency and combined content + metadata
 * updates ({@code Prefer: set-linkset}).
 */
public final class UpdateOptions {
    /** Default options (unconditional). */
    public static final UpdateOptions DEFAULT = builder().build();

    private final String ifMatch;
    private final String ifNoneMatch;
    private final List<Link> links;
    private final boolean setLinkset;
    private final Map<String, List<String>> headers;
    private final Duration timeout;

    private UpdateOptions(Builder b) {
        this.ifMatch = b.ifMatch;
        this.ifNoneMatch = b.ifNoneMatch;
        this.links = List.copyOf(b.links);
        this.setLinkset = b.setLinkset;
        this.headers = RequestOptions.freeze(b.headers);
        this.timeout = b.timeout;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Only update if the resource still has this ETag (otherwise {@link PreconditionFailedException}). */
    public static UpdateOptions ifMatch(String etag) {
        return builder().ifMatch(etag).build();
    }

    public Optional<String> ifMatchValue() {
        return Optional.ofNullable(ifMatch);
    }

    public Optional<String> ifNoneMatchValue() {
        return Optional.ofNullable(ifNoneMatch);
    }

    public List<Link> links() {
        return links;
    }

    public boolean setLinkset() {
        return setLinkset;
    }

    public Map<String, List<String>> headers() {
        return headers;
    }

    public Optional<Duration> timeout() {
        return Optional.ofNullable(timeout);
    }

    /** Builder for {@link UpdateOptions}. */
    public static final class Builder {
        private String ifMatch;
        private String ifNoneMatch;
        private final List<Link> links = new ArrayList<>();
        private boolean setLinkset;
        private final Map<String, List<String>> headers = new LinkedHashMap<>();
        private Duration timeout;

        private Builder() {}

        public Builder ifMatch(String etag) {
            this.ifMatch = etag;
            return this;
        }

        /** {@code If-None-Match}; use {@code "*"} to only create-if-absent with PUT where supported. */
        public Builder ifNoneMatch(String etag) {
            this.ifNoneMatch = etag;
            return this;
        }

        /** A link to send with the request; applied to the linkset only with {@link #setLinkset(boolean)}. */
        public Builder link(Link link) {
            links.add(link);
            return this;
        }

        /**
         * Also replace (PUT) or update (PATCH) the resource linkset with the given links, atomically with the
         * content ({@code Prefer: set-linkset}). Servers without support ignore it or answer 501.
         */
        public Builder setLinkset(boolean setLinkset) {
            this.setLinkset = setLinkset;
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

        public UpdateOptions build() {
            return new UpdateOptions(this);
        }
    }
}
