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
 * Options for creating resources: an identity hint (sent as {@code Slug}), user-managed metadata links
 * and extra resource types (sent as {@code Link: <type>; rel="type"}).
 */
public final class CreateOptions {
    /** Default options. */
    public static final CreateOptions DEFAULT = builder().build();

    private final String slug;
    private final List<Link> links;
    private final List<String> types;
    private final Map<String, List<String>> headers;
    private final Duration timeout;

    private CreateOptions(Builder b) {
        this.slug = b.slug;
        this.links = List.copyOf(b.links);
        this.types = List.copyOf(b.types);
        this.headers = RequestOptions.freeze(b.headers);
        this.timeout = b.timeout;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Options with only an identity hint. */
    public static CreateOptions slug(String slug) {
        return builder().slug(slug).build();
    }

    public Optional<String> slugValue() {
        return Optional.ofNullable(slug);
    }

    public List<Link> links() {
        return links;
    }

    public List<String> types() {
        return types;
    }

    public Map<String, List<String>> headers() {
        return headers;
    }

    public Optional<Duration> timeout() {
        return Optional.ofNullable(timeout);
    }

    /** Builder for {@link CreateOptions}. */
    public static final class Builder {
        private String slug;
        private final List<Link> links = new ArrayList<>();
        private final List<String> types = new ArrayList<>();
        private final Map<String, List<String>> headers = new LinkedHashMap<>();
        private Duration timeout;

        private Builder() {}

        /** The identity hint for the new resource URI (the server may adapt or ignore it). */
        public Builder slug(String slug) {
            this.slug = slug;
            return this;
        }

        /** A user-managed metadata link for the new resource. */
        public Builder link(Link link) {
            links.add(link);
            return this;
        }

        /** An additional resource type (e.g. {@code https://schema.org/Person}). */
        public Builder type(String typeIri) {
            types.add(typeIri);
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

        public CreateOptions build() {
            return new CreateOptions(this);
        }
    }
}
