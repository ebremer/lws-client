// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Per-call options shared by all operations: extra request headers and a timeout. */
public final class RequestOptions {
    /** No extra headers, client default timeout. */
    public static final RequestOptions DEFAULT = builder().build();

    private final Map<String, List<String>> headers;
    private final Duration timeout;

    private RequestOptions(Builder b) {
        this.headers = freeze(b.headers);
        this.timeout = b.timeout;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Options with one extra header. */
    public static RequestOptions header(String name, String value) {
        return builder().header(name, value).build();
    }

    /** Extra request headers. */
    public Map<String, List<String>> headers() {
        return headers;
    }

    /** Timeout overriding the client default. */
    public Optional<Duration> timeout() {
        return Optional.ofNullable(timeout);
    }

    static Map<String, List<String>> freeze(Map<String, List<String>> h) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        h.forEach((k, v) -> out.put(k, List.copyOf(v)));
        return Collections.unmodifiableMap(out);
    }

    static void addHeader(Map<String, List<String>> headers, String name, String value) {
        headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
    }

    /** Builder for {@link RequestOptions}. */
    public static final class Builder {
        private final Map<String, List<String>> headers = new LinkedHashMap<>();
        private Duration timeout;

        private Builder() {}

        /** Adds a request header. */
        public Builder header(String name, String value) {
            addHeader(headers, name, value);
            return this;
        }

        /** Sets the request timeout. */
        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        public RequestOptions build() {
            return new RequestOptions(this);
        }
    }
}
