// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import com.ebremer.lws.auth.AuthRequest;
import com.ebremer.lws.auth.AuthResponse;
import com.ebremer.lws.auth.Authenticator;
import com.ebremer.lws.internal.Uris;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;

/**
 * Sends requests: applies default headers and the authenticator, retries once after a {@code 401} the
 * authenticator handled, and follows redirects itself so credentials are re-evaluated per target
 * (internal).
 */
final class Pipeline {
    private static final int MAX_REDIRECTS = 10;
    private static final Set<String> RESTRICTED = Set.of("connection", "content-length", "expect", "host", "upgrade");

    record Call(String method, URI uri, Body body, Map<String, List<String>> headers, Duration timeout) {}

    private final HttpClient http;
    private final Authenticator authenticator;
    private final String userAgent;
    private final Map<String, List<String>> defaultHeaders;
    private final Duration timeout;
    private final Executor executor;

    Pipeline(HttpClient http, Authenticator authenticator, String userAgent, Map<String, List<String>> defaultHeaders,
             Duration timeout, Executor executor) {
        this.http = http;
        this.authenticator = authenticator;
        this.userAgent = userAgent;
        this.defaultHeaders = defaultHeaders;
        this.timeout = timeout;
        this.executor = executor;
    }

    HttpClient http() {
        return http;
    }

    Authenticator authenticator() {
        return authenticator;
    }

    /** One request attempt's mutable state. */
    private static final class Attempt implements AuthRequest {
        final String method;
        final URI uri;
        final Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        Attempt(String method, URI uri) {
            this.method = method;
            this.uri = uri;
        }

        @Override
        public String method() {
            return method;
        }

        @Override
        public URI uri() {
            return uri;
        }

        @Override
        public Optional<String> header(String name) {
            List<String> v = headers.get(name);
            return v == null || v.isEmpty() ? Optional.empty() : Optional.of(v.get(0));
        }

        @Override
        public void setHeader(String name, String value) {
            List<String> l = new ArrayList<>();
            l.add(value);
            headers.put(name, l);
        }

        @Override
        public void removeHeader(String name) {
            headers.remove(name);
        }
    }

    private Attempt prepare(String method, URI uri, Map<String, List<String>> callHeaders) {
        Attempt a = new Attempt(method, uri);
        defaultHeaders.forEach((k, v) -> a.headers.put(k, new ArrayList<>(v)));
        callHeaders.forEach((k, v) -> a.headers.put(k, new ArrayList<>(v)));
        if (!a.headers.containsKey("User-Agent") && userAgent != null) a.setHeader("User-Agent", userAgent);
        if (authenticator != null) authenticator.authorize(a);
        return a;
    }

    private HttpRequest build(Attempt a, Body body, Duration callTimeout) {
        HttpRequest.Builder b = HttpRequest.newBuilder(a.uri).method(a.method, body.publisher());
        Duration t = callTimeout != null ? callTimeout : timeout;
        if (t != null) b.timeout(t);
        a.headers.forEach((name, values) -> {
            if (RESTRICTED.contains(name.toLowerCase(Locale.ROOT))) return;
            for (String v : values) b.header(name, v);
        });
        return b.build();
    }

    <T> HttpResponse<T> send(Call call, BodyHandler<T> handler) {
        String method = call.method();
        URI uri = call.uri();
        Body body = call.body() == null ? Body.empty() : call.body();
        boolean authRetried = false;
        int redirects = 0;
        while (true) {
            Attempt a = prepare(method, uri, call.headers());
            HttpRequest req = build(a, body, call.timeout());
            HttpResponse<T> resp;
            try {
                resp = http.send(req, handler);
            } catch (IOException e) {
                throw new LwsTransportException(method + " " + uri + " failed: " + e.getMessage(), e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new LwsTransportException(method + " " + uri + " interrupted", e);
            }
            int status = resp.statusCode();
            if (status == 401 && authenticator != null && !authRetried) {
                authRetried = true;
                boolean retry;
                try {
                    retry = authenticator.handleChallenge(a, new AuthResponse(uri, status, resp.headers()));
                } catch (RuntimeException e) {
                    discard(resp);
                    throw e;
                }
                if (retry) {
                    discard(resp);
                    continue;
                }
                return resp;
            }
            Optional<Redirect> r = redirect(method, uri, body, resp, redirects);
            if (r.isPresent()) {
                discard(resp);
                redirects++;
                method = r.get().method();
                uri = r.get().uri();
                body = r.get().body();
                continue;
            }
            return resp;
        }
    }

    <T> CompletableFuture<HttpResponse<T>> sendAsync(Call call, BodyHandler<T> handler) {
        Body body = call.body() == null ? Body.empty() : call.body();
        return attemptAsync(call, call.method(), call.uri(), body, handler, false, 0);
    }

    private <T> CompletableFuture<HttpResponse<T>> attemptAsync(Call call, String method, URI uri, Body body,
                                                                 BodyHandler<T> handler, boolean authRetried, int redirects) {
        Attempt a;
        HttpRequest req;
        try {
            a = prepare(method, uri, call.headers());
            req = build(a, body, call.timeout());
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
        return http.sendAsync(req, handler)
                .handle((resp, ex) -> {
                    if (ex != null) {
                        Throwable c = ex instanceof CompletionException && ex.getCause() != null ? ex.getCause() : ex;
                        if (c instanceof LwsException le) throw le;
                        throw new LwsTransportException(method + " " + uri + " failed: " + c.getMessage(), c);
                    }
                    return resp;
                })
                .thenCompose(resp -> {
                    int status = resp.statusCode();
                    if (status == 401 && authenticator != null && !authRetried) {
                        return CompletableFuture
                                .supplyAsync(() -> authenticator.handleChallenge(a, new AuthResponse(uri, status, resp.headers())), executor)
                                .thenCompose(retry -> {
                                    if (!retry) return CompletableFuture.completedFuture(resp);
                                    discard(resp);
                                    return attemptAsync(call, method, uri, body, handler, true, redirects);
                                });
                    }
                    Optional<Redirect> r = redirect(method, uri, body, resp, redirects);
                    if (r.isPresent()) {
                        discard(resp);
                        return attemptAsync(call, r.get().method(), r.get().uri(), r.get().body(), handler, authRetried, redirects + 1);
                    }
                    return CompletableFuture.completedFuture(resp);
                });
    }

    private record Redirect(String method, URI uri, Body body) {}

    private static Optional<Redirect> redirect(String method, URI uri, Body body, HttpResponse<?> resp, int redirects) {
        int s = resp.statusCode();
        if (redirects >= MAX_REDIRECTS || !(s == 301 || s == 302 || s == 303 || s == 307 || s == 308)) return Optional.empty();
        Optional<String> loc = resp.headers().firstValue("location");
        if (loc.isEmpty()) return Optional.empty();
        URI target = Uris.resolveOrNull(uri, loc.get());
        if (target == null) return Optional.empty();
        boolean safe = method.equals("GET") || method.equals("HEAD") || method.equals("OPTIONS");
        if (s == 303) {
            return Optional.of(new Redirect(method.equals("HEAD") ? "HEAD" : "GET", target, Body.empty()));
        }
        if (safe || s == 307 || s == 308) return Optional.of(new Redirect(method, target, body));
        return Optional.empty();
    }

    private static void discard(HttpResponse<?> resp) {
        if (resp.body() instanceof InputStream in) {
            try {
                in.close();
            } catch (IOException ignored) {
                // nothing to do
            }
        }
    }
}
