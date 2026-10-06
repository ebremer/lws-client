// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import com.ebremer.lws.AuthenticationException;
import com.ebremer.lws.Lws;
import com.ebremer.lws.LwsException;
import com.ebremer.lws.LwsTransportException;
import com.ebremer.lws.http.AuthChallenge;
import com.ebremer.lws.internal.HeaderLists;
import com.ebremer.lws.internal.Json;
import com.ebremer.lws.internal.Uris;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiPredicate;

/**
 * The LWS authorization flow (OAuth 2.0 token exchange, RFC 8693):
 *
 * <ol>
 *   <li>a request is answered {@code 401} with {@code WWW-Authenticate: Bearer as_uri="…", realm="…"};</li>
 *   <li>the request URI must lie inside the realm, and the authorization server must use HTTPS
 *       (loopback hosts excepted) and pass the optional filter;</li>
 *   <li>the authorization server metadata is read from {@code /.well-known/lws-configuration} and its
 *       {@code issuer} checked;</li>
 *   <li>the {@link CredentialProvider}'s subject token is exchanged for an access token with
 *       {@code resource = realm};</li>
 *   <li>the request is retried once with the token, and the token is reused (until 30 seconds before it
 *       expires) for every URL inside the realm.</li>
 * </ol>
 *
 * Instances are thread-safe; concurrent requests share a single in-flight exchange per realm.
 */
public final class TokenExchangeAuthenticator implements Authenticator {
    private final CredentialProvider credentials;
    private final HttpClient http;
    private final boolean allowInsecureHttp;
    private final BiPredicate<URI, URI> filter;
    private final Clock clock;
    private final Duration refreshSkew;
    private final Duration timeout;
    private final String userAgent;

    private final Map<String, Entry> tokens = new ConcurrentHashMap<>();
    private final Map<String, CompletableFuture<Entry>> inflight = new ConcurrentHashMap<>();
    private final Map<String, AuthorizationServerMetadata> metadata = new ConcurrentHashMap<>();

    private record Entry(URI issuer, URI realm, AccessToken token) {}

    private TokenExchangeAuthenticator(Builder b) {
        this.credentials = Objects.requireNonNull(b.credentials, "credentials");
        this.http = b.http != null ? b.http
                : HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(30)).build();
        this.allowInsecureHttp = b.allowInsecureHttp;
        this.filter = b.filter;
        this.clock = b.clock;
        this.refreshSkew = b.refreshSkew;
        this.timeout = b.timeout;
        this.userAgent = b.userAgent;
    }

    /** An authenticator with default settings. */
    public static TokenExchangeAuthenticator of(CredentialProvider credentials) {
        return builder(credentials).build();
    }

    /** A builder for an authenticator using {@code credentials}. */
    public static Builder builder(CredentialProvider credentials) {
        return new Builder(credentials);
    }

    /** The credential provider. */
    public CredentialProvider credentials() {
        return credentials;
    }

    @Override
    public void authorize(AuthRequest request) {
        Entry best = null;
        Instant now = clock.instant();
        for (Entry e : tokens.values()) {
            if (!e.token().isValid(now, refreshSkew) || !Uris.contains(e.realm(), request.uri())) continue;
            if (best == null || pathLength(e.realm()) > pathLength(best.realm())) best = e;
        }
        if (best != null) request.setHeader("Authorization", "Bearer " + best.token().value());
    }

    @Override
    public boolean handleChallenge(AuthRequest request, AuthResponse response) {
        AuthChallenge challenge = null;
        for (AuthChallenge c : response.challenges()) {
            if (c.isScheme("Bearer") && c.asUri().isPresent() && c.realm().isPresent()) {
                challenge = c;
                break;
            }
        }
        if (challenge == null) return false;
        URI asUri = challenge.asUri().get();
        URI realm = challenge.realm().get();
        if (!Uris.contains(realm, request.uri())) {
            throw new AuthenticationException("Request URI " + request.uri() + " is not within the challenge realm " + realm);
        }
        requireSecure(asUri, "authorization server");
        if (filter != null && !filter.test(asUri, realm)) {
            throw new AuthenticationException("Authorization server " + asUri + " rejected by the authorization server filter");
        }
        String key = key(asUri, realm);
        Entry cached = tokens.get(key);
        String sent = request.header("Authorization").orElse(null);
        if (cached != null) {
            boolean usedCached = ("Bearer " + cached.token().value()).equals(sent);
            if (!usedCached && cached.token().isValid(clock.instant(), refreshSkew)) {
                return true; // obtained concurrently; retry with it
            }
            tokens.remove(key, cached);
        }
        obtain(asUri, realm);
        return true;
    }

    /** Returns a valid access token for the realm, performing the token exchange when needed. */
    public AccessToken accessToken(URI asUri, URI realm) {
        Entry e = tokens.get(key(asUri, realm));
        if (e != null && e.token().isValid(clock.instant(), refreshSkew)) return e.token();
        requireSecure(asUri, "authorization server");
        return obtain(asUri, realm).token();
    }

    /** Forgets all cached tokens and metadata. */
    public void clear() {
        tokens.clear();
        metadata.clear();
    }

    private Entry obtain(URI asUri, URI realm) {
        String key = key(asUri, realm);
        CompletableFuture<Entry> mine = new CompletableFuture<>();
        CompletableFuture<Entry> existing = inflight.putIfAbsent(key, mine);
        if (existing != null) {
            try {
                return existing.join();
            } catch (CompletionException e) {
                if (e.getCause() instanceof RuntimeException re) throw re;
                throw e;
            }
        }
        try {
            AccessToken token = exchange(asUri, realm);
            Entry entry = new Entry(asUri, realm, token);
            tokens.put(key, entry);
            mine.complete(entry);
            return entry;
        } catch (RuntimeException e) {
            mine.completeExceptionally(e);
            throw e;
        } finally {
            inflight.remove(key, mine);
        }
    }

    private AccessToken exchange(URI asUri, URI realm) {
        AuthorizationServerMetadata md = metadata(asUri);
        requireSecure(md.tokenEndpoint(), "token endpoint");
        if (!md.supportsSubjectTokenType(credentials.tokenType())) {
            throw new AuthenticationException("Authorization server " + asUri + " does not accept subject tokens of type "
                    + credentials.tokenType() + " (supported: " + md.subjectTokenTypesSupported() + ")");
        }
        String subjectToken = credentials.subjectToken(new CredentialContext(asUri, realm, md));
        String form = "grant_type=" + enc(Lws.GRANT_TYPE_TOKEN_EXCHANGE)
                + "&resource=" + enc(realm.toString())
                + "&subject_token=" + enc(subjectToken)
                + "&subject_token_type=" + enc(credentials.tokenType());
        HttpRequest.Builder rb = HttpRequest.newBuilder(md.tokenEndpoint())
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .header("Content-Type", Lws.MediaType.FORM)
                .header("Accept", Lws.MediaType.JSON);
        decorate(rb);
        HttpResponse<byte[]> resp = send(rb.build());
        JsonNode body = null;
        if (resp.body() != null && resp.body().length > 0) {
            try {
                body = Json.MAPPER.readTree(resp.body());
            } catch (IOException e) {
                body = null;
            }
        }
        if (resp.statusCode() / 100 != 2) {
            String error = body == null ? null : Json.text(body, "error");
            String desc = body == null ? null : Json.text(body, "error_description");
            throw new AuthenticationException("Token exchange at " + md.tokenEndpoint() + " failed with HTTP " + resp.statusCode()
                    + (error != null ? ": " + error : "") + (desc != null ? " (" + desc + ")" : ""), error, desc, null);
        }
        if (body == null || !body.isObject()) throw new AuthenticationException("Token endpoint returned no JSON object");
        return AccessToken.fromTokenResponse(body, clock.instant());
    }

    private AuthorizationServerMetadata metadata(URI asUri) {
        String k = asUri.toString();
        AuthorizationServerMetadata md = metadata.get(k);
        if (md != null) return md;
        URI url = AuthorizationServerMetadata.metadataUrl(asUri);
        HttpRequest.Builder rb = HttpRequest.newBuilder(url).GET().header("Accept", Lws.MediaType.JSON);
        decorate(rb);
        HttpResponse<byte[]> resp = send(rb.build());
        if (resp.statusCode() != 200) {
            throw new AuthenticationException("Cannot read authorization server metadata " + url + ": HTTP " + resp.statusCode());
        }
        if (!HeaderLists.isJson(resp.headers().firstValue("content-type").orElse("application/json"))) {
            throw new AuthenticationException("Authorization server metadata " + url + " is not JSON");
        }
        try {
            md = AuthorizationServerMetadata.parse(Json.parse(resp.body()), url);
        } catch (LwsException e) {
            throw new AuthenticationException("Invalid authorization server metadata at " + url + ": " + e.getMessage(), e);
        }
        if (!Uris.equalsIgnoringTrailingSlash(md.issuer(), asUri.toString())) {
            throw new AuthenticationException("Authorization server metadata issuer " + md.issuer() + " does not match as_uri " + asUri);
        }
        metadata.put(k, md);
        return md;
    }

    private HttpResponse<byte[]> send(HttpRequest request) {
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new LwsTransportException(request.method() + " " + request.uri() + " failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LwsTransportException(request.method() + " " + request.uri() + " interrupted", e);
        }
    }

    private void decorate(HttpRequest.Builder rb) {
        if (timeout != null) rb.timeout(timeout);
        if (userAgent != null) rb.header("User-Agent", userAgent);
    }

    private void requireSecure(URI uri, String what) {
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (scheme.equals("https")) return;
        if (scheme.equals("http") && (allowInsecureHttp || Uris.isLoopback(uri))) return;
        throw new AuthenticationException("Refusing to use insecure " + what + " " + uri + " (HTTPS required)");
    }

    private static String key(URI asUri, URI realm) {
        return asUri + " " + realm;
    }

    private static int pathLength(URI u) {
        return Optional.ofNullable(u.getRawPath()).map(String::length).orElse(0);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /** Builder for {@link TokenExchangeAuthenticator}. */
    public static final class Builder {
        private final CredentialProvider credentials;
        private HttpClient http;
        private boolean allowInsecureHttp;
        private BiPredicate<URI, URI> filter;
        private Clock clock = Clock.systemUTC();
        private Duration refreshSkew = Duration.ofSeconds(30);
        private Duration timeout = Duration.ofSeconds(30);
        private String userAgent = "lws-client-java/0.1.0";

        private Builder(CredentialProvider credentials) {
            this.credentials = Objects.requireNonNull(credentials, "credentials");
        }

        /** The HTTP client for metadata and token requests. */
        public Builder httpClient(HttpClient http) {
            this.http = http;
            return this;
        }

        /** Allow plain-HTTP authorization servers beyond loopback hosts (testing only). */
        public Builder allowInsecureHttp(boolean allow) {
            this.allowInsecureHttp = allow;
            return this;
        }

        /**
         * Decides whether to trust an authorization server ({@code as_uri}) for a realm before any credential
         * is sent to it. Defaults to trusting every server that passes the realm and HTTPS checks.
         */
        public Builder authorizationServerFilter(BiPredicate<URI, URI> filter) {
            this.filter = filter;
            return this;
        }

        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock);
            return this;
        }

        /** Refresh tokens this long before they expire (default 30 seconds). */
        public Builder refreshSkew(Duration skew) {
            this.refreshSkew = Objects.requireNonNull(skew);
            return this;
        }

        /** Timeout of metadata and token requests (default 30 seconds). */
        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        public Builder userAgent(String userAgent) {
            this.userAgent = userAgent;
            return this;
        }

        public TokenExchangeAuthenticator build() {
            return new TokenExchangeAuthenticator(this);
        }
    }
}
