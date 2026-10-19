// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import com.ebremer.lws.AuthenticationException;
import com.ebremer.lws.Lws;
import com.ebremer.lws.LwsException;
import com.ebremer.lws.LwsTransportException;
import com.ebremer.lws.StorageDescription;
import com.ebremer.lws.http.AuthChallenge;
import com.ebremer.lws.http.Link;
import com.ebremer.lws.http.LinkHeader;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiPredicate;

/**
 * The LWS authorization flow (OAuth 2.0 protected resource metadata, RFC 9728, and token exchange, RFC 8693):
 *
 * <ol>
 *   <li>a request is answered {@code 401} with {@code WWW-Authenticate: Bearer resource_metadata="…"} and a
 *       {@code Link} to the storage that holds the resource;</li>
 *   <li>what the {@code 401} told is checked against the request URL (lws10-core "Discovery Validation by a
 *       Client"): the protected resource metadata is on the requested origin and describes the requested URL,
 *       and the root of the linked storage, read from its description, is on the requested origin;</li>
 *   <li>the first authorization server of the metadata that uses HTTPS (loopback hosts excepted) and passes the
 *       optional filter is the issuer; its metadata is read from {@code /.well-known/lws-configuration} and its
 *       {@code issuer} checked;</li>
 *   <li>the {@link CredentialProvider}'s subject token is exchanged for an access token with
 *       {@code resource = storage};</li>
 *   <li>the request is retried once with the token, and the token is sent ahead (until 30 seconds before it
 *       expires) to every URL inside the storage or its root.</li>
 * </ol>
 *
 * <p>The challenge of the drafts before 19 October 2026, {@code Bearer as_uri="…", realm="…"}, is still followed
 * when no {@code Bearer} challenge has {@code resource_metadata}: the request URL must lie inside the realm,
 * {@code as_uri} is the issuer, and the realm is both the token's storage and its only scope.
 *
 * <p>A challenge that fails a check is not acted on at all: no token is asked for what it named, and a cached
 * token the request carried is kept (a storage can hold a resource whose {@code 401} links to another storage).
 * Metadata, storage description and token requests never follow a redirect.
 *
 * Instances are thread-safe; concurrent requests share a single in-flight exchange per issuer and storage.
 */
public final class TokenExchangeAuthenticator implements Authenticator {
    /** The {@code Accept} of a storage description request, as {@code LwsClient#getStorageDescription} sends it. */
    private static final String ACCEPT_DESCRIPTION = Lws.MediaType.LWS_CID + ", " + Lws.MediaType.LD_JSON + ";q=0.9, "
            + Lws.MediaType.JSON + ";q=0.8";

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
    private final Map<String, StorageDescription> descriptions = new ConcurrentHashMap<>();

    /** Where a challenge leads: the issuer, the storage the token is for, and the scopes it is sent ahead to. */
    private record Target(URI issuer, URI storage, List<URI> scopes) {}

    /** A cached token, keyed by issuer and storage. */
    private record Entry(URI issuer, URI storage, List<URI> scopes, AccessToken token) {
        Entry withScopes(List<URI> more) {
            List<URI> all = new ArrayList<>(scopes);
            for (URI s : more) {
                if (!all.contains(s)) all.add(s);
            }
            return all.size() == scopes.size() ? this : new Entry(issuer, storage, List.copyOf(all), token);
        }
    }

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
        int bestLength = -1;
        Instant now = clock.instant();
        for (Entry e : tokens.values()) {
            if (!e.token().isValid(now, refreshSkew)) continue;
            for (URI scope : e.scopes()) {
                if (Uris.contains(scope, request.uri()) && pathLength(scope) > bestLength) {
                    best = e;
                    bestLength = pathLength(scope);
                }
            }
        }
        if (best != null) request.setHeader("Authorization", "Bearer " + best.token().value());
    }

    /**
     * Runs the flow for a {@code 401}. The retry carries the token even when the request URL lies outside its
     * scope, as that URL has just passed the checks; later requests there get no token up front, and their
     * {@code 401} reuses the cached token.
     */
    @Override
    public boolean handleChallenge(AuthRequest request, AuthResponse response) {
        Target target = discover(request.uri(), response);
        if (target == null) return false;
        String key = key(target.issuer(), target.storage());
        Entry cached = tokens.get(key);
        String sent = request.header("Authorization").orElse(null);
        AccessToken token = null;
        if (cached != null) {
            boolean usedCached = ("Bearer " + cached.token().value()).equals(sent);
            if (!usedCached && cached.token().isValid(clock.instant(), refreshSkew)) {
                tokens.replace(key, cached, cached.withScopes(target.scopes()));
                token = cached.token(); // obtained concurrently, or the URL lies outside its scope
            } else {
                tokens.remove(key, cached);
            }
        }
        if (token == null) token = obtain(target).token();
        request.setHeader("Authorization", "Bearer " + token.value());
        return true;
    }

    /**
     * Returns a valid access token for a storage from an authorization server, performing the token exchange
     * when needed. No discovery check is made: the caller vouches for both. A token obtained here is sent ahead
     * to URLs inside the storage.
     */
    public AccessToken accessToken(URI issuer, URI storage) {
        Entry e = tokens.get(key(issuer, storage));
        if (e != null && e.token().isValid(clock.instant(), refreshSkew)) return e.token();
        requireSecure(issuer, "authorization server");
        return obtain(new Target(issuer, storage, List.of(storage))).token();
    }

    /** Forgets all cached tokens, authorization server metadata and storage descriptions. */
    public void clear() {
        tokens.clear();
        metadata.clear();
        descriptions.clear();
    }

    /**
     * Picks the challenge to follow and checks what the {@code 401} told against the request URL, up to the
     * authorization server's metadata. Returns null when no challenge is one this flow follows: the {@code 401}
     * is then the caller's.
     */
    private Target discover(URI url, AuthResponse response) {
        List<AuthChallenge> challenges = response.challenges();
        for (AuthChallenge c : challenges) {
            if (c.isScheme("Bearer") && c.param("resource_metadata").isPresent()) return discover(url, c, response);
        }
        for (AuthChallenge c : challenges) {
            if (c.isScheme("Bearer") && c.asUri().isPresent() && c.realm().isPresent()) return legacy(url, c);
        }
        return null;
    }

    /** The flow of lws10-core: protected resource metadata, the storage's description, and the three checks. */
    private Target discover(URI url, AuthChallenge challenge, AuthResponse response) {
        String named = challenge.param("resource_metadata").orElseThrow();
        URI metadataUrl = Uris.resolveOrNull(url, named);
        if (metadataUrl == null || !Uris.sameOrigin(metadataUrl, url)) {
            throw new AuthenticationException("Protected resource metadata " + named + " is not on the origin of " + url);
        }
        URI storage = LinkHeader.first(LinkHeader.parse(response.headers().allValues("link"), url), Lws.Rel.STORAGE)
                .map(Link::href)
                .orElseThrow(() -> new AuthenticationException("The 401 for " + url + " links to no storage (rel=\""
                        + Lws.Rel.STORAGE + "\")"));
        ProtectedResourceMetadata prm = protectedResourceMetadata(metadataUrl);
        if (!prm.describes(url)) {
            throw new AuthenticationException("Protected resource metadata " + metadataUrl + " describes " + prm.resource()
                    + ", not " + url);
        }
        URI root = storageRoot(storage);
        if (!Uris.sameOrigin(root, url)) {
            throw new AuthenticationException("The root " + root + " of storage " + storage + " is not on the origin of " + url);
        }
        for (String s : prm.authorizationServers()) {
            URI issuer = Uris.resolveOrNull(null, s);
            if (issuer != null && isSecure(issuer) && (filter == null || filter.test(issuer, storage))) {
                metadata(issuer);
                return new Target(issuer, storage, List.of(storage, root));
            }
        }
        throw new AuthenticationException("No authorization server of " + metadataUrl + " uses HTTPS and passes the filter: "
                + prm.authorizationServers());
    }

    /** The challenge of the drafts before 19 October 2026: {@code as_uri} and a {@code realm} containing the URL. */
    private Target legacy(URI url, AuthChallenge challenge) {
        URI issuer = challenge.asUri().orElseThrow();
        URI realm = challenge.realm().orElseThrow();
        if (!Uris.contains(realm, url)) {
            throw new AuthenticationException("Request URI " + url + " is not within the challenge realm " + realm);
        }
        requireSecure(issuer, "authorization server");
        if (filter != null && !filter.test(issuer, realm)) {
            throw new AuthenticationException("Authorization server " + issuer + " rejected by the authorization server filter");
        }
        metadata(issuer);
        return new Target(issuer, realm, List.of(realm));
    }

    private Entry obtain(Target target) {
        String key = key(target.issuer(), target.storage());
        CompletableFuture<Entry> mine = new CompletableFuture<>();
        CompletableFuture<Entry> existing = inflight.putIfAbsent(key, mine);
        if (existing != null) {
            Entry e;
            try {
                e = existing.join();
            } catch (CompletionException ex) {
                if (ex.getCause() instanceof RuntimeException re) throw re;
                throw ex;
            }
            tokens.computeIfPresent(key, (k, v) -> v.withScopes(target.scopes()));
            return e;
        }
        try {
            AccessToken token = exchange(target.issuer(), target.storage());
            Entry entry = new Entry(target.issuer(), target.storage(), target.scopes(), token);
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

    private AccessToken exchange(URI issuer, URI storage) {
        AuthorizationServerMetadata md = metadata(issuer);
        requireSecure(md.tokenEndpoint(), "token endpoint");
        if (!md.supportsSubjectTokenType(credentials.tokenType())) {
            throw new AuthenticationException("Authorization server " + issuer + " does not accept subject tokens of type "
                    + credentials.tokenType() + " (supported: " + md.subjectTokenTypesSupported() + ")");
        }
        String subjectToken = credentials.subjectToken(new CredentialContext(issuer, storage, md));
        String form = "grant_type=" + enc(Lws.GRANT_TYPE_TOKEN_EXCHANGE)
                + "&resource=" + enc(storage.toString())
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

    /** The protected resource metadata at {@code url} (not cached: it describes one resource). */
    private ProtectedResourceMetadata protectedResourceMetadata(URI url) {
        HttpResponse<byte[]> resp = get(url, Lws.MediaType.JSON);
        if (resp.statusCode() != 200) {
            throw new AuthenticationException("Cannot read protected resource metadata " + url + ": HTTP " + resp.statusCode());
        }
        if (!HeaderLists.isJson(resp.headers().firstValue("content-type").orElse("application/json"))) {
            throw new AuthenticationException("Protected resource metadata " + url + " is not JSON");
        }
        try {
            return ProtectedResourceMetadata.parse(Json.parse(resp.body()));
        } catch (LwsException e) {
            throw new AuthenticationException("Invalid protected resource metadata at " + url + ": " + e.getMessage(), e);
        }
    }

    /** The root of a storage, from its description; descriptions are cached per storage URL until {@link #clear()}. */
    private URI storageRoot(URI storage) {
        String k = storage.toString();
        StorageDescription sd = descriptions.get(k);
        if (sd == null) {
            HttpResponse<byte[]> resp = get(storage, ACCEPT_DESCRIPTION);
            if (resp.statusCode() != 200) {
                throw new AuthenticationException("Cannot read the description of storage " + storage + ": HTTP " + resp.statusCode());
            }
            String ct = resp.headers().firstValue("content-type").orElse(null);
            if (ct != null && !HeaderLists.isJson(ct) && !Lws.MediaType.LWS_CID.equals(HeaderLists.essence(ct))) {
                throw new AuthenticationException("Storage description " + storage + " has unexpected media type " + ct);
            }
            try {
                sd = StorageDescription.parse(Json.parse(resp.body()), storage);
            } catch (LwsException e) {
                throw new AuthenticationException("Invalid storage description at " + storage + ": " + e.getMessage(), e);
            }
            descriptions.put(k, sd);
        }
        try {
            return sd.storageRoot();
        } catch (LwsException e) {
            throw new AuthenticationException(e.getMessage(), e);
        }
    }

    private AuthorizationServerMetadata metadata(URI issuer) {
        String k = issuer.toString();
        AuthorizationServerMetadata md = metadata.get(k);
        if (md != null) return md;
        URI url = AuthorizationServerMetadata.metadataUrl(issuer);
        HttpResponse<byte[]> resp = get(url, Lws.MediaType.JSON);
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
        if (!Uris.equalsIgnoringTrailingSlash(md.issuer(), issuer.toString())) {
            throw new AuthenticationException("Authorization server metadata issuer " + md.issuer() + " does not match " + issuer);
        }
        metadata.put(k, md);
        return md;
    }

    /** A {@code GET} without credentials (the client must not follow redirects). */
    private HttpResponse<byte[]> get(URI url, String accept) {
        HttpRequest.Builder rb = HttpRequest.newBuilder(url).GET().header("Accept", accept);
        decorate(rb);
        return send(rb.build());
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

    /** Whether a subject token may be sent to {@code uri}: HTTPS, or HTTP to a loopback host or when allowed. */
    private boolean isSecure(URI uri) {
        if (uri.getHost() == null) return false;
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (scheme.equals("https")) return true;
        return scheme.equals("http") && (allowInsecureHttp || Uris.isLoopback(uri));
    }

    private void requireSecure(URI uri, String what) {
        if (!isSecure(uri)) throw new AuthenticationException("Refusing to use insecure " + what + " " + uri + " (HTTPS required)");
    }

    private static String key(URI issuer, URI storage) {
        return issuer + " " + storage;
    }

    /** The length of a scope's path as a directory (with its trailing {@code /}). */
    private static int pathLength(URI scope) {
        String p = Optional.ofNullable(scope.getRawPath()).orElse("");
        return p.endsWith("/") ? p.length() : p.length() + 1;
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

        /**
         * The HTTP client for protected resource metadata, storage description, authorization server metadata and
         * token requests. It must not follow redirects.
         */
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
         * Decides whether to trust an authorization server (an issuer the protected resource metadata names, or
         * the {@code as_uri} of a challenge of the drafts before 19 October 2026) for a storage, given as
         * {@code (issuer, storage)}, before any credential is sent to it. Defaults to trusting every server that
         * passes the discovery and HTTPS checks.
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
