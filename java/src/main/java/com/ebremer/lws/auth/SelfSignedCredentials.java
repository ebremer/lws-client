// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import com.ebremer.lws.Lws;
import com.ebremer.lws.internal.Json;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Self-signed identity authentication suite ({@code lws10-authn-ssi-cid}, including {@code did:key}
 * subjects): the agent signs its own JWT credential
 * ({@code urn:ietf:params:oauth:token-type:jwt}) with {@code sub = iss = client_id = agent},
 * {@code aud = [authorization server]}, {@code iat}, {@code exp} and a random {@code jti}.
 *
 * <pre>{@code
 * KeyPair keys = KeyPairs.generateP256();
 * SelfSignedCredentials creds = SelfSignedCredentials.didKey(keys);   // agent = did:key:zDn…
 * }</pre>
 *
 * <p>Supports ES256 (P-256), ES384, and EdDSA (Ed25519). Tokens are cached per audience until 60 seconds
 * before they expire.
 */
public final class SelfSignedCredentials implements CredentialProvider {
    private static final Duration REUSE_MARGIN = Duration.ofSeconds(60);

    private final URI agent;
    private final PrivateKey key;
    private final String kid;
    private final String alg;
    private final Duration lifetime;
    private final Clock clock;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    private record Cached(String token, Instant expires) {}

    private SelfSignedCredentials(URI agent, PrivateKey key, String kid, Duration lifetime, Clock clock) {
        this.agent = Objects.requireNonNull(agent, "agent");
        this.key = Objects.requireNonNull(key, "key");
        this.kid = kid;
        this.alg = Jwt.algorithm(key);
        this.lifetime = Objects.requireNonNull(lifetime, "lifetime");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Credentials for an agent whose controlled identifier document (at {@code agent}) lists the key under
     * {@code authentication}; {@code kid} identifies that verification method.
     */
    public static SelfSignedCredentials forAgent(URI agent, PrivateKey key, String kid) {
        return new SelfSignedCredentials(agent, key, kid, Duration.ofSeconds(300), Clock.systemUTC());
    }

    /** Credentials for a {@code did:key} agent derived from the key pair (P-256 or Ed25519). */
    public static SelfSignedCredentials didKey(KeyPair keyPair) {
        URI did = URI.create(DidKey.fromPublicKey(keyPair.getPublic()));
        return new SelfSignedCredentials(did, keyPair.getPrivate(), DidKey.keyId(keyPair.getPublic()),
                Duration.ofSeconds(300), Clock.systemUTC());
    }

    /** Returns a copy whose tokens live for {@code lifetime} (default 300 seconds). */
    public SelfSignedCredentials withLifetime(Duration lifetime) {
        return new SelfSignedCredentials(agent, key, kid, lifetime, clock);
    }

    /** Returns a copy using {@code clock} (for tests). */
    public SelfSignedCredentials withClock(Clock clock) {
        return new SelfSignedCredentials(agent, key, kid, lifetime, clock);
    }

    /** The agent identifier ({@code sub}, {@code iss} and {@code client_id}). */
    public URI agent() {
        return agent;
    }

    /** The key id placed in the JWT header, or null. */
    public String keyId() {
        return kid;
    }

    /** The JOSE algorithm ({@code ES256}, {@code EdDSA}, …). */
    public String algorithm() {
        return alg;
    }

    @Override
    public String tokenType() {
        return Lws.TokenType.JWT;
    }

    @Override
    public String subjectToken(CredentialContext context) {
        String aud = context.issuer().toString();
        Instant now = clock.instant();
        Cached c = cache.get(aud);
        if (c != null && now.plus(REUSE_MARGIN).isBefore(c.expires())) return c.token();
        String token = createToken(aud);
        cache.put(aud, new Cached(token, now.plus(lifetime)));
        return token;
    }

    /** Creates and signs a new credential for {@code audience}. */
    public String createToken(String audience) {
        long now = clock.instant().getEpochSecond();
        ObjectNode header = Json.object();
        header.put("alg", alg);
        header.put("typ", "JWT");
        if (kid != null) header.put("kid", kid);
        ObjectNode claims = Json.object();
        String id = agent.toString();
        claims.put("sub", id);
        claims.put("iss", id);
        claims.put("client_id", id);
        claims.putArray("aud").add(audience);
        claims.put("iat", now);
        claims.put("exp", now + lifetime.getSeconds());
        claims.put("jti", UUID.randomUUID().toString());
        return Jwt.sign(header, claims, key);
    }
}
