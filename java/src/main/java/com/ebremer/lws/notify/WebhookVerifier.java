// SPDX-License-Identifier: MIT
package com.ebremer.lws.notify;

import com.ebremer.lws.LwsClient;
import com.ebremer.lws.LwsException;
import com.ebremer.lws.SignatureVerificationException;
import com.ebremer.lws.StorageDescription;
import com.ebremer.lws.StorageDescription.VerificationMethod;
import com.ebremer.lws.auth.Jwk;
import com.ebremer.lws.http.StructuredFields;
import com.ebremer.lws.http.StructuredFields.Bytes;
import com.ebremer.lws.http.StructuredFields.InnerList;
import com.ebremer.lws.http.StructuredFields.Item;
import com.ebremer.lws.http.StructuredFields.Member;
import com.ebremer.lws.internal.Uris;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Verifies signed webhook deliveries ({@code lws10-notifications-webhook}): RFC 9530
 * {@code Content-Digest} and RFC 9421 HTTP Message Signatures whose key is published in the signing
 * storage's description (located by the signature {@code keyid}).
 *
 * <pre>{@code
 * WebhookVerifier verifier = WebhookVerifier.builder()
 *     .client(client)                                  // fetches storage descriptions
 *     .trustedStorages(List.of(URI.create("https://storage.example/")))
 *     .build();
 * VerifiedNotification v = verifier.verify("POST", inboxUrl, headers, body);
 * }</pre>
 *
 * <p>The URL passed to {@code verify} must be the inbox URL as registered in the subscription (not the
 * URL a reverse proxy forwarded to), because {@code @scheme}, {@code @authority} and {@code @path} are
 * signed.
 */
public final class WebhookVerifier {
    /** Components every LWS webhook signature must cover. */
    public static final List<String> REQUIRED_COMPONENTS =
            List.of("@method", "@scheme", "@authority", "@path", "content-type", "content-digest");

    private final Function<URI, StorageDescription> descriptions;
    private final Clock clock;
    private final Duration maxAge;
    private final Duration clockSkew;
    private final Set<URI> trusted;
    private final Duration cacheTtl;
    private final Map<URI, Cached> cache = new ConcurrentHashMap<>();

    private record Cached(StorageDescription description, Instant fetched) {}

    private WebhookVerifier(Builder b) {
        Function<URI, StorageDescription> d = b.descriptions;
        if (d == null) {
            LwsClient c = b.client != null ? b.client : LwsClient.builder().build();
            d = c::getStorageDescription;
        }
        this.descriptions = d;
        this.clock = b.clock;
        this.maxAge = b.maxAge;
        this.clockSkew = b.clockSkew;
        this.trusted = b.trusted == null ? null : Set.copyOf(b.trusted);
        this.cacheTtl = b.cacheTtl;
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Verifies a delivery.
     *
     * @param method the request method (POST)
     * @param inboxUrl the inbox URL as registered
     * @param headers the request headers (names case-insensitive)
     * @param body the raw request body
     * @return the verified notification
     * @throws SignatureVerificationException if anything does not verify
     */
    public VerifiedNotification verify(String method, URI inboxUrl, Map<String, ? extends Collection<String>> headers, byte[] body) {
        Objects.requireNonNull(inboxUrl, "inboxUrl");
        Map<String, List<String>> h = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.forEach((k, v) -> {
            if (k != null) h.computeIfAbsent(k, x -> new java.util.ArrayList<>()).addAll(v);
        });
        byte[] content = body == null ? new byte[0] : body;

        checkDigest(field(h, "content-digest"), content);

        Map<String, Member> inputs = dictionary(field(h, "signature-input"), "Signature-Input");
        Map<String, Member> signatures = dictionary(field(h, "signature"), "Signature");
        String label = null;
        InnerList covered = null;
        for (Map.Entry<String, Member> e : inputs.entrySet()) {
            if (e.getValue() instanceof InnerList il && il.params().get("keyid") instanceof String && signatures.containsKey(e.getKey())) {
                label = e.getKey();
                covered = il;
                break;
            }
        }
        if (label == null) throw fail("No signature with a keyid in Signature-Input/Signature");
        if (!(signatures.get(label) instanceof Item sigItem) || !(sigItem.value() instanceof Bytes sigBytes)) {
            throw fail("Signature " + label + " is not a byte sequence");
        }

        Set<String> components = new HashSet<>();
        for (Item it : covered.items()) {
            if (!(it.value() instanceof String name)) throw fail("Covered component is not a string");
            if (!it.params().isEmpty()) throw fail("Unsupported component parameters on " + name);
            if (!components.add(name)) throw fail("Duplicate covered component " + name);
        }
        for (String r : REQUIRED_COMPONENTS) {
            if (!components.contains(r)) throw fail("Required component not covered: " + r);
        }
        Map<String, Object> params = covered.params();
        if (!(params.get("created") instanceof Long created)) throw fail("Signature parameters lack an integer 'created'");
        long now = clock.instant().getEpochSecond();
        if (created < now - maxAge.getSeconds()) throw fail("Signature too old (created " + created + ")");
        if (created > now + clockSkew.getSeconds()) throw fail("Signature created in the future (created " + created + ")");
        Object expires = params.get("expires");
        if (expires != null && (!(expires instanceof Long exp) || exp < now)) throw fail("Signature expired");
        String keyid = (String) params.get("keyid");
        String alg = params.get("alg") instanceof String a ? a : null;

        int hash = keyid.indexOf('#');
        if (hash < 0 || hash == keyid.length() - 1) throw fail("keyid is not a URL with a fragment: " + keyid);
        URI storageId;
        try {
            storageId = Uris.parse(keyid.substring(0, hash));
        } catch (IllegalArgumentException e) {
            throw fail("keyid is not a URL: " + keyid);
        }
        if (!storageId.isAbsolute()) throw fail("keyid is not an absolute URL: " + keyid);
        if (trusted != null && !trusted.contains(storageId)) throw fail("Storage " + storageId + " is not trusted");

        String base = signatureBase(method, inboxUrl, h, covered);
        byte[] signature = sigBytes.value();

        Cached cached = cache.get(storageId);
        boolean fromCache = cached != null && cached.fetched().plus(cacheTtl).isAfter(clock.instant());
        StorageDescription desc = fromCache ? cached.description() : fetch(storageId);
        String algorithm;
        try {
            algorithm = verifyWith(desc, storageId, keyid, alg, base, signature);
        } catch (SignatureVerificationException first) {
            if (!fromCache) throw first;
            desc = fetch(storageId);
            algorithm = verifyWith(desc, storageId, keyid, alg, base, signature);
        }

        Notification notification;
        try {
            notification = Notification.parse(content);
        } catch (LwsException e) {
            throw new SignatureVerificationException("Signed body is not a valid notification: " + e.getMessage(), e);
        }
        if (!notification.storage().equals(storageId)) {
            throw fail("Notification storage " + notification.storage() + " does not match the signing storage " + storageId);
        }
        return new VerifiedNotification(notification, keyid, storageId, label, algorithm);
    }

    /** Builds the RFC 9421 signature base for the covered components (exposed for diagnostics). */
    public static String signatureBase(String method, URI url, Map<String, List<String>> headers, InnerList covered) {
        StringBuilder sb = new StringBuilder();
        for (Item it : covered.items()) {
            String name = (String) it.value();
            sb.append(StructuredFields.serializeBareItem(name)).append(": ").append(componentValue(name, method, url, headers)).append('\n');
        }
        sb.append("\"@signature-params\": ").append(StructuredFields.serialize(covered));
        return sb.toString();
    }

    private static String componentValue(String name, String method, URI url, Map<String, List<String>> headers) {
        switch (name) {
            case "@method":
                return method.toUpperCase(Locale.ROOT);
            case "@scheme":
                return url.getScheme().toLowerCase(Locale.ROOT);
            case "@authority": {
                String host = url.getHost().toLowerCase(Locale.ROOT);
                int port = url.getPort();
                return port < 0 || port == defaultPort(url) ? host : host + ":" + port;
            }
            case "@path": {
                String p = url.getRawPath();
                return p == null || p.isEmpty() ? "/" : p;
            }
            case "@query":
                return "?" + (url.getRawQuery() == null ? "" : url.getRawQuery());
            case "@target-uri":
                return url.toString();
            case "@request-target": {
                String p = url.getRawPath() == null || url.getRawPath().isEmpty() ? "/" : url.getRawPath();
                return url.getRawQuery() == null ? p : p + "?" + url.getRawQuery();
            }
            default:
                if (name.startsWith("@")) throw fail("Unsupported derived component " + name);
                List<String> values = headers.get(name);
                if (values == null || values.isEmpty()) throw fail("Covered header field missing: " + name);
                StringBuilder sb = new StringBuilder();
                for (String v : values) {
                    if (sb.length() > 0) sb.append(", ");
                    sb.append(v.trim());
                }
                return sb.toString();
        }
    }

    private static int defaultPort(URI url) {
        return "https".equalsIgnoreCase(url.getScheme()) ? 443 : "http".equalsIgnoreCase(url.getScheme()) ? 80 : -1;
    }

    private String verifyWith(StorageDescription desc, URI storageId, String keyid, String alg, String base, byte[] signature) {
        if (!desc.id().equals(storageId)) {
            throw fail("Storage description id " + desc.id() + " does not match the keyid storage " + storageId);
        }
        VerificationMethod vm = desc.verificationMethod(keyid)
                .orElseThrow(() -> fail("Verification method " + keyid + " not found in the storage description"));
        if (!desc.isAuthenticationMethod(vm)) {
            throw fail("Verification method " + keyid + " is not referenced from authentication");
        }
        ObjectNode jwk = vm.publicKeyJwk();
        if (jwk == null) throw fail("Verification method " + keyid + " has no publicKeyJwk");
        PublicKey key;
        try {
            key = Jwk.toPublicKey(jwk);
        } catch (IllegalArgumentException e) {
            throw new SignatureVerificationException("Unusable verification key " + keyid + ": " + e.getMessage(), e);
        }
        String keyAlg = keyAlgorithm(jwk, alg);
        if (alg != null && !alg.equals(keyAlg)) throw fail("alg " + alg + " does not match the key type (" + keyAlg + ")");
        try {
            Signature s = jca(keyAlg);
            s.initVerify(key);
            s.update(base.getBytes(StandardCharsets.UTF_8));
            if (!s.verify(signature)) throw fail("Signature does not verify");
        } catch (GeneralSecurityException e) {
            throw new SignatureVerificationException("Signature does not verify: " + e.getMessage(), e);
        }
        return keyAlg;
    }

    private static String keyAlgorithm(ObjectNode jwk, String requested) {
        String kty = jwk.path("kty").asText();
        String crv = jwk.path("crv").asText();
        if ("EC".equals(kty) && "P-256".equals(crv)) return "ecdsa-p256-sha256";
        if ("EC".equals(kty) && "P-384".equals(crv)) return "ecdsa-p384-sha384";
        if ("OKP".equals(kty) && "Ed25519".equals(crv)) return "ed25519";
        if ("RSA".equals(kty)) {
            if ("rsa-pss-sha512".equals(requested) || "rsa-v1_5-sha256".equals(requested)) return requested;
            String jwkAlg = jwk.path("alg").asText("");
            if (jwkAlg.startsWith("PS")) return "rsa-pss-sha512";
            if (jwkAlg.startsWith("RS")) return "rsa-v1_5-sha256";
            throw fail("RSA key requires an alg signature parameter");
        }
        throw fail("Unsupported verification key type " + kty + " " + crv);
    }

    private static Signature jca(String alg) throws GeneralSecurityException {
        switch (alg) {
            case "ecdsa-p256-sha256":
                return Signature.getInstance("SHA256withECDSAinP1363Format");
            case "ecdsa-p384-sha384":
                return Signature.getInstance("SHA384withECDSAinP1363Format");
            case "ed25519":
                return Signature.getInstance("Ed25519");
            case "rsa-v1_5-sha256":
                return Signature.getInstance("SHA256withRSA");
            case "rsa-pss-sha512": {
                Signature s = Signature.getInstance("RSASSA-PSS");
                s.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
                return s;
            }
            default:
                throw fail("Unsupported signature algorithm " + alg);
        }
    }

    private StorageDescription fetch(URI storageId) {
        StorageDescription d;
        try {
            d = descriptions.apply(storageId);
        } catch (LwsException e) {
            throw new SignatureVerificationException("Cannot retrieve storage description " + storageId + ": " + e.getMessage(), e);
        }
        if (d == null) throw fail("No storage description for " + storageId);
        cache.put(storageId, new Cached(d, clock.instant()));
        return d;
    }

    private static void checkDigest(String header, byte[] body) {
        Map<String, Member> digests = dictionary(header, "Content-Digest");
        boolean any = false;
        for (String[] alg : new String[][] {{"sha-256", "SHA-256"}, {"sha-512", "SHA-512"}}) {
            Member m = digests.get(alg[0]);
            if (m == null) continue;
            any = true;
            if (!(m instanceof Item it) || !(it.value() instanceof Bytes expected)) throw fail("Malformed " + alg[0] + " digest");
            try {
                byte[] actual = MessageDigest.getInstance(alg[1]).digest(body);
                if (!MessageDigest.isEqual(actual, expected.value())) throw fail("Content-Digest " + alg[0] + " mismatch");
            } catch (GeneralSecurityException e) {
                throw new SignatureVerificationException("Digest unavailable: " + alg[1], e);
            }
        }
        if (!any) throw fail("Content-Digest has no supported algorithm (sha-256, sha-512)");
    }

    private static String field(Map<String, List<String>> headers, String name) {
        List<String> v = headers.get(name);
        if (v == null || v.isEmpty()) throw fail("Missing " + name + " header");
        return String.join(", ", v);
    }

    private static Map<String, Member> dictionary(String value, String what) {
        try {
            return StructuredFields.parseDictionary(value);
        } catch (IllegalArgumentException e) {
            throw new SignatureVerificationException("Malformed " + what + ": " + e.getMessage(), e);
        }
    }

    private static SignatureVerificationException fail(String message) {
        return new SignatureVerificationException(message);
    }

    /** Builder for {@link WebhookVerifier}. */
    public static final class Builder {
        private Function<URI, StorageDescription> descriptions;
        private LwsClient client;
        private Clock clock = Clock.systemUTC();
        private Duration maxAge = Duration.ofSeconds(300);
        private Duration clockSkew = Duration.ofSeconds(300);
        private Collection<URI> trusted;
        private Duration cacheTtl = Duration.ofMinutes(10);

        private Builder() {}

        /** The client used to fetch storage descriptions (default: a new anonymous client). */
        public Builder client(LwsClient client) {
            this.client = client;
            return this;
        }

        /** A custom storage description source (overrides {@link #client}). */
        public Builder descriptions(Function<URI, StorageDescription> descriptions) {
            this.descriptions = descriptions;
            return this;
        }

        /** Only accept deliveries signed by these storages. */
        public Builder trustedStorages(Collection<URI> storages) {
            this.trusted = storages;
            return this;
        }

        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock);
            return this;
        }

        /** Maximum age of a signature's {@code created} time (default 300 seconds). */
        public Builder maxAge(Duration maxAge) {
            this.maxAge = Objects.requireNonNull(maxAge);
            return this;
        }

        /** Tolerated clock skew for {@code created} times in the future (default 300 seconds). */
        public Builder clockSkew(Duration skew) {
            this.clockSkew = Objects.requireNonNull(skew);
            return this;
        }

        /** How long storage descriptions (keys) are cached (default 10 minutes). */
        public Builder keyCacheTtl(Duration ttl) {
            this.cacheTtl = Objects.requireNonNull(ttl);
            return this;
        }

        public WebhookVerifier build() {
            return new WebhookVerifier(this);
        }
    }
}
