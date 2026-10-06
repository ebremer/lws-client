// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import com.ebremer.lws.auth.ControlledIdentifiers;
import com.ebremer.lws.auth.CredentialContext;
import com.ebremer.lws.auth.DidKey;
import com.ebremer.lws.auth.Jwk;
import com.ebremer.lws.auth.Jwt;
import com.ebremer.lws.auth.KeyPairs;
import com.ebremer.lws.auth.SamlCredentials;
import com.ebremer.lws.auth.SelfSignedCredentials;
import com.ebremer.lws.http.StructuredFields;
import com.ebremer.lws.notify.Notification;
import com.ebremer.lws.notify.VerifiedNotification;
import com.ebremer.lws.notify.WebhookVerifier;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/** did:key, JWT, JWK and RFC 9421 webhook vectors from the shared fixtures. */
class CryptoFixturesTest {

    @TestFactory
    Stream<DynamicTest> didKeyVectors() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode v : Fixtures.json("did-key.json").get("vectors")) {
            tests.add(dynamicTest(v.get("name").asText(), () -> {
                PublicKey key = Jwk.toPublicKey(v.get("publicJwk"));
                assertEquals(v.get("did").asText(), DidKey.fromPublicKey(key));
                assertEquals(v.get("kid").asText(), DidKey.keyId(key));
                assertEquals(v.get("kid").asText(), DidKey.keyId(v.get("did").asText()));
                PublicKey decoded = DidKey.toPublicKey(v.get("did").asText());
                assertEquals(Jwk.fromPublicKey(key), Jwk.fromPublicKey(decoded));
            }));
        }
        return tests.stream();
    }

    @TestFactory
    Stream<DynamicTest> jwtVectors() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode v : Fixtures.json("jwt.json").get("vectors")) {
            tests.add(dynamicTest(v.get("name").asText(), () -> {
                String jwt = v.get("jwt").asText();
                PublicKey key = Jwk.toPublicKey(v.get("publicJwk"));
                assertTrue(Jwt.verify(jwt, key), "signature verifies");
                assertEquals(v.get("header"), Jwt.header(jwt));
                assertEquals(v.get("claims"), Jwt.claims(jwt));
                // The did:key in the claims resolves to the same key.
                assertTrue(Jwt.verify(jwt, DidKey.toPublicKey(v.get("claims").get("sub").asText())));
                String tampered = jwt.substring(0, jwt.length() - 4) + (jwt.endsWith("AAAA") ? "BBBB" : "AAAA");
                assertFalse(Jwt.verify(tampered, key));
            }));
        }
        return tests.stream();
    }

    @Test
    void privateJwkRoundTrip() {
        for (String name : List.of("keys/p256.json", "keys/ed25519.json")) {
            JsonNode doc = Fixtures.json(name);
            KeyPair kp = Jwk.toKeyPair(doc.get("privateJwk"));
            ObjectNode back = Jwk.fromKeyPair(kp);
            assertEquals(doc.get("privateJwk").get("d").asText(), back.get("d").asText(), name);
            assertEquals(doc.get("publicJwk").get("x").asText(), back.get("x").asText(), name);
        }
    }

    @Test
    void selfSignedCredentialsP256AndEd25519() {
        for (KeyPair kp : List.of(KeyPairs.generateP256(), KeyPairs.generateEd25519())) {
            SelfSignedCredentials creds = SelfSignedCredentials.didKey(kp);
            assertEquals(Lws.TokenType.JWT, creds.tokenType());
            assertTrue(creds.agent().toString().startsWith(kp.getPublic().getAlgorithm().equals("EC") ? "did:key:zDn" : "did:key:z6Mk"));
            String jwt = creds.subjectToken(new CredentialContext(URI.create("https://as.example"), URI.create("https://s.example/"), null));
            assertTrue(Jwt.verify(jwt, kp.getPublic()));
            ObjectNode h = Jwt.header(jwt);
            ObjectNode c = Jwt.claims(jwt);
            assertEquals(creds.algorithm(), h.get("alg").asText());
            assertEquals("JWT", h.get("typ").asText());
            assertEquals(creds.keyId(), h.get("kid").asText());
            assertEquals(creds.agent().toString(), c.get("sub").asText());
            assertEquals(c.get("sub"), c.get("iss"));
            assertEquals(c.get("sub"), c.get("client_id"));
            assertEquals("https://as.example", c.get("aud").get(0).asText());
            assertEquals(300, c.get("exp").asLong() - c.get("iat").asLong());
            assertNotNull(c.get("jti"));
            // cached per audience
            assertEquals(jwt, creds.subjectToken(new CredentialContext(URI.create("https://as.example"), URI.create("https://s.example/"), null)));
        }
        // ES256 signatures are JOSE raw r||s (64 bytes), never DER.
        String es = SelfSignedCredentials.didKey(KeyPairs.generateP256()).createToken("https://as.example");
        assertEquals(64, java.util.Base64.getUrlDecoder().decode(es.substring(es.lastIndexOf('.') + 1)).length);
    }

    @Test
    void controlledIdentifierDocument() {
        KeyPair kp = KeyPairs.generateP256();
        ObjectNode doc = ControlledIdentifiers.document(URI.create("https://id.example/agent"), kp.getPublic(), "k1");
        assertEquals("https://id.example/agent", doc.get("id").asText());
        JsonNode vm = doc.get("authentication").get(0);
        assertEquals("https://id.example/agent#k1", vm.get("id").asText());
        assertEquals("JsonWebKey", vm.get("type").asText());
        assertEquals("k1", vm.get("publicKeyJwk").get("kid").asText());
        assertEquals("ES256", vm.get("publicKeyJwk").get("alg").asText());
        assertFalse(vm.get("publicKeyJwk").has("d"));
    }

    @Test
    void samlEncoding() {
        SamlCredentials s = SamlCredentials.ofXml("<saml:Assertion/>");
        assertEquals(Lws.TokenType.SAML2, s.tokenType());
        assertEquals("PHNhbWw6QXNzZXJ0aW9uLz4", s.subjectToken(null));
    }

    @TestFactory
    Stream<DynamicTest> webhookVectors() {
        StorageDescription desc = StorageDescription.parse(Fixtures.json("webhook/storage-description.json"),
                URI.create("https://storage.example/"));
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode name : Fixtures.json("webhook/index.json").get("vectors")) {
            JsonNode v = Fixtures.json("webhook/" + name.asText());
            tests.add(dynamicTest(v.get("name").asText(), () -> {
                AtomicInteger fetches = new AtomicInteger();
                WebhookVerifier verifier = WebhookVerifier.builder()
                        .descriptions(u -> {
                            fetches.incrementAndGet();
                            assertEquals(URI.create("https://storage.example/"), u);
                            return desc;
                        })
                        .clock(Clock.fixed(Instant.ofEpochSecond(v.get("now").asLong()), ZoneOffset.UTC))
                        .trustedStorages(List.of(URI.create("https://storage.example/")))
                        .build();
                Map<String, List<String>> headers = new LinkedHashMap<>();
                Iterator<Map.Entry<String, JsonNode>> it = v.get("headers").properties().iterator();
                while (it.hasNext()) {
                    Map.Entry<String, JsonNode> e = it.next();
                    headers.put(e.getKey(), List.of(e.getValue().asText()));
                }
                byte[] body = v.get("body").asText().getBytes(StandardCharsets.UTF_8);
                URI url = URI.create(v.get("url").asText());
                JsonNode expected = v.get("expected");
                if (expected.get("valid").asBoolean()) {
                    if (v.has("signatureBase")) {
                        Map<String, StructuredFields.Member> input = StructuredFields.parseDictionary(headers.get("signature-input").get(0));
                        String base = WebhookVerifier.signatureBase("POST", url, headers, (StructuredFields.InnerList) input.get("sig1"));
                        assertEquals(v.get("signatureBase").asText(), base);
                    }
                    VerifiedNotification vn = verifier.verify(v.get("method").asText(), url, headers, body);
                    assertEquals(expected.get("keyid").asText(), vn.keyId());
                    Notification n = vn.notification();
                    JsonNode en = expected.get("notification");
                    assertEquals(en.get("storage").asText(), n.storage().toString());
                    assertEquals(en.get("activities").size(), n.activities().size());
                    for (int i = 0; i < n.activities().size(); i++) {
                        JsonNode ea = en.get("activities").get(i);
                        assertEquals(ea.get("objectId").asText(), n.activities().get(i).object().id().toString());
                        assertEquals(ea.get("types").get(0).asText(), n.activities().get(i).types().get(0));
                    }
                } else {
                    assertThrows(SignatureVerificationException.class, () -> verifier.verify(v.get("method").asText(), url, headers, body));
                }
            }));
        }
        return tests.stream();
    }

    @Test
    void webhookVerifierRejectsUntrustedStorage() {
        JsonNode v = Fixtures.json("webhook/p256-valid.json");
        WebhookVerifier verifier = WebhookVerifier.builder()
                .descriptions(u -> { throw new AssertionError("must not fetch"); })
                .clock(Clock.fixed(Instant.ofEpochSecond(v.get("now").asLong()), ZoneOffset.UTC))
                .trustedStorages(List.of(URI.create("https://other.example/")))
                .build();
        Map<String, List<String>> headers = new LinkedHashMap<>();
        v.get("headers").properties().forEach(e -> headers.put(e.getKey(), List.of(e.getValue().asText())));
        assertThrows(SignatureVerificationException.class, () -> verifier.verify("POST", URI.create(v.get("url").asText()), headers,
                v.get("body").asText().getBytes(StandardCharsets.UTF_8)));
    }
}
