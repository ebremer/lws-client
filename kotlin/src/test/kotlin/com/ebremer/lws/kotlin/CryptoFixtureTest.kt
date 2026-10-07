// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.auth.ControlledIdentifierDocument
import com.ebremer.lws.kotlin.auth.DidKey
import com.ebremer.lws.kotlin.auth.Jwt
import com.ebremer.lws.kotlin.auth.SigningKey
import com.ebremer.lws.kotlin.auth.VerificationKey
import com.ebremer.lws.kotlin.http.Headers
import com.ebremer.lws.kotlin.http.SfInnerList
import com.ebremer.lws.kotlin.http.StructuredFields
import com.ebremer.lws.kotlin.notify.WebhookVerifier
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import java.net.URI
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The did:key, JWT, key and RFC 9421 webhook fixtures. */
class CryptoFixtureTest {
    private fun vectors(name: String, test: (JsonObject) -> Unit): List<DynamicTest> =
        Fixtures.load(name).arr("vectors").map { v -> DynamicTest.dynamicTest(v.jsonObject.str("name")) { test(v.jsonObject) } }

    @TestFactory
    fun didKeyDerivation(): List<DynamicTest> = vectors("did-key.json") { v ->
        val key = VerificationKey.fromJwk(v.obj("publicJwk"))
        assertEquals(v.str("did"), DidKey.did(key))
        assertEquals(v.str("kid"), DidKey.keyId(key))
        assertEquals(v.str("kid"), DidKey.keyIdForDid(v.str("did")))
        assertEquals(v.str("did"), DidKey.didFromJwk(v.obj("publicJwk")))
        assertEquals(key, DidKey.publicKey(v.str("kid")))
        assertEquals(v.obj("publicJwk").toMap(), DidKey.publicKey(v.str("did")).jwk().toMap())
    }

    @Test
    fun didKeyErrorsAndBase58() {
        assertEquals("", DidKey.encode(ByteArray(0)))
        assertEquals("11", DidKey.encode(ByteArray(2)))
        assertContentEquals(byteArrayOf(0, 0, 1, 2), DidKey.decode(DidKey.encode(byteArrayOf(0, 0, 1, 2))))
        assertNull(DidKey.decode("0OIl"))
        for (bad in listOf("did:web:x", "did:key:z0", "did:key:z" + DidKey.encode(byteArrayOf(0x12, 0x34, 0x61, 0x62, 0x63)))) {
            assertFailsWith<IllegalArgumentException>(bad) { DidKey.publicKey(bad) }
        }
        // A P-256 point that is not on the curve.
        assertFailsWith<IllegalArgumentException> {
            DidKey.publicKey("did:key:z" + DidKey.encode(byteArrayOf(0x80.toByte(), 0x24, 0x02) + ByteArray(32) { 0xff.toByte() }))
        }
        assertFailsWith<IllegalArgumentException> { DidKey.did(SigningKey.generate("ES384").publicKey) }
    }

    @TestFactory
    fun jwtCredentialsVerify(): List<DynamicTest> = vectors("jwt.json") { v ->
        val key = VerificationKey.fromJwk(v.obj("publicJwk"))
        val jwt = v.str("jwt")
        assertTrue(Jwt.verify(jwt, key))
        assertEquals(v.obj("header"), Jwt.decodeHeader(jwt))
        assertEquals(v.obj("claims"), Jwt.decodeClaims(jwt))
        assertEquals(v.obj("claims").str("exp").toLong(), Jwt.expiration(jwt)?.epochSecond)
        val tampered = jwt.substring(0, jwt.length - 4) + (if (jwt[jwt.length - 4] == 'A') 'B' else 'A') + jwt.substring(jwt.length - 3)
        assertFalse(Jwt.verify(tampered, key))
        // The kid in the header is the did:key of the key, so the signing key is implied by the token.
        assertEquals(DidKey.keyId(key), v.obj("header").str("kid"))
        assertFalse(Jwt.verify("a.b", key))
        assertNull(Jwt.expiration("not a jwt"))
    }

    @TestFactory
    fun testKeysImportAndSign(): List<DynamicTest> = listOf("keys/p256.json", "keys/ed25519.json", "keys/p256-unlisted.json").map { file ->
        DynamicTest.dynamicTest(file) {
            val f = Fixtures.load(file)
            val key = SigningKey.fromJwk(f.obj("privateJwk"))
            assertEquals(f.obj("publicJwk").toMap(), key.publicKey.jwk().toMap())
            assertEquals(f.obj("privateJwk").filterKeys { it in setOf("kty", "crv", "x", "y", "d") }, key.jwk().toMap())
            val signature = key.sign("signature input".toByteArray())
            assertEquals(64, signature.size)
            val public = VerificationKey.fromJwk(f.obj("publicJwk"))
            assertTrue(public.verify(signature, "signature input".toByteArray()))
            assertFalse(public.verify(signature, "other input".toByteArray()))
            assertFalse(f.obj("privateJwk").str("d") in key.toString())
            assertFailsWith<IllegalArgumentException> { SigningKey.fromJwk(f.obj("publicJwk")) }
        }
    }

    @Test
    fun generatedKeysRoundTrip() {
        for (key in listOf(SigningKey.generateP256(), SigningKey.generateEd25519(), SigningKey.generate("ES384"))) {
            val again = SigningKey.fromJwk(key.jwk())
            assertEquals(key.publicKey, again.publicKey)
            assertTrue(key.publicKey.verify(again.sign("x".toByteArray()), "x".toByteArray()))
            assertEquals(key.algorithm, again.algorithm)
            assertEquals(key.publicKey, SigningKey.of(key.toKeyPair()).publicKey)
            assertEquals(key.publicKey, VerificationKey.of(key.publicKey.javaKey))
        }
        assertEquals(96, SigningKey.generate("ES384").sign("x".toByteArray()).size)
        val mismatched = JsonObject(SigningKey.generateP256().jwk() + ("x" to SigningKey.generateP256().jwk()["x"]!!))
        val edMismatched = JsonObject(SigningKey.generateEd25519().jwk() + ("x" to SigningKey.generateEd25519().jwk()["x"]!!))
        val bad: List<() -> Any> = listOf(
            { SigningKey.fromJwk(mismatched) },
            { SigningKey.fromJwk(edMismatched) },
            { SigningKey.generate("RS256") },
            { VerificationKey.fromJwk(json("""{"kty":"RSA","crv":"x"}""").jsonObject) },
            { VerificationKey.fromJwk(json("""{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"}""").jsonObject) },
            { VerificationKey.fromJwk(json("""{"kty":"OKP","crv":"X25519","x":"AAAA"}""").jsonObject) },
            { VerificationKey.fromJwk(json("""{"kty":"EC","crv":"P-256","x":"!!","y":"AAAA"}""").jsonObject) },
            { VerificationKey.fromJwk(json("""{"kty":"OKP","crv":"Ed25519","x":"AAAA"}""").jsonObject) },
        )
        for (b in bad) assertFailsWith<IllegalArgumentException> { b() }
    }

    @Test
    fun controlledIdentifierDocument() {
        val key = SigningKey.generateEd25519()
        val doc = ControlledIdentifierDocument.create("https://id.example/alice", key.jwk(), "key-1")
        val method = doc.arr("authentication")[0].jsonObject
        assertEquals(json("""["https://www.w3.org/ns/cid/v1"]"""), doc["@context"])
        assertEquals("https://id.example/alice#key-1", method.str("id"))
        assertEquals("EdDSA", method.obj("publicKeyJwk").str("alg"))
        assertFalse("d" in method.obj("publicKeyJwk"))
        assertEquals(
            "did:key:z6Mk#z6Mk",
            ControlledIdentifierDocument.create("did:key:z6Mk", key.publicKey, "did:key:z6Mk#z6Mk").arr("authentication")[0].jsonObject.str("id"),
        )
    }

    private class Vector(val v: JsonObject, val headers: Headers, val body: ByteArray, val description: StorageDescription) {
        val url = URI(v.str("url"))
        val clock: Clock = Clock.fixed(Instant.ofEpochSecond(v.str("now").toLong()), ZoneOffset.UTC)
    }

    private fun headers(o: JsonObject): Headers =
        Headers.of(o.entries.flatMap { (k, v) -> if (v is JsonArray) v.map { k to it.str } else listOf(k to v.str) })

    private fun vector(file: String): Vector {
        val v = Fixtures.load("webhook/$file")
        val description = StorageDescription.parse(Fixtures.load("webhook/storage-description.json"), URI("https://storage.example/"))
        return Vector(v, headers(v.obj("headers")), v.str("body").toByteArray(), description)
    }

    @TestFactory
    fun webhookVectors(): List<DynamicTest> = Fixtures.load("webhook/index.json").strings("vectors").map { file ->
        DynamicTest.dynamicTest(file) {
            runTest {
                val x = vector(file)
                val fetches = mutableListOf<URI>()
                val verifier = WebhookVerifier(
                    storageDescriptionResolver = { url ->
                        fetches.add(url)
                        assertEquals(URI("https://storage.example/"), url)
                        x.description
                    },
                    clock = x.clock,
                )
                val expected = x.v.obj("expected")
                x.v.strOrNull("signatureBase")?.let { base ->
                    val covered = StructuredFields.parseDictionary(x.headers["signature-input"]!!)["sig1"] as SfInnerList
                    assertEquals(base, WebhookVerifier.signatureBase(x.v.str("method"), x.url, x.headers, covered))
                }
                if (!expected.flag("valid")) {
                    assertFailsWith<SignatureVerificationException> { verifier.verify(x.v.str("method"), x.url, x.headers, x.body) }
                    return@runTest
                }
                val verified = verifier.verify(x.v.str("method"), x.url, x.headers, x.body)
                assertEquals(expected.str("keyid"), verified.keyId)
                assertEquals(URI("https://storage.example/"), verified.storage)
                val n = expected.obj("notification")
                assertEquals(n.str("storage"), verified.notification.storage.toString())
                val activities = n.arr("activities").map { it.jsonObject }
                assertEquals(activities.size, verified.notification.activities.size)
                activities.forEachIndexed { i, a ->
                    val got = verified.notification.activities[i]
                    assertEquals(a.strings("types"), got.types)
                    assertEquals(a.str("objectId"), got.`object`.id.toString())
                    assertEquals(a.strOrNull("target"), got.target?.toString())
                }
                assertEquals(1, fetches.size)
                // The description is cached: a second delivery does not fetch it again.
                verifier.verify(x.v.str("method"), x.url, x.headers, x.body)
                assertEquals(1, fetches.size)
            }
        }
    }

    @Test
    fun webhookTrustedStoragesAreEnforcedEvenWhenEmpty() = runTest {
        val x = vector("p256-valid.json")
        fun make(vararg trusted: String) = WebhookVerifier(
            storageDescriptionResolver = { x.description }, trustedStorages = trusted.map(::URI), clock = x.clock,
        )
        for (trusted in listOf(emptyArray(), arrayOf("https://other.example/"))) {
            assertFailsWith<SignatureVerificationException> { make(*trusted).verify("POST", x.url, x.headers, x.body) }
        }
        // Compared as URLs: case and the default port do not matter.
        assertEquals(URI("https://storage.example/"), make("HTTPS://Storage.Example:443/").verify("POST", x.url, x.headers, x.body).storage)
        val any = WebhookVerifier(storageDescriptionResolver = { x.description }, clock = x.clock)
        assertEquals("ecdsa-p256-sha256", any.verify("POST", x.url, x.headers.toMap(), x.body).algorithm)
    }

    @Test
    fun webhookKeyRotationRefetchesOnce() = runTest {
        val x = vector("p256-valid.json")
        // A stale description whose key is the unlisted key (as if the storage rotated keys since).
        val doc = Fixtures.load("webhook/storage-description.json")
        val methods = doc.arr("verificationMethod")
        val method = JsonObject(methods[0].jsonObject + ("publicKeyJwk" to Fixtures.load("keys/p256-unlisted.json").obj("publicJwk")))
        val stale = StorageDescription.parse(JsonObject(doc + ("verificationMethod" to JsonArray(listOf<JsonElement>(method) + methods.drop(1)))), URI("https://storage.example/"))
        var fetches = 0
        val answers = listOf(stale, x.description)
        val verifier = WebhookVerifier(storageDescriptionResolver = { answers[fetches++] }, clock = x.clock)
        // The first fetch is stale and was not cached before: the failure is final.
        assertFailsWith<SignatureVerificationException> { verifier.verify("POST", x.url, x.headers, x.body) }
        assertEquals(1, fetches)
        // Now the stale description is cached: verification fails with it, refetches once and succeeds.
        verifier.verify("POST", x.url, x.headers, x.body)
        assertEquals(2, fetches)
    }

    @Test
    fun webhookVerifierRejectsBadInput() = runTest {
        val x = vector("p256-valid.json")
        val verifier = WebhookVerifier(storageDescriptionResolver = { x.description }, clock = x.clock)
        val cases = listOf(
            x.headers.without("content-digest") to x.body,
            x.headers.without("signature") to x.body,
            x.headers.with("signature-input", "sig1=(") to x.body,
            x.headers.with("content-digest", "md5=:AAAA:") to x.body,
            x.headers to x.body + ' '.code.toByte(),
        )
        for ((h, b) in cases) assertFailsWith<SignatureVerificationException> { verifier.verify("POST", x.url, h, b) }
        // A different inbox URL changes the signature base.
        assertFailsWith<SignatureVerificationException> { verifier.verify("POST", URI("https://elsewhere.example/inbox"), x.headers, x.body) }
        assertFailsWith<IllegalArgumentException> { verifier.verify("POST", URI("/inbox"), x.headers, x.body) }
        // A storage description that cannot be retrieved is a verification failure.
        val failing = WebhookVerifier(storageDescriptionResolver = { throw ProtocolException("no description") }, clock = x.clock)
        assertFailsWith<SignatureVerificationException> { failing.verify("POST", x.url, x.headers, x.body) }
        assertEquals(JsonPrimitive("POST"), JsonPrimitive(x.v.str("method")))
    }
}
