// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin.auth

import com.ebremer.lws.kotlin.Vocabulary
import com.ebremer.lws.kotlin.internal.Base64Url
import com.ebremer.lws.kotlin.internal.JsonAccess
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.math.BigInteger
import java.time.Instant

/**
 * `did:key` identifiers for P-256 (`did:key:zDn…`) and Ed25519 (`did:key:z6Mk…`) keys: multibase base58btc of the
 * multicodec prefix (`0x80 0x24` p256-pub, `0xed 0x01` ed25519-pub) and the (compressed) public key.
 */
public object DidKey {
    private const val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private val P256 = byteArrayOf(0x80.toByte(), 0x24)
    private val ED25519 = byteArrayOf(0xed.toByte(), 0x01)
    private val B58 = BigInteger.valueOf(58)

    /**
     * The `did:key` of a public key.
     *
     * @throws IllegalArgumentException for a P-384 key
     */
    public fun did(key: VerificationKey): String {
        val prefix = when (key.curve) {
            "P-256" -> P256
            "Ed25519" -> ED25519
            else -> throw IllegalArgumentException("did:key supports P-256 and Ed25519 keys, not ${key.curve}")
        }
        return "did:key:z" + encode(prefix + key.compressed())
    }

    /** The `did:key` of a public JWK. */
    public fun didFromJwk(jwk: JsonObject): String = did(VerificationKey.fromJwk(jwk))

    /** The key id of a key's `did:key`: `did:key:z…#z…`. */
    public fun keyId(key: VerificationKey): String = keyIdForDid(did(key))

    /**
     * The key id of a `did:key` (the DID, `#` and its method-specific identifier).
     *
     * @throws IllegalArgumentException when it is not a did:key
     */
    public fun keyIdForDid(did: String): String {
        require(did.startsWith("did:key:z")) { "Not a did:key: $did" }
        val base = did.substringBefore('#')
        return base + "#" + base.substring("did:key:".length)
    }

    /**
     * The public key a `did:key` (or its key id) encodes.
     *
     * @throws IllegalArgumentException when it is not a P-256 or Ed25519 did:key
     */
    public fun publicKey(did: String): VerificationKey {
        val base = did.substringBefore('#')
        require(base.startsWith("did:key:z")) { "Not a base58btc did:key: $did" }
        val bytes = decode(base.substring("did:key:z".length)) ?: throw IllegalArgumentException("Not a base58btc did:key: $did")
        if (bytes.size == 35 && bytes[0] == P256[0] && bytes[1] == P256[1]) {
            val (x, y) = Ec.decompress("P-256", bytes.copyOfRange(2, bytes.size)) ?: throw IllegalArgumentException("Invalid P-256 point in did:key")
            return VerificationKey.ec("P-256", x, y)
        }
        if (bytes.size == 34 && bytes[0] == ED25519[0] && bytes[1] == ED25519[1]) {
            return VerificationKey.ed25519(bytes.copyOfRange(2, bytes.size))
        }
        throw IllegalArgumentException("Unsupported did:key key type: $did")
    }

    /** base58btc encoding (Bitcoin alphabet). */
    public fun encode(bytes: ByteArray): String {
        val zeros = bytes.takeWhile { it.toInt() == 0 }.size
        var n = BigInteger(1, bytes)
        val out = StringBuilder()
        while (n.signum() > 0) {
            val (q, r) = n.divideAndRemainder(B58)
            out.append(ALPHABET[r.toInt()])
            n = q
        }
        repeat(zeros) { out.append('1') }
        return out.reverse().toString()
    }

    /** base58btc decoding, or null for a character outside the alphabet. */
    public fun decode(text: String): ByteArray? {
        var n = BigInteger.ZERO
        for (c in text) {
            val v = ALPHABET.indexOf(c)
            if (v < 0) return null
            n = n.multiply(B58).add(BigInteger.valueOf(v.toLong()))
        }
        val zeros = text.takeWhile { it == '1' }.length
        val body = if (n.signum() == 0) ByteArray(0) else n.toByteArray().let { if (it[0].toInt() == 0) it.copyOfRange(1, it.size) else it }
        return ByteArray(zeros) + body
    }
}

/** Compact JSON Web Tokens (RFC 7519) signed with a [SigningKey], and their unverified contents. */
public object Jwt {
    /** Signs a JWT; the header's `alg` is set from the key. */
    public fun sign(header: JsonObject, claims: JsonObject, key: SigningKey): String {
        val h = JsonObject(mapOf("alg" to JsonPrimitive(key.algorithm)) + header.filterKeys { it != "alg" })
        val input = Base64Url.encode(JsonAccess.encode(h).toByteArray()) + "." + Base64Url.encode(JsonAccess.encode(claims).toByteArray())
        return input + "." + Base64Url.encode(key.sign(input.toByteArray(Charsets.US_ASCII)))
    }

    /** Whether a JWT is signed by [key] (its header's `alg` must be the key's algorithm). */
    public fun verify(jwt: String, key: VerificationKey): Boolean {
        val parts = jwt.split('.')
        if (parts.size != 3) return false
        val header = try {
            decodeHeader(jwt)
        } catch (_: IllegalArgumentException) {
            return false
        }
        val signature = Base64Url.decode(parts[2]) ?: return false
        if (JsonAccess.str(header, "alg") != key.algorithm) return false
        return key.verify(signature, (parts[0] + "." + parts[1]).toByteArray(Charsets.US_ASCII))
    }

    /**
     * The header, without verifying anything.
     *
     * @throws IllegalArgumentException when it is not a JWT
     */
    public fun decodeHeader(jwt: String): JsonObject = part(jwt, 0)

    /**
     * The claims, without verifying anything.
     *
     * @throws IllegalArgumentException when it is not a JWT
     */
    public fun decodeClaims(jwt: String): JsonObject = part(jwt, 1)

    /** The `exp` claim of a JWT (unverified), or null when it is not a JWT or has none. */
    public fun expiration(token: String): Instant? = try {
        JsonAccess.long(decodeClaims(token), "exp")?.let(Instant::ofEpochSecond)
    } catch (_: IllegalArgumentException) {
        null
    } catch (_: java.time.DateTimeException) {
        null
    }

    private fun part(jwt: String, index: Int): JsonObject {
        val parts = jwt.split('.')
        require(parts.size >= 2) { "Not a JWT" }
        val bytes = Base64Url.decode(parts[index]) ?: throw IllegalArgumentException("Not a JWT: invalid base64url")
        val value = try {
            JsonAccess.decode(bytes)
        } catch (_: SerializationException) {
            throw IllegalArgumentException("Not a JWT: a part is not JSON")
        }
        return value as? JsonObject ?: throw IllegalArgumentException("Not a JWT: a part is not a JSON object")
    }
}

/**
 * The controlled identifier document an agent with an HTTPS identifier publishes at that identifier, so that
 * authorization servers can verify its self-signed credentials (`lws10-authn-ssi-cid`).
 */
public object ControlledIdentifierDocument {
    /**
     * The document: `@context` CID v1, `id`, and `authentication` with one `JsonWebKey` verification method
     * (`agent#kid`, or `kid` itself when it is a URI).
     */
    public fun create(agent: String, publicKey: VerificationKey, kid: String): JsonObject = create(agent, publicKey.jwk(), kid)

    /** The document, from the agent's public JWK (a private member `d` is left out). */
    public fun create(agent: String, publicJwk: JsonObject, kid: String): JsonObject {
        val jwk = LinkedHashMap<String, JsonElement>(publicJwk.filterKeys { it != "d" })
        jwk["kid"] = JsonPrimitive(kid)
        if ("alg" !in jwk) {
            val kty = JsonAccess.str(publicJwk, "kty")
            val crv = JsonAccess.str(publicJwk, "crv")
            jwk["alg"] = JsonPrimitive(if (kty == "OKP") "EdDSA" else if (crv == "P-384") "ES384" else "ES256")
        }
        val method = JsonObject(
            mapOf(
                "id" to JsonPrimitive(if (':' in kid) kid else "$agent#$kid"),
                "type" to JsonPrimitive("JsonWebKey"),
                "controller" to JsonPrimitive(agent),
                "publicKeyJwk" to JsonObject(jwk),
            ),
        )
        return JsonObject(
            mapOf(
                "@context" to JsonArray(listOf(JsonPrimitive(Vocabulary.CID_CONTEXT))),
                "id" to JsonPrimitive(agent),
                "authentication" to JsonArray(listOf(method)),
            ),
        )
    }
}
