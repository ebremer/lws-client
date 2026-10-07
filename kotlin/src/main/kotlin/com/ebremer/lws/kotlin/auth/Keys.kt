// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin.auth

import com.ebremer.lws.kotlin.internal.Base64Url
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.EdECPrivateKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.NamedParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * A public key that verifies signatures: P-256 (`ES256`), P-384 (`ES384`) or Ed25519 (`EdDSA`). ECDSA signatures
 * are JOSE's raw `r‖s`.
 *
 * @property curve `P-256`, `P-384` or `Ed25519`
 */
public class VerificationKey private constructor(public val curve: String, x: ByteArray, y: ByteArray?, key: PublicKey) {
    private val xBytes = x
    private val yBytes = y

    /** The key for the Java Cryptography Architecture. */
    public val javaKey: PublicKey = key

    /** The JOSE algorithm: `ES256`, `ES384` or `EdDSA`. */
    public val algorithm: String
        get() = when (curve) {
            "P-256" -> "ES256"
            "P-384" -> "ES384"
            else -> "EdDSA"
        }

    /** The JWK `kty`: `EC` or `OKP`. */
    public val keyType: String get() = if (curve == "Ed25519") "OKP" else "EC"

    /** The public JWK. */
    public fun jwk(): JsonObject {
        val j = linkedMapOf("kty" to JsonPrimitive(keyType), "crv" to JsonPrimitive(curve), "x" to JsonPrimitive(Base64Url.encode(xBytes)))
        if (yBytes != null) j["y"] = JsonPrimitive(Base64Url.encode(yBytes))
        return JsonObject(j)
    }

    /** The compressed point (`02|03 ‖ x`) of an EC key, or the raw key of an Ed25519 one. */
    public fun compressed(): ByteArray {
        val y = yBytes ?: return xBytes.copyOf()
        return byteArrayOf(if (y.last().toInt() and 1 == 1) 3 else 2) + xBytes
    }

    /** Verifies a signature (raw `r‖s` for ECDSA) over [data]. */
    public fun verify(signature: ByteArray, data: ByteArray): Boolean {
        val expected = if (curve == "Ed25519") 64 else 2 * Ec.size(curve)
        if (signature.size != expected || signature.all { it.toInt() == 0 }) return false
        return try {
            val v = Signature.getInstance(Ec.signatureAlgorithm(curve))
            v.initVerify(javaKey)
            v.update(data)
            v.verify(signature)
        } catch (_: GeneralSecurityException) {
            false
        }
    }

    override fun equals(other: Any?): Boolean =
        other is VerificationKey && other.curve == curve && MessageDigest.isEqual(other.xBytes, xBytes) &&
            (other.yBytes ?: ByteArray(0)).contentEquals(yBytes ?: ByteArray(0))

    override fun hashCode(): Int = 31 * curve.hashCode() + xBytes.contentHashCode()

    override fun toString(): String = "$algorithm public key"

    public companion object {
        /**
         * Imports a public JWK (`EC` P-256 or P-384, `OKP` Ed25519); private members are ignored.
         *
         * @throws IllegalArgumentException for an unsupported or invalid key
         */
        public fun fromJwk(jwk: JsonObject): VerificationKey {
            val kty = string(jwk, "kty")
            val crv = string(jwk, "crv")
            return when (kty) {
                "EC" -> {
                    require(crv == "P-256" || crv == "P-384") { "Unsupported EC curve: $crv" }
                    val size = Ec.size(crv)
                    ec(crv, member(jwk, "x", size), member(jwk, "y", size))
                }
                "OKP" -> {
                    require(crv == "Ed25519") { "Unsupported OKP curve: $crv" }
                    ed25519(member(jwk, "x", 32, exact = true))
                }
                else -> throw IllegalArgumentException("Unsupported JWK kty: $kty")
            }
        }

        /**
         * Wraps a JCA public key (EC P-256 or P-384, or Ed25519).
         *
         * @throws IllegalArgumentException for another kind of key
         */
        public fun of(key: PublicKey): VerificationKey = when {
            key is ECPublicKey -> {
                val crv = Ec.curveName(key.params)
                val size = Ec.size(crv)
                ec(crv, Ec.fixed(key.w.affineX, size), Ec.fixed(key.w.affineY, size))
            }
            key.algorithm.equals("Ed25519", ignoreCase = true) || key.algorithm.equals("EdDSA", ignoreCase = true) -> {
                val enc = key.encoded
                ed25519(enc.copyOfRange(enc.size - 32, enc.size))
            }
            else -> throw IllegalArgumentException("Unsupported key type ${key.algorithm}")
        }

        /** An EC key from its coordinates; the point must be on the curve. */
        internal fun ec(curve: String, x: ByteArray, y: ByteArray): VerificationKey {
            val params = Ec.params(curve)
            val point = ECPoint(BigInteger(1, x), BigInteger(1, y))
            require(Ec.isOnCurve(params, point)) { "Invalid $curve public key: the point is not on the curve" }
            val key = try {
                KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params))
            } catch (e: GeneralSecurityException) {
                throw IllegalArgumentException("Invalid $curve public key: ${e.message}", e)
            }
            return VerificationKey(curve, x, y, key)
        }

        /** An Ed25519 key from its 32 bytes. */
        internal fun ed25519(x: ByteArray): VerificationKey {
            require(x.size == 32) { "An Ed25519 public key has 32 bytes" }
            val key = try {
                KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(Ec.ED25519_SPKI_PREFIX + x))
            } catch (e: GeneralSecurityException) {
                throw IllegalArgumentException("Invalid Ed25519 public key: ${e.message}", e)
            }
            return VerificationKey("Ed25519", x, null, key)
        }

        internal fun string(jwk: JsonObject, name: String): String =
            (jwk[name] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: throw IllegalArgumentException("JWK member '$name' is missing")

        /**
         * A base64url JWK member of [size] bytes. EC integers that are shorter are left-padded; an [exact] member (an
         * Ed25519 key or seed, which are not integers) must have the size.
         */
        internal fun member(jwk: JsonObject, name: String, size: Int, exact: Boolean = false): ByteArray {
            val bytes = Base64Url.decode(string(jwk, name)) ?: throw IllegalArgumentException("JWK member '$name' is not base64url")
            require(bytes.isNotEmpty() && bytes.size <= size && (!exact || bytes.size == size)) { "JWK member '$name' has the wrong length" }
            return ByteArray(size - bytes.size) + bytes
        }
    }
}

/**
 * A private key that signs: P-256 (`ES256`, required by the self-signed suite), P-384 (`ES384`) or Ed25519
 * (`EdDSA`). ECDSA signatures are JOSE's raw `r‖s`.
 *
 * ```kotlin
 * val key = SigningKey.generateP256()
 * val jwk = key.jwk()                 // store it: {"kty":"EC","crv":"P-256","x":…,"y":…,"d":…}
 * val again = SigningKey.fromJwk(jwk)
 * ```
 *
 * @property publicKey the public half
 */
public class SigningKey private constructor(public val publicKey: VerificationKey, private val privateKey: PrivateKey, private val d: ByteArray) {

    /** The JOSE algorithm: `ES256`, `ES384` or `EdDSA`. */
    public val algorithm: String get() = publicKey.algorithm

    /** The private JWK (public members and `d`). Keep it secret. */
    public fun jwk(): JsonObject = JsonObject(publicKey.jwk() + ("d" to JsonPrimitive(Base64Url.encode(d))))

    /** The key pair for the Java Cryptography Architecture. */
    public fun toKeyPair(): KeyPair = KeyPair(publicKey.javaKey, privateKey)

    /** Signs [data]: raw `r‖s` (64 bytes for P-256, 96 for P-384) or a 64-byte Ed25519 signature. */
    public fun sign(data: ByteArray): ByteArray {
        val s = Signature.getInstance(Ec.signatureAlgorithm(publicKey.curve))
        s.initSign(privateKey)
        s.update(data)
        return s.sign()
    }

    override fun toString(): String = "$algorithm private key"

    public companion object {
        /** A new P-256 key. */
        public fun generateP256(): SigningKey = generateEc("P-256")

        /** A new Ed25519 key. */
        public fun generateEd25519(): SigningKey {
            val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
            return ed25519(seed)
        }

        /**
         * A new key for a JOSE algorithm: `ES256`, `ES384` or `EdDSA`.
         *
         * @throws IllegalArgumentException for another algorithm
         */
        public fun generate(algorithm: String): SigningKey = when (algorithm) {
            "ES256" -> generateP256()
            "ES384" -> generateEc("P-384")
            "EdDSA", "Ed25519" -> generateEd25519()
            else -> throw IllegalArgumentException("Unsupported algorithm: $algorithm")
        }

        private fun generateEc(curve: String): SigningKey {
            val g = KeyPairGenerator.getInstance("EC")
            g.initialize(ECGenParameterSpec(Ec.stdName(curve)))
            return of(g.generateKeyPair())
        }

        /**
         * Wraps a JCA key pair (EC P-256 or P-384, or Ed25519).
         *
         * @throws IllegalArgumentException for another kind of key
         */
        public fun of(keyPair: KeyPair): SigningKey {
            val public = VerificationKey.of(keyPair.public)
            val private = keyPair.private
            val d = when (private) {
                is ECPrivateKey -> Ec.fixed(private.s, Ec.size(public.curve))
                is EdECPrivateKey -> private.bytes.orElseThrow { IllegalArgumentException("The Ed25519 private key bytes are not available") }
                else -> throw IllegalArgumentException("Unsupported private key type ${private.algorithm}")
            }
            val key = SigningKey(public, private, d)
            require(key.matches()) { "The key pair's public key does not match its private key" }
            return key
        }

        /**
         * Imports a private JWK (`EC` P-256 or P-384, `OKP` Ed25519, with `d`). Its public members must match `d`.
         *
         * @throws IllegalArgumentException for a public, unsupported, invalid or inconsistent key
         */
        public fun fromJwk(jwk: JsonObject): SigningKey {
            require((jwk["d"] as? JsonPrimitive)?.isString == true) { "The JWK has no private key member 'd'" }
            val public = VerificationKey.fromJwk(jwk)
            if (public.curve == "Ed25519") {
                val key = ed25519(VerificationKey.member(jwk, "d", 32, exact = true))
                require(key.publicKey == public) { "The JWK's 'x' does not match its 'd'" }
                return key
            }
            val size = Ec.size(public.curve)
            val d = VerificationKey.member(jwk, "d", size)
            val params = Ec.params(public.curve)
            val s = BigInteger(1, d)
            require(s.signum() > 0 && s < params.order) { "Invalid ${public.curve} private key" }
            val private = try {
                KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(s, params))
            } catch (e: GeneralSecurityException) {
                throw IllegalArgumentException("Invalid ${public.curve} private key: ${e.message}", e)
            }
            val key = SigningKey(public, private, d)
            require(key.matches()) { "The JWK's 'x' and 'y' do not match its 'd'" }
            return key
        }

        /** An Ed25519 key from its seed; the JDK derives the public key from it. */
        private fun ed25519(seed: ByteArray): SigningKey {
            require(seed.size == 32) { "An Ed25519 seed has 32 bytes" }
            val fixed = object : SecureRandom() {
                override fun nextBytes(bytes: ByteArray) {
                    seed.copyInto(bytes, 0, 0, minOf(bytes.size, seed.size))
                }
            }
            val g = KeyPairGenerator.getInstance("Ed25519")
            g.initialize(NamedParameterSpec.ED25519, fixed)
            val pair = g.generateKeyPair()
            val private = KeyFactory.getInstance("Ed25519").generatePrivate(PKCS8EncodedKeySpec(Ec.ED25519_PKCS8_PREFIX + seed))
            return SigningKey(VerificationKey.of(pair.public), private, seed.copyOf())
        }
    }

    /** Whether the public key verifies what the private key signs. */
    private fun matches(): Boolean {
        val probe = ByteArray(32).also { SecureRandom().nextBytes(it) }
        return publicKey.verify(sign(probe), probe)
    }
}

/** The curves: parameters, sizes, point checks and decompression. */
internal object Ec {
    val ED25519_SPKI_PREFIX: ByteArray = hex("302a300506032b6570032100")
    val ED25519_PKCS8_PREFIX: ByteArray = hex("302e020100300506032b657004220420")

    fun size(curve: String): Int = when (curve) {
        "P-256" -> 32
        "P-384" -> 48
        else -> throw IllegalArgumentException("Unsupported EC curve: $curve")
    }

    fun stdName(curve: String): String = when (curve) {
        "P-256" -> "secp256r1"
        "P-384" -> "secp384r1"
        else -> throw IllegalArgumentException("Unsupported EC curve: $curve")
    }

    fun signatureAlgorithm(curve: String): String = when (curve) {
        "P-256" -> "SHA256withECDSAinP1363Format"
        "P-384" -> "SHA384withECDSAinP1363Format"
        else -> "Ed25519"
    }

    fun params(curve: String): ECParameterSpec {
        val p = AlgorithmParameters.getInstance("EC")
        p.init(ECGenParameterSpec(stdName(curve)))
        return p.getParameterSpec(ECParameterSpec::class.java)
    }

    fun curveName(params: ECParameterSpec): String = when (params.curve.field.fieldSize) {
        256 -> "P-256"
        384 -> "P-384"
        else -> throw IllegalArgumentException("Unsupported EC curve")
    }

    /** Whether a point satisfies y² = x³ + ax + b (mod p), with coordinates below p. */
    fun isOnCurve(params: ECParameterSpec, point: ECPoint): Boolean {
        val p = (params.curve.field as ECFieldFp).p
        val x = point.affineX
        val y = point.affineY
        if (x.signum() < 0 || x >= p || y.signum() < 0 || y >= p) return false
        return y.modPow(BigInteger.TWO, p) == rhs(params, x, p)
    }

    private fun rhs(params: ECParameterSpec, x: BigInteger, p: BigInteger): BigInteger =
        x.modPow(BigInteger.valueOf(3), p).add(params.curve.a.multiply(x)).add(params.curve.b).mod(p)

    /** Decompresses a point (`02|03 ‖ x`): x and y, or null when it is not on the curve. */
    fun decompress(curve: String, compressed: ByteArray): Pair<ByteArray, ByteArray>? {
        val size = size(curve)
        if (compressed.size != size + 1 || (compressed[0].toInt() != 2 && compressed[0].toInt() != 3)) return null
        val params = params(curve)
        val p = (params.curve.field as ECFieldFp).p
        val x = BigInteger(1, compressed.copyOfRange(1, compressed.size))
        if (x >= p) return null
        val rhs = rhs(params, x, p)
        // p ≡ 3 (mod 4) for both curves: the square root is rhs^((p+1)/4).
        var y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p)
        if (y.modPow(BigInteger.TWO, p) != rhs) return null
        if (y.testBit(0) != (compressed[0].toInt() == 3)) y = p.subtract(y)
        return compressed.copyOfRange(1, compressed.size) to fixed(y, size)
    }

    /** A non-negative integer as exactly [size] big-endian bytes. */
    fun fixed(v: BigInteger, size: Int): ByteArray {
        val b = v.toByteArray().let { if (it.size > 1 && it[0].toInt() == 0) it.copyOfRange(1, it.size) else it }
        require(b.size <= size) { "Integer too large" }
        return ByteArray(size - b.size) + b
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
}
