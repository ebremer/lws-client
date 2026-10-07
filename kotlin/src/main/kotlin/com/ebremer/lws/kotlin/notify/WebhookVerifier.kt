// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin.notify

import com.ebremer.lws.kotlin.LwsClient
import com.ebremer.lws.kotlin.LwsException
import com.ebremer.lws.kotlin.ProtocolException
import com.ebremer.lws.kotlin.SignatureVerificationException
import com.ebremer.lws.kotlin.StorageDescription
import com.ebremer.lws.kotlin.auth.VerificationKey
import com.ebremer.lws.kotlin.http.Headers
import com.ebremer.lws.kotlin.http.SfBytes
import com.ebremer.lws.kotlin.http.SfInnerList
import com.ebremer.lws.kotlin.http.SfInteger
import com.ebremer.lws.kotlin.http.SfItem
import com.ebremer.lws.kotlin.http.SfMember
import com.ebremer.lws.kotlin.http.SfString
import com.ebremer.lws.kotlin.http.StructuredFieldException
import com.ebremer.lws.kotlin.http.StructuredFields
import com.ebremer.lws.kotlin.internal.Urls
import com.sun.net.httpserver.HttpExchange
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URI
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

/**
 * Verifies signed webhook deliveries (RFC 9421 HTTP Message Signatures with an RFC 9530 `Content-Digest`): the
 * digest of the body, a signature covering `@method`, `@scheme`, `@authority`, `@path`, `content-type` and
 * `content-digest`, its age, the key from the storage description of the `keyid`'s storage (which must list it under
 * `authentication`), and that the notification comes from that storage.
 *
 * ```kotlin
 * val verifier = WebhookVerifier(client, trustedStorages = listOf(URI("https://storage.example/")))
 * val verified = verifier.verify("POST", inboxUrl, headers, body)
 * verified.notification.activities.forEach { println("${it.types} ${it.`object`.id}") }
 * ```
 *
 * Storage descriptions are cached for [keyCacheTtl]; when a signature fails with a cached key, the description is
 * fetched again once (the storage may have rotated its key).
 *
 * @param client the client that retrieves storage descriptions (default: an anonymous one)
 * @param storageDescriptionResolver retrieves a storage description instead of [client]
 * @param trustedStorages accept deliveries from these storages only (compared as URLs); an empty list trusts none,
 *     null trusts any
 * @param maxAge the oldest acceptable signature
 * @param clockSkew how far in the future a signature may be created
 * @param keyCacheTtl how long storage descriptions are cached
 * @param clock the clock (for tests)
 */
public class WebhookVerifier(
    client: LwsClient? = null,
    storageDescriptionResolver: (suspend (URI) -> StorageDescription)? = null,
    trustedStorages: List<URI>? = null,
    private val maxAge: Duration = 300.seconds,
    private val clockSkew: Duration = 300.seconds,
    private val keyCacheTtl: Duration = 10.minutes,
    private val clock: Clock = Clock.systemUTC(),
) {
    private val descriptions: suspend (URI) -> StorageDescription = storageDescriptionResolver
        ?: (client ?: LwsClient()).let { c -> { url: URI -> c.getStorageDescription(url) } }
    private val trusted: Set<String>? = trustedStorages?.map { Urls.canonical(it.toString()) }?.toSet()
    private val cache = ConcurrentHashMap<String, Pair<StorageDescription, Instant>>()

    /**
     * Verifies a delivery.
     *
     * @param method the request method
     * @param url the inbox URL as registered
     * @param headers the request headers
     * @param body the raw body bytes
     * @throws SignatureVerificationException when the delivery does not verify
     * @throws IllegalArgumentException when the inbox URL is not absolute
     */
    public suspend fun verify(method: String, url: URI, headers: Headers, body: ByteArray): VerifiedNotification {
        val inbox = url.toString()
        require(Urls.isHttp(inbox)) { "The inbox URL must be an absolute http(s) URL: $url" }
        checkDigest(field(headers, "content-digest"), body)
        val inputs = dictionary(field(headers, "signature-input"), "Signature-Input")
        val signatures = dictionary(field(headers, "signature"), "Signature")
        val (label, covered) = inputs.entries.firstNotNullOfOrNull { (key, member) ->
            if (member is SfInnerList && member.params["keyid"] is SfString && key in signatures) key to member else null
        } ?: throw fail("No signature with a keyid in Signature-Input and Signature")
        val sigItem = signatures[label]
        val signature = ((sigItem as? SfItem)?.value as? SfBytes)?.bytes ?: throw fail("Signature $label is not a byte sequence")
        val components = mutableSetOf<String>()
        for (item in covered.items) {
            val name = (item.value as? SfString)?.value ?: throw fail("A covered component is not a string")
            if (item.params.isNotEmpty()) throw fail("Unsupported component parameters on $name")
            if (!components.add(name)) throw fail("Duplicate covered component $name")
        }
        for (r in REQUIRED_COMPONENTS) if (r !in components) throw fail("Required component not covered: $r")
        val params = covered.params
        val created = (params["created"] as? SfInteger)?.value ?: throw fail("The signature parameters lack an integer 'created'")
        val now = clock.instant().epochSecond
        if (created < now - maxAge.inWholeSeconds) throw fail("Signature too old (created $created)")
        if (created > now + clockSkew.inWholeSeconds) throw fail("Signature created in the future (created $created)")
        if ("expires" in params) {
            val expires = (params["expires"] as? SfInteger)?.value
            if (expires == null || expires < now) throw fail("Signature expired")
        }
        val keyid = (params["keyid"] as? SfString)?.value ?: throw fail("The signature has no keyid")
        val alg = (params["alg"] as? SfString)?.value
        val hash = keyid.indexOf('#')
        if (hash <= 0 || hash == keyid.length - 1) throw fail("keyid is not a URL with a fragment: $keyid")
        val storageText = keyid.substring(0, hash)
        val storageId = Urls.toUri(storageText)?.takeIf { Urls.isHttp(storageText) } ?: throw fail("keyid is not an absolute http(s) URL: $keyid")
        if (trusted != null && Urls.canonical(storageText) !in trusted) throw fail("Storage $storageText is not trusted")
        val base = signatureBase(method, url, headers, covered).toByteArray(Charsets.UTF_8)
        val cacheKey = Urls.canonical(storageText)
        val cached = cache[cacheKey]
        val algorithm = if (cached != null && cached.second.plus(keyCacheTtl.toJavaDuration()) > clock.instant()) {
            try {
                verifyWith(cached.first, storageText, keyid, alg, base, signature)
            } catch (_: SignatureVerificationException) {
                // The key may have rotated: fetch the description again, once.
                verifyWith(fetch(storageId), storageText, keyid, alg, base, signature)
            }
        } else {
            verifyWith(fetch(storageId), storageText, keyid, alg, base, signature)
        }
        val notification = try {
            Notification.parse(body)
        } catch (e: ProtocolException) {
            throw fail("The signed body is not a valid notification: ${e.message}")
        }
        if (Urls.canonical(notification.storage.toString()) != Urls.canonical(storageText)) {
            throw fail("Notification storage ${notification.storage} does not match the signing storage $storageText")
        }
        return VerifiedNotification(notification, keyid, storageId, label, algorithm)
    }

    /** Verifies a delivery whose headers are a map of name to values, as HTTP stacks report them. */
    public suspend fun verify(method: String, url: URI, headers: Map<String, List<String>>, body: ByteArray): VerifiedNotification =
        verify(method, url, Headers.ofLists(headers), body)

    /**
     * Verifies a delivery received by the JDK's built-in server (`com.sun.net.httpserver`), reading its body.
     * [inboxUrl] is the inbox URL as registered (needed behind proxies; the request's own URL otherwise).
     *
     * @throws SignatureVerificationException when the delivery does not verify
     */
    public suspend fun verifyExchange(exchange: HttpExchange, inboxUrl: URI): VerifiedNotification {
        val body = withContext(Dispatchers.IO) { exchange.requestBody.use { it.readAllBytes() } }
        return verify(exchange.requestMethod, inboxUrl, exchange.requestHeaders, body)
    }

    private suspend fun fetch(storageId: URI): StorageDescription {
        val description = try {
            descriptions(storageId)
        } catch (e: LwsException) {
            throw fail("Cannot retrieve the storage description $storageId: ${e.message}")
        }
        cache[Urls.canonical(storageId.toString())] = description to clock.instant()
        return description
    }

    public companion object {
        /** The components a signature must cover. */
        public val REQUIRED_COMPONENTS: List<String> = listOf("@method", "@scheme", "@authority", "@path", "content-type", "content-digest")

        /**
         * The RFC 9421 signature base of a request for the covered components.
         *
         * @throws SignatureVerificationException for an unsupported or missing component
         */
        public fun signatureBase(method: String, url: URI, headers: Headers, covered: SfInnerList): String {
            val s = StringBuilder()
            for (item in covered.items) {
                val name = (item.value as? SfString)?.value ?: throw fail("A covered component is not a string")
                val quoted = try {
                    StructuredFields.serializeBareItem(item.value)
                } catch (_: StructuredFieldException) {
                    "\"$name\""
                }
                s.append(quoted).append(": ").append(componentValue(name, method, url.toString(), headers)).append('\n')
            }
            return try {
                s.append("\"@signature-params\": ").append(StructuredFields.serializeInnerList(covered)).toString()
            } catch (e: StructuredFieldException) {
                throw fail("The signature parameters cannot be serialized: ${e.message}")
            }
        }

        private fun componentValue(name: String, method: String, url: String, headers: Headers): String = when (name) {
            "@method" -> method.uppercase()
            "@scheme" -> Urls.scheme(url)
            "@authority" -> {
                val host = Urls.host(url)
                val h = if (':' in host) "[$host]" else host
                val port = Urls.port(url)
                if (port == null || port == (if (Urls.scheme(url) == "https") 443 else 80)) h else "$h:$port"
            }
            "@path" -> Urls.path(url)
            "@query" -> Urls.query(url).ifEmpty { "?" }
            "@target-uri" -> Urls.withoutFragment(url)
            "@request-target" -> Urls.path(url) + Urls.query(url)
            else -> {
                if (name.startsWith("@")) throw fail("Unsupported derived component $name")
                val values = headers.all(name)
                if (values.isEmpty()) throw fail("Covered header field missing: $name")
                values.joinToString(", ") { it.trim(' ', '\t') }
            }
        }

        private fun verifyWith(description: StorageDescription, storageId: String, keyid: String, alg: String?, base: ByteArray, signature: ByteArray): String {
            if (Urls.canonical(description.id.toString()) != Urls.canonical(storageId)) {
                throw fail("Storage description id ${description.id} does not match the keyid storage $storageId")
            }
            val method = description.verificationMethod(keyid) ?: throw fail("Verification method $keyid not found in the storage description")
            if (!description.isAuthenticationMethod(method)) throw fail("Verification method $keyid is not referenced from authentication")
            val jwk = method.publicKeyJwk ?: throw fail("Verification method $keyid has no publicKeyJwk")
            val key = try {
                VerificationKey.fromJwk(jwk)
            } catch (e: IllegalArgumentException) {
                throw fail("Unusable verification key $keyid: ${e.message}")
            }
            val keyAlgorithm = when (key.curve) {
                "P-256" -> "ecdsa-p256-sha256"
                "P-384" -> "ecdsa-p384-sha384"
                else -> "ed25519"
            }
            if (alg != null && alg != keyAlgorithm) throw fail("alg $alg does not match the key type ($keyAlgorithm)")
            if (!key.verify(signature, base)) throw fail("The signature does not verify")
            return keyAlgorithm
        }

        private fun checkDigest(header: String, body: ByteArray) {
            val digests = dictionary(header, "Content-Digest")
            var any = false
            for ((name, algo) in listOf("sha-256" to "SHA-256", "sha-512" to "SHA-512")) {
                val member = digests[name] ?: continue
                any = true
                val expected = ((member as? SfItem)?.value as? SfBytes)?.bytes ?: throw fail("Malformed $name digest")
                if (!MessageDigest.isEqual(MessageDigest.getInstance(algo).digest(body), expected)) throw fail("Content-Digest $name mismatch")
            }
            if (!any) throw fail("Content-Digest has no supported algorithm (sha-256, sha-512)")
        }

        private fun field(headers: Headers, name: String): String {
            val values = headers.all(name)
            if (values.isEmpty()) throw fail("Missing $name header")
            return values.joinToString(", ")
        }

        private fun dictionary(value: String, what: String): Map<String, SfMember> = try {
            StructuredFields.parseDictionary(value)
        } catch (e: StructuredFieldException) {
            throw fail("Malformed $what: ${e.message}")
        }

        private fun fail(message: String) = SignatureVerificationException(message)
    }
}
