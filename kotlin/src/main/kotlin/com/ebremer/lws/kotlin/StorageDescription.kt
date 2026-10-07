// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.internal.JsonAccess
import com.ebremer.lws.kotlin.internal.Urls
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.URI

/**
 * A storage description (`application/lws+cid`): a controlled identifier document listing the storage's
 * services, capabilities and keys.
 *
 * @property id the storage identifier (absolute)
 * @property authentication references (strings) or embedded verification methods
 * @property raw the document
 */
public class StorageDescription(
    public val id: URI,
    public val types: List<String>,
    public val services: List<Service>,
    public val capabilities: List<Capability>,
    public val verificationMethods: List<VerificationMethod>,
    public val authentication: List<JsonElement>,
    public val raw: JsonObject,
) {
    /**
     * The storage root container.
     *
     * @throws ProtocolException when the description has no `StorageRoot` service
     */
    public fun storageRoot(): URI = service(ServiceType.STORAGE_ROOT)?.serviceEndpoint
        ?: throw ProtocolException("The storage description $id has no StorageRoot service")

    /** The first service of a type, or null. */
    public fun service(type: String): Service? = services.firstOrNull { it.hasType(type) }

    /** Every service of a type. */
    public fun services(type: String): List<Service> = services.filter { it.hasType(type) }

    /** The first capability of a type, or null. */
    public fun capability(type: String): Capability? = capabilities.firstOrNull { it.hasType(type) }

    public fun notificationService(): Service? = service(ServiceType.NOTIFICATION)

    public fun accessRequestService(): Service? = service(ServiceType.ACCESS_REQUEST)

    public fun accessGrantService(): Service? = service(ServiceType.ACCESS_GRANT)

    public fun typeIndexService(): Service? = service(ServiceType.TYPE_INDEX)

    public fun typeSearchService(): Service? = service(ServiceType.TYPE_SEARCH)

    public fun hasType(type: String): Boolean = Vocabulary.hasType(types, type)

    /**
     * The verification method whose `id` is [idOrFragment], or resolves to the same URL against the storage
     * identifier (`#key-1`, `key-1` and the full URL are equal).
     */
    public fun verificationMethod(idOrFragment: String): VerificationMethod? = verificationMethods.firstOrNull { v ->
        v.id != null && (v.id == idOrFragment || sameId(v.id, idOrFragment))
    }

    /** Whether a verification method is referenced from `authentication` (by id, or embedded with the same id). */
    public fun isAuthenticationMethod(method: VerificationMethod): Boolean {
        val id = method.id ?: return false
        return authentication.any { a ->
            val ref = when (a) {
                is JsonPrimitive -> a.takeIf { it.isString }?.content
                is JsonObject -> JsonAccess.str(a, "id")
                else -> null
            }
            ref != null && (ref == id || sameId(ref, id))
        }
    }

    private fun sameId(a: String, b: String): Boolean {
        val ra = resolveRef(a)
        return ra != null && ra == resolveRef(b)
    }

    private fun resolveRef(reference: String): String? {
        val r = if (':' !in reference && !reference.startsWith("#") && !reference.startsWith("/")) "#$reference" else reference
        return Urls.resolve(r, id.toString())
    }

    override fun toString(): String = id.toString()

    public companion object {
        /**
         * Parses a description; its `id` resolves against the URL it came from.
         *
         * @throws ProtocolException without an `id`, or when `type` does not include `Storage`
         */
        public fun parse(json: JsonElement, base: URI? = null): StorageDescription {
            val o = JsonAccess.obj(json, "The storage description")
            val idText = JsonAccess.str(o, "id") ?: throw ProtocolException("The storage description has no id")
            val id = Urls.resolve(idText, base?.toString())?.let(Urls::toUri)
                ?: throw ProtocolException("The storage description id is not a URL: $idText")
            val types = JsonAccess.types(o)
            if (!Vocabulary.hasType(types, ResourceType.STORAGE)) {
                throw ProtocolException("The document type [${types.joinToString(", ")}] does not include Storage")
            }
            val services = JsonAccess.objects(o, "service").mapNotNull { s ->
                JsonAccess.url(s, "serviceEndpoint", id)?.let { Service(JsonAccess.url(s, "id", id), JsonAccess.types(s), it, s) }
            }
            val capabilities = JsonAccess.objects(o, "capability").map { Capability(JsonAccess.url(it, "id", id), JsonAccess.types(it), it) }
            val methods = JsonAccess.objects(o, "verificationMethod").map(::VerificationMethod)
            val authentication = when (val auth = o["authentication"]) {
                null, JsonNull -> emptyList()
                is JsonArray -> auth.toList()
                else -> listOf(auth)
            }
            return StorageDescription(id, types, services, capabilities, methods, authentication, o)
        }
    }
}

/**
 * A service of a storage description (`StorageRoot`, `NotificationService`, …), extra members in [raw].
 *
 * @property serviceEndpoint absolute
 */
public class Service(
    public val id: URI?,
    public val types: List<String>,
    public val serviceEndpoint: URI,
    public val raw: JsonObject = JsonObject(emptyMap()),
) {
    public fun hasType(type: String): Boolean = Vocabulary.hasType(types, type)

    /** The `subscriptionType` values of a notification service. */
    public val subscriptionTypes: List<String> get() = JsonAccess.strings(raw, "subscriptionType")

    /** The `conformsTo` values. */
    public val conformsTo: List<String> get() = JsonAccess.strings(raw, "conformsTo")

    /** A member of the service object, or null. */
    public fun property(name: String): JsonElement? = raw[name]

    override fun toString(): String = types.joinToString(",") + " " + serviceEndpoint
}

/** A capability of a storage description, extra members in [raw]. */
public class Capability(public val id: URI?, public val types: List<String>, public val raw: JsonObject = JsonObject(emptyMap())) {
    public fun hasType(type: String): Boolean = Vocabulary.hasType(types, type)

    public fun property(name: String): JsonElement? = raw[name]
}

/** A verification method of a controlled identifier document (`JsonWebKey` with `publicKeyJwk`). */
public class VerificationMethod(public val raw: JsonObject) {
    /** The `id` as written (possibly relative or a bare fragment). */
    public val id: String? = JsonAccess.str(raw, "id")
    public val type: String? = JsonAccess.str(raw, "type")
    public val controller: String? = JsonAccess.str(raw, "controller")
    public val publicKeyJwk: JsonObject? = raw["publicKeyJwk"] as? JsonObject
}
