// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin.notify

import com.ebremer.lws.kotlin.ActivityType
import com.ebremer.lws.kotlin.ProtocolException
import com.ebremer.lws.kotlin.ResourceType
import com.ebremer.lws.kotlin.SubscriptionType
import com.ebremer.lws.kotlin.Vocabulary
import com.ebremer.lws.kotlin.internal.Dates
import com.ebremer.lws.kotlin.internal.JsonAccess
import com.ebremer.lws.kotlin.internal.Urls
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.URI
import java.time.Instant

/**
 * A webhook subscription to create at a notification service.
 *
 * @property topics the resources to watch (absolute URLs)
 * @property inbox the absolute URL deliveries are POSTed to
 * @property expires the requested expiry
 */
public class WebhookSubscriptionRequest(public val topics: List<URI>, public val inbox: URI, public val expires: Instant? = null) {
    init {
        require(topics.isNotEmpty()) { "At least one topic is required" }
        for (u in topics + inbox) require(u.isAbsolute) { "Not an absolute URL: $u" }
    }

    /** The request body. */
    public fun toJson(): JsonObject {
        val o = linkedMapOf<String, JsonElement>(
            "@context" to JsonArray(listOf(JsonPrimitive(Vocabulary.LWS_CONTEXT))),
            "type" to JsonPrimitive(SubscriptionType.WEBHOOK),
            "topic" to JsonArray(topics.map { JsonPrimitive(it.toString()) }),
            "inbox" to JsonPrimitive(inbox.toString()),
        )
        if (expires != null) o["expires"] = JsonPrimitive(Dates.formatRfc3339(expires))
        return JsonObject(o)
    }
}

/**
 * A subscription, as created or retrieved.
 *
 * @property url the subscription resource (its `subscription` member, else the `Location`)
 * @property expiresRaw `expires` as received
 * @property raw the document
 */
public class Subscription(public val url: URI, public val expiresRaw: String?, public val raw: JsonObject) {
    public val types: List<String> = JsonAccess.types(raw)

    /** The first `type` (`WebhookSubscription`). */
    public val type: String? = types.firstOrNull()

    /** When it expires, or null. */
    public val expires: Instant? = Dates.parseRfc3339(expiresRaw)

    override fun toString(): String = url.toString()

    public companion object {
        /**
         * Parses a subscription document; `subscription` resolves against [base], and [location] stands in for it.
         *
         * @throws ProtocolException when there is no subscription URL
         */
        public fun parse(json: JsonElement, base: URI? = null, location: URI? = null): Subscription {
            val o = JsonAccess.obj(json, "The subscription")
            val url = JsonAccess.url(o, "subscription", base) ?: location ?: throw ProtocolException("The subscription response has no subscription URL")
            return Subscription(url, JsonAccess.str(o, "expires"), o)
        }
    }
}

/** The object of an activity: the resource that changed. */
public class ActivityObject(public val id: URI, public val types: List<String> = emptyList(), public val raw: JsonObject = JsonObject(emptyMap())) {
    public val isContainer: Boolean get() = Vocabulary.hasType(types, ResourceType.CONTAINER)

    public val isDataResource: Boolean get() = Vocabulary.hasType(types, ResourceType.DATA_RESOURCE)

    override fun toString(): String = id.toString()
}

/** One activity of a notification: `Create`, `Update` or `Delete` of a resource. */
public class Activity(
    public val id: String?,
    public val types: List<String>,
    public val `object`: ActivityObject,
    public val actor: URI? = null,
    public val target: URI? = null,
    public val origin: URI? = null,
    public val publishedRaw: String? = null,
    public val raw: JsonObject = JsonObject(emptyMap()),
) {
    public val published: Instant? = Dates.parseRfc3339(publishedRaw)

    public val isCreate: Boolean get() = hasType(ActivityType.CREATE)

    public val isUpdate: Boolean get() = hasType(ActivityType.UPDATE)

    public val isDelete: Boolean get() = hasType(ActivityType.DELETE)

    /** Whether the activity has a type (`Update`, `as:Update` and the full Activity Streams IRI are equal). */
    public fun hasType(type: String): Boolean =
        type in types || "as:$type" in types || "${Vocabulary.ACTIVITYSTREAMS_CONTEXT}#$type" in types

    public companion object {
        /**
         * Parses an activity object.
         *
         * @throws ProtocolException without an object with an absolute id
         */
        public fun parse(o: JsonObject): Activity {
            val obj = o["object"] as? JsonObject ?: throw ProtocolException("The activity has no object")
            val id = JsonAccess.str(obj, "id")?.let { Urls.resolve(it, null) }?.let(Urls::toUri)
                ?: throw ProtocolException("The activity object has no valid id")
            return Activity(
                JsonAccess.str(o, "id"), JsonAccess.types(o), ActivityObject(id, JsonAccess.types(obj), obj),
                JsonAccess.url(o, "actor", null), JsonAccess.url(o, "target", null), JsonAccess.url(o, "origin", null),
                JsonAccess.str(o, "published"), o,
            )
        }
    }
}

/**
 * A notification (`type: Notification`): the storage it comes from and its activities (one or several).
 *
 * @property raw the document
 */
public class Notification(public val storage: URI, public val activities: List<Activity>, public val raw: JsonObject = JsonObject(emptyMap())) {
    public companion object {
        /**
         * Parses a notification.
         *
         * @throws ProtocolException when it is not a `Notification` with a storage and activities
         */
        public fun parse(json: JsonElement): Notification {
            val o = JsonAccess.obj(json, "The notification")
            if (!Vocabulary.hasType(JsonAccess.types(o), ResourceType.NOTIFICATION)) throw ProtocolException("The document type is not Notification")
            val storageText = JsonAccess.str(o, "storage") ?: throw ProtocolException("The notification has no storage")
            val storage = Urls.resolve(storageText, null)?.let(Urls::toUri) ?: throw ProtocolException("The notification storage is not an absolute URL")
            val activities = when (val a = o["activity"]) {
                is JsonArray -> a.map { Activity.parse(JsonAccess.obj(it, "An activity")) }
                is JsonObject -> listOf(Activity.parse(a))
                else -> throw ProtocolException("The notification has no activity")
            }
            return Notification(storage, activities, o)
        }

        /**
         * Parses a notification from its body (UTF-8 JSON).
         *
         * @throws ProtocolException when it is not JSON or not a notification
         */
        public fun parse(body: ByteArray): Notification = parse(JsonAccess.parse(body, "The notification"))

        /** Parses a notification from its JSON text. */
        public fun parse(text: String): Notification = parse(text.toByteArray(Charsets.UTF_8))
    }
}

/**
 * A notification whose signature verified.
 *
 * @property keyId the `keyid` of the signature (a verification method of the storage)
 * @property storage the storage identifier
 * @property label the signature label used (`sig1`)
 * @property algorithm the signature algorithm (`ecdsa-p256-sha256`, `ed25519`, `ecdsa-p384-sha384`)
 */
public class VerifiedNotification(
    public val notification: Notification,
    public val keyId: String,
    public val storage: URI,
    public val label: String = "",
    public val algorithm: String = "",
)
