// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin.access

import com.ebremer.lws.kotlin.ConstraintOperand
import com.ebremer.lws.kotlin.ConstraintOperator
import com.ebremer.lws.kotlin.ProtocolException
import com.ebremer.lws.kotlin.ResourceType
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
 * A constraint of an access policy (ODRL): `leftOperand operator rightOperand`, such as `purpose eq <uri>`.
 *
 * @property rightOperand a JSON value: a string, a list of strings, …
 */
public class Constraint(public val leftOperand: String, public val operator: String, public val rightOperand: JsonElement) {
    public fun toJson(): JsonObject = JsonObject(
        linkedMapOf("leftOperand" to JsonPrimitive(leftOperand), "operator" to JsonPrimitive(operator), "rightOperand" to rightOperand),
    )

    override fun equals(other: Any?): Boolean =
        other is Constraint && other.leftOperand == leftOperand && other.operator == operator && other.rightOperand == rightOperand

    override fun hashCode(): Int = toJson().hashCode()

    override fun toString(): String = "$leftOperand $operator $rightOperand"

    public companion object {
        /** Use for one purpose. */
        public fun purpose(purpose: String): Constraint = Constraint(ConstraintOperand.PURPOSE, ConstraintOperator.EQ, JsonPrimitive(purpose))

        /** Use for any of several purposes. */
        public fun purposeAnyOf(vararg purposes: String): Constraint = anyOf(ConstraintOperand.PURPOSE, purposes)

        /** Use by one client application. */
        public fun client(clientId: String): Constraint = Constraint(ConstraintOperand.CLIENT, ConstraintOperator.EQ, JsonPrimitive(clientId))

        /** Resources of one media type. */
        public fun format(mediaType: String): Constraint = Constraint(ConstraintOperand.FORMAT, ConstraintOperator.EQ, JsonPrimitive(mediaType))

        /** Resources of any of several media types. */
        public fun formatAnyOf(vararg mediaTypes: String): Constraint = anyOf(ConstraintOperand.FORMAT, mediaTypes)

        /** Resources of one type. */
        public fun type(type: String): Constraint = Constraint(ConstraintOperand.TYPE, ConstraintOperator.EQ, JsonPrimitive(type))

        /** Resources of any of several types. */
        public fun typeAnyOf(vararg types: String): Constraint = anyOf(ConstraintOperand.TYPE, types)

        /** Not before an instant (`dateTime gteq`). */
        public fun notBefore(instant: Instant): Constraint = dateTime(ConstraintOperator.GTEQ, Dates.formatRfc3339(instant))

        /** Not before an RFC 3339 date-time, kept as written. */
        public fun notBefore(dateTime: String): Constraint = dateTime(ConstraintOperator.GTEQ, checked(dateTime))

        /** Not after an instant (`dateTime lteq`). */
        public fun notAfter(instant: Instant): Constraint = dateTime(ConstraintOperator.LTEQ, Dates.formatRfc3339(instant))

        /** Not after an RFC 3339 date-time, kept as written. */
        public fun notAfter(dateTime: String): Constraint = dateTime(ConstraintOperator.LTEQ, checked(dateTime))

        private fun anyOf(operand: String, values: Array<out String>) =
            Constraint(operand, ConstraintOperator.IS_ANY_OF, JsonArray(values.map(::JsonPrimitive)))

        private fun dateTime(operator: String, value: String) = Constraint(ConstraintOperand.DATE_TIME, operator, JsonPrimitive(value))

        private fun checked(dateTime: String): String {
            require(Dates.parseRfc3339(dateTime) != null) { "Not an RFC 3339 date-time: $dateTime" }
            return dateTime
        }

        internal fun parse(json: JsonElement): Constraint {
            val o = json as? JsonObject ?: JsonObject(emptyMap())
            val left = JsonAccess.str(o, "leftOperand")
            val op = JsonAccess.str(o, "operator")
            val right = o["rightOperand"]
            if (left == null || op == null || right == null) throw ProtocolException("Incomplete constraint")
            return Constraint(left, op, right)
        }
    }
}

/**
 * The resources an access policy is about.
 *
 * @property type `StorageResource`, `Container` or `DataResource`
 * @property values the resources
 */
public class AccessTarget(public val type: String, public val values: List<String>) {
    init {
        require(values.isNotEmpty()) { "An access target needs at least one value" }
    }

    public fun toJson(): JsonObject =
        JsonObject(linkedMapOf("type" to JsonPrimitive(type), "value" to JsonArray(values.map(::JsonPrimitive))))

    public companion object {
        public fun storageResources(vararg resources: String): AccessTarget = AccessTarget("StorageResource", resources.asList())

        public fun containers(vararg resources: String): AccessTarget = AccessTarget("Container", resources.asList())

        public fun dataResources(vararg resources: String): AccessTarget = AccessTarget("DataResource", resources.asList())

        internal fun parse(o: JsonObject): AccessTarget = AccessTarget(JsonAccess.str(o, "type") ?: "StorageResource", JsonAccess.strings(o, "value"))
    }
}

/**
 * An access policy: who ([assignee]) may do what ([actions]) to which resources ([target]), under [constraints].
 *
 * @property actions `read`, `modify`, `create`, `delete` (see [com.ebremer.lws.kotlin.AccessAction])
 * @property assignee the agent (an absolute IRI)
 * @throws IllegalArgumentException without actions, or with an assignee that is not an absolute IRI
 */
public class AccessPolicy(
    public val actions: List<String>,
    public val assignee: String,
    public val target: AccessTarget? = null,
    public val constraints: List<Constraint> = emptyList(),
    public val types: List<String> = listOf(ResourceType.ACCESS_POLICY),
) {
    init {
        require(actions.isNotEmpty()) { "An access policy needs at least one action" }
        require(Urls.hasScheme(assignee)) { "The assignee must be an absolute IRI: $assignee" }
    }

    public fun toJson(): JsonObject {
        val o = linkedMapOf<String, JsonElement>(
            "type" to JsonArray(types.map(::JsonPrimitive)),
            "action" to JsonArray(actions.map(::JsonPrimitive)),
            "assignee" to JsonPrimitive(assignee),
        )
        if (target != null) o["target"] = target.toJson()
        if (constraints.isNotEmpty()) o["constraint"] = JsonArray(constraints.map { it.toJson() })
        return JsonObject(o)
    }

    internal companion object {
        fun parse(json: JsonElement): AccessPolicy {
            val o = JsonAccess.obj(json, "The access policy")
            val assignee = JsonAccess.str(o, "assignee") ?: throw ProtocolException("The access policy has no assignee")
            val constraints = (o["constraint"] as? JsonArray)?.map(Constraint::parse) ?: emptyList()
            val target = (o["target"] as? JsonObject)?.let(AccessTarget::parse)
            return try {
                AccessPolicy(JsonAccess.strings(o, "action"), assignee, target, constraints, JsonAccess.types(o))
            } catch (e: IllegalArgumentException) {
                throw ProtocolException(e.message ?: "Invalid access policy", e)
            }
        }
    }
}

/**
 * An access request or grant (`application/lws+json`, ODRL-based access profile).
 *
 * @property storage the storage (absolute)
 * @property access at least one policy
 * @property inbox where to send the answer
 * @property types the document types (`AccessRequest` or `AccessGrant` by default)
 * @property raw the document as received (null for one built here)
 */
public sealed class AccessDocument(
    public val storage: URI,
    public val access: List<AccessPolicy>,
    public val inbox: URI?,
    types: List<String>,
    public val raw: JsonObject?,
    documentType: String,
) {
    public val types: List<String> = types.ifEmpty { listOf(documentType) }

    init {
        require(access.isNotEmpty()) { "At least one access policy is required" }
        require(storage.isAbsolute) { "Not an absolute URL: $storage" }
        require(inbox == null || inbox.isAbsolute) { "Not an absolute URL: $inbox" }
    }

    /** The document, built from the fields (see [raw] for the one received). */
    public fun toJson(): JsonObject {
        val o = linkedMapOf<String, JsonElement>(
            "@context" to JsonArray(listOf(JsonPrimitive(Vocabulary.LWS_CONTEXT))),
            "type" to JsonArray(types.map(::JsonPrimitive)),
        )
        if (inbox != null) o["inbox"] = JsonPrimitive(inbox.toString())
        o["storage"] = JsonPrimitive(storage.toString())
        o["access"] = JsonArray(access.map { it.toJson() })
        return JsonObject(o)
    }

    /** The document as received, else as built. */
    public fun document(): JsonObject = raw ?: toJson()

    override fun toString(): String = JsonAccess.encode(document())

    internal class Parsed(val storage: URI, val access: List<AccessPolicy>, val inbox: URI?, val types: List<String>, val raw: JsonObject)

    internal companion object {
        fun parse(json: JsonElement, documentType: String): Parsed {
            val what = "The $documentType"
            val o = JsonAccess.obj(json, what)
            val types = JsonAccess.types(o)
            if (!Vocabulary.hasType(types, documentType)) {
                throw ProtocolException("The document type [${types.joinToString(", ")}] does not include $documentType")
            }
            val storageText = JsonAccess.str(o, "storage") ?: throw ProtocolException("$what has no storage")
            val storage = Urls.resolve(storageText, null)?.let(Urls::toUri) ?: throw ProtocolException("$what storage is not an absolute URL")
            val inbox = JsonAccess.str(o, "inbox")?.let { Urls.resolve(it, null)?.let(Urls::toUri) ?: throw ProtocolException("$what inbox is not an absolute URL") }
            val policies = when (val a = o["access"]) {
                is JsonArray -> a.map(AccessPolicy::parse)
                is JsonObject -> listOf(AccessPolicy.parse(a))
                else -> emptyList()
            }
            if (policies.isEmpty()) throw ProtocolException("$what has no access")
            return Parsed(storage, policies, inbox, types, o)
        }

        fun text(json: String, documentType: String): JsonElement = JsonAccess.parse(json.toByteArray(Charsets.UTF_8), "The $documentType")
    }
}

/**
 * An access request: what an agent asks a storage's controller for.
 *
 * ```kotlin
 * val request = AccessRequest(
 *     storage = URI("https://storage.example/"),
 *     access = listOf(AccessPolicy(listOf(AccessAction.READ), me.agent, AccessTarget.containers("https://storage.example/photos/"))),
 * )
 * val location = client.requestAccess(storage.accessRequestService()!!.serviceEndpoint, request)
 * ```
 */
public class AccessRequest(
    storage: URI,
    access: List<AccessPolicy>,
    inbox: URI? = null,
    types: List<String> = emptyList(),
    raw: JsonObject? = null,
) : AccessDocument(storage, access, inbox, types, raw, ResourceType.ACCESS_REQUEST) {
    public companion object {
        /**
         * Parses an access request; [raw] keeps it as received.
         *
         * @throws ProtocolException when it is not a valid access request
         */
        public fun parse(json: JsonElement): AccessRequest =
            AccessDocument.parse(json, ResourceType.ACCESS_REQUEST).let { AccessRequest(it.storage, it.access, it.inbox, it.types, it.raw) }

        /** Parses an access request from its JSON text. */
        public fun parse(json: String): AccessRequest = parse(AccessDocument.text(json, ResourceType.ACCESS_REQUEST))
    }
}

/** An access grant: the access a storage's controller gives an agent. */
public class AccessGrant(
    storage: URI,
    access: List<AccessPolicy>,
    inbox: URI? = null,
    types: List<String> = emptyList(),
    raw: JsonObject? = null,
) : AccessDocument(storage, access, inbox, types, raw, ResourceType.ACCESS_GRANT) {
    public companion object {
        /**
         * Parses an access grant; [raw] keeps it as received.
         *
         * @throws ProtocolException when it is not a valid access grant
         */
        public fun parse(json: JsonElement): AccessGrant =
            AccessDocument.parse(json, ResourceType.ACCESS_GRANT).let { AccessGrant(it.storage, it.access, it.inbox, it.types, it.raw) }

        /** Parses an access grant from its JSON text. */
        public fun parse(json: String): AccessGrant = parse(AccessDocument.text(json, ResourceType.ACCESS_GRANT))
    }
}
