// SPDX-License-Identifier: MIT
//
// The Kotlin adapter of the lws-client driver.
//
// Runs the operations of driver/PROTOCOL.md with the LwsClient of lws-client for Kotlin (../../../kotlin), speaking the
// line-delimited JSON protocol lws-driver/1 on stdin and stdout:
//
//   java -jar driver/adapters/kotlin/build/libs/lws-driver-adapter-kotlin.jar
//
// The adapter is a thin wrapper: it calls the library's operations with the library's options and reports the
// library's results and errors, without retrying or fixing anything up.
package com.ebremer.lws.driver.adapter

import com.ebremer.lws.kotlin.AuthenticationException
import com.ebremer.lws.kotlin.BadRequestException
import com.ebremer.lws.kotlin.ByteRange
import com.ebremer.lws.kotlin.ConflictException
import com.ebremer.lws.kotlin.ContainedResource
import com.ebremer.lws.kotlin.ContainerPage
import com.ebremer.lws.kotlin.CreateResult
import com.ebremer.lws.kotlin.ForbiddenException
import com.ebremer.lws.kotlin.GoneException
import com.ebremer.lws.kotlin.HttpException
import com.ebremer.lws.kotlin.InsufficientStorageException
import com.ebremer.lws.kotlin.Linkset
import com.ebremer.lws.kotlin.LwsClient
import com.ebremer.lws.kotlin.MethodNotAllowedException
import com.ebremer.lws.kotlin.NotAcceptableException
import com.ebremer.lws.kotlin.NotFoundException
import com.ebremer.lws.kotlin.NotImplementedException
import com.ebremer.lws.kotlin.PreconditionFailedException
import com.ebremer.lws.kotlin.ProtocolException
import com.ebremer.lws.kotlin.Resource
import com.ebremer.lws.kotlin.ResourceMetadata
import com.ebremer.lws.kotlin.Service
import com.ebremer.lws.kotlin.SignatureVerificationException
import com.ebremer.lws.kotlin.StorageDescription
import com.ebremer.lws.kotlin.TransportException
import com.ebremer.lws.kotlin.TypeQuery
import com.ebremer.lws.kotlin.UnauthorizedException
import com.ebremer.lws.kotlin.UnprocessableContentException
import com.ebremer.lws.kotlin.UnsupportedMediaTypeException
import com.ebremer.lws.kotlin.UpdateResult
import com.ebremer.lws.kotlin.access.AccessGrant
import com.ebremer.lws.kotlin.access.AccessRequest
import com.ebremer.lws.kotlin.auth.Authenticator
import com.ebremer.lws.kotlin.auth.BearerTokenAuthenticator
import com.ebremer.lws.kotlin.auth.CredentialProvider
import com.ebremer.lws.kotlin.auth.OpenIdCredentials
import com.ebremer.lws.kotlin.auth.SelfSignedCredentials
import com.ebremer.lws.kotlin.auth.SigningKey
import com.ebremer.lws.kotlin.auth.TokenExchangeAuthenticator
import com.ebremer.lws.kotlin.http.Headers
import com.ebremer.lws.kotlin.http.Link
import com.ebremer.lws.kotlin.http.ProblemDetails
import com.ebremer.lws.kotlin.json.JsonPatch
import com.ebremer.lws.kotlin.notify.Subscription
import com.ebremer.lws.kotlin.notify.WebhookSubscriptionRequest
import com.ebremer.lws.kotlin.notify.WebhookVerifier
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.FileDescriptor
import java.io.FileOutputStream
import java.io.PrintStream
import java.net.URI
import java.net.URISyntaxException
import java.time.Instant
import java.time.OffsetDateTime
import java.time.format.DateTimeParseException
import java.util.Base64
import kotlin.math.floor
import kotlin.system.exitProcess
import kotlin.time.Duration.Companion.seconds

const val PROTOCOL: String = "lws-driver/1"
const val LANGUAGE: String = "kotlin"
val LIBRARY: String = LwsClient.DEFAULT_USER_AGENT

/** An error the adapter reports itself: `InvalidArguments` or `Unsupported`. */
class AdapterError(val kind: String, message: String) : RuntimeException(message) {
    companion object {
        fun invalid(message: String) = AdapterError("InvalidArguments", message)
    }
}

// ---------------------------------------------------------------------------------------------
// Arguments

/** The arguments of a request: a JSON object's members (a JSON null counts as absent). */
class Args(private val members: JsonObject) {
    fun raw(name: String): JsonElement? = members[name]?.takeIf { it != JsonNull }

    fun has(name: String): Boolean = raw(name) != null

    fun str(name: String): String = optStr(name) ?: throw AdapterError.invalid("missing argument '$name'")

    fun optStr(name: String): String? {
        val v = raw(name) ?: return null
        if (v !is JsonPrimitive || !v.isString) throw AdapterError.invalid("argument '$name' must be a string")
        return v.content
    }

    /** A request target: an absolute URL. A relative one is malformed (PROTOCOL.md section 3). */
    fun url(name: String): URI {
        val v = str(name)
        if (!Regex("^[A-Za-z][A-Za-z0-9+.\\-]*:").containsMatchIn(v)) throw AdapterError.invalid("argument '$name' must be an absolute URL, not '$v'")
        return uri(v, name)
    }

    fun optBool(name: String): Boolean? {
        val v = raw(name) ?: return null
        if (v !is JsonPrimitive || v.isString || (v.content != "true" && v.content != "false")) throw AdapterError.invalid("argument '$name' must be a boolean")
        return v.content == "true"
    }

    /** An integer of at least [minimum]; a JSON number without a fraction (`2.0`) counts. */
    fun optInt(name: String, minimum: Long = 0): Long? {
        val v = raw(name) ?: return null
        val n = (v as? JsonPrimitive)?.takeIf { !it.isString }?.content?.let { c ->
            c.toLongOrNull() ?: c.toDoubleOrNull()?.takeIf { floor(it) == it && kotlin.math.abs(it) < 9.0e18 }?.toLong()
        }
        if (n == null || n < minimum) {
            throw AdapterError.invalid("argument '$name' must be " + if (minimum == 0L) "a non-negative integer" else "an integer of at least $minimum")
        }
        return n
    }

    fun obj(name: String): JsonObject = optObj(name) ?: throw AdapterError.invalid("missing argument '$name'")

    fun optObj(name: String): JsonObject? {
        val v = raw(name) ?: return null
        return v as? JsonObject ?: throw AdapterError.invalid("argument '$name' must be an object")
    }

    fun optList(name: String): JsonArray? {
        val v = raw(name) ?: return null
        return v as? JsonArray ?: throw AdapterError.invalid("argument '$name' must be an array")
    }

    fun optStrings(name: String): List<String>? = optList(name)?.map { e ->
        (e as? JsonPrimitive)?.takeIf { it.isString }?.content ?: throw AdapterError.invalid("argument '$name' must be an array of strings")
    }

    fun strings(name: String): List<String> = optStrings(name) ?: throw AdapterError.invalid("missing argument '$name'")

    fun limit(): Int = minOf(optInt("limit") ?: 1000, Int.MAX_VALUE - 1L).toInt()

    companion object {
        fun of(value: JsonElement?, what: String): Args = when (value) {
            null, JsonNull -> Args(JsonObject(emptyMap()))
            is JsonObject -> Args(value)
            else -> throw AdapterError.invalid("$what must be an object")
        }
    }
}

fun uri(value: String, name: String): URI = try {
    URI(value)
} catch (e: URISyntaxException) {
    throw AdapterError.invalid("argument '$name' is not a URI: ${e.message}")
}

/** A `body` argument as bytes, with the content type it implies. */
fun bodyOf(body: JsonElement?, contentType: String?): Pair<ByteArray, String> {
    if (body == null) return ByteArray(0) to (contentType ?: "application/octet-stream")
    val b = Args.of(body, "argument 'body'")
    b.raw("text")?.let { t ->
        if (t is JsonPrimitive && t.isString) return t.content.toByteArray(Charsets.UTF_8) to (contentType ?: "text/plain")
    }
    b.raw("base64")?.let { t ->
        if (t is JsonPrimitive && t.isString) return base64(t.content, "body") to (contentType ?: "application/octet-stream")
    }
    if ("json" in (body as JsonObject)) return Json.encodeToString(JsonElement.serializer(), body["json"]!!).toByteArray(Charsets.UTF_8) to (contentType ?: "application/json")
    throw AdapterError.invalid("argument 'body' must have text, base64 or json")
}

/** Standard base64, padded, decoded strictly. */
fun base64(text: String, name: String): ByteArray {
    if (!Regex("^[A-Za-z0-9+/]*={0,2}$").matches(text) || text.length % 4 != 0) throw AdapterError.invalid("argument '$name': invalid base64")
    return try {
        Base64.getDecoder().decode(text)
    } catch (_: IllegalArgumentException) {
        throw AdapterError.invalid("argument '$name': invalid base64")
    }
}

/** Rebuilds an RFC 6902 operations array with the library's JsonPatch builder. */
fun patchOf(operations: JsonElement?): JsonPatch {
    val ops = operations as? JsonArray ?: throw AdapterError.invalid("argument 'patch' must be an array of operations")
    val patch = JsonPatch()
    for (raw in ops) {
        val op = raw as? JsonObject
        val name = (op?.get("op") as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: throw AdapterError.invalid("a patch operation must be an object with an op")
        fun pointer(member: String): String =
            (op[member] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: throw AdapterError.invalid("a '$name' patch operation needs a string '$member'")
        fun value(): JsonElement = op["value"] ?: throw AdapterError.invalid("a '$name' patch operation needs a 'value'")
        when (name) {
            "add" -> patch.add(pointer("path"), value())
            "remove" -> patch.remove(pointer("path"))
            "replace" -> patch.replace(pointer("path"), value())
            "move" -> patch.move(pointer("from"), pointer("path"))
            "copy" -> patch.copy(pointer("from"), pointer("path"))
            "test" -> patch.test(pointer("path"), value())
            else -> throw AdapterError.invalid("unknown patch operation '$name'")
        }
    }
    return patch
}

/** Rebuilds an application/lws-query+json document with the library's TypeQuery builder. */
fun queryOf(query: JsonObject): TypeQuery {
    val q = TypeQuery()
    for ((key, groups) in query) {
        if (groups !is JsonArray) throw AdapterError.invalid("query member '$key' must be a list of groups")
        try {
            val clause = q.relation(key)
            for (g in groups) {
                when {
                    g is JsonPrimitive && g.isString -> clause.allOf(g.content)
                    g is JsonArray && g.all { it is JsonPrimitive && it.isString } -> clause.anyOf(*g.map { (it as JsonPrimitive).content }.toTypedArray())
                    else -> throw AdapterError.invalid("a group of query member '$key' must be an IRI or a list of IRIs")
                }
            }
        } catch (e: IllegalArgumentException) {
            throw AdapterError.invalid("query member '$key': ${e.message}")
        }
    }
    return q
}

fun linksOf(links: JsonArray?): List<Link> = links?.map { l ->
    val m = l as? JsonObject
    val href = (m?.get("href") as? JsonPrimitive)?.takeIf { it.isString }?.content
    val rel = (m?.get("rel") as? JsonPrimitive)?.takeIf { it.isString }?.content
    if (href == null || rel == null) throw AdapterError.invalid("argument 'links' must be an array of {href, rel} objects")
    Link(uri(href, "links"), rel)
} ?: emptyList()

/** The headers of a notification delivery: name → list of values (or a single value). */
fun headersOf(headers: JsonObject): Headers = Headers.of(
    headers.entries.flatMap { (name, values) ->
        val list = when (values) {
            is JsonPrimitive -> listOf(values)
            is JsonArray -> values.toList()
            else -> emptyList()
        }
        if (values !is JsonPrimitive && values !is JsonArray || list.any { it !is JsonPrimitive || !it.isString }) {
            throw AdapterError.invalid("header '$name' must be a list of strings")
        }
        list.map { name to (it as JsonPrimitive).content }
    },
)

// ---------------------------------------------------------------------------------------------
// Results

/** A JSON value from a Kotlin one: strings, numbers, booleans, URIs, lists, maps and JSON values. */
fun json(value: Any?): JsonElement = when (value) {
    null -> JsonNull
    is JsonElement -> value
    is String -> JsonPrimitive(value)
    is Number -> JsonPrimitive(value)
    is Boolean -> JsonPrimitive(value)
    is URI -> JsonPrimitive(value.toString())
    is Map<*, *> -> JsonObject(value.entries.associate { it.key.toString() to json(it.value) })
    is Iterable<*> -> JsonArray(value.map(::json))
    else -> JsonPrimitive(value.toString())
}

/** An object of the given members, leaving out the absent (null) ones. */
fun members(vararg values: Pair<String, Any?>): JsonObject = JsonObject(values.filter { it.second != null }.associate { it.first to json(it.second) })

fun isTextual(contentType: String): Boolean {
    val e = contentType.substringBefore(';').trim().lowercase()
    return e.startsWith("text/") || e == "application/json" || e == "application/xml" || e.endsWith("+json") || e.endsWith("+xml")
}

fun bodyResult(r: Resource): JsonObject =
    if (r.contentType?.let(::isTextual) == true) members("text" to r.text()) else members("base64" to Base64.getEncoder().encodeToString(r.bytes))

fun metadataResult(m: ResourceMetadata): JsonObject = members(
    "url" to m.url,
    "status" to m.status,
    "etag" to m.etag,
    "lastModified" to m.lastModified,
    "contentType" to m.contentType,
    "contentLength" to m.contentLength,
    "links" to m.links.map { members("href" to it.href, "rel" to it.rel, "params" to it.params) },
    "linkset" to m.linkset,
    "parent" to m.parent,
    "storage" to m.storage,
    "types" to m.types,
    "allow" to m.allow,
    "acceptPatch" to m.acceptPatch,
)

fun itemResult(i: ContainedResource): JsonObject =
    members("id" to i.id, "types" to i.types, "format" to i.format, "size" to i.size, "modified" to i.modifiedRaw)

fun pageResult(p: ContainerPage): JsonObject = members(
    "id" to p.id,
    "types" to p.types,
    "totalItems" to p.totalItems,
    "items" to p.items.map(::itemResult),
    "first" to p.first,
    "next" to p.next,
    "prev" to p.prev,
    "last" to p.last,
    "metadata" to metadataResult(p.metadata),
)

fun updateResult(u: UpdateResult): JsonObject = members("status" to u.status, "etag" to u.etag, "metadata" to metadataResult(u.metadata))

fun createdResult(c: CreateResult): JsonObject = members("location" to c.location, "metadata" to metadataResult(c.metadata))

fun serviceResult(s: Service): JsonObject = members(
    "id" to s.id,
    "types" to s.types,
    "serviceEndpoint" to s.serviceEndpoint,
    "subscriptionType" to if ("subscriptionType" in s.raw) s.subscriptionTypes else null,
)

fun storageResult(s: StorageDescription): JsonObject {
    val root = try {
        s.storageRoot()
    } catch (_: ProtocolException) {
        null
    }
    return members(
        "id" to s.id,
        "types" to s.types,
        "storageRoot" to root,
        "services" to s.services.map(::serviceResult),
        "verificationMethods" to s.verificationMethods.map { members("id" to it.id, "type" to it.type, "controller" to it.controller) },
        "raw" to s.raw,
    )
}

fun subscriptionResult(s: Subscription): JsonObject =
    members("subscription" to s.url, "types" to s.types, "expires" to s.expiresRaw, "raw" to s.raw)

/** Pulls at most `limit + 1` elements: the first `limit`, and whether there was one more. */
suspend fun <T> take(sequence: Flow<T>, limit: Int): Pair<List<T>, Boolean> {
    val items = sequence.take(limit + 1).toList()
    return items.take(limit) to (items.size > limit)
}

suspend fun listing(sequence: Flow<ContainedResource>, limit: Int): JsonObject {
    val (items, truncated) = take(sequence, limit)
    return members("items" to items.map(::itemResult), "truncated" to truncated)
}

// ---------------------------------------------------------------------------------------------
// Errors

/** The problem object: the extensions, and the standard members present. */
fun problemResult(p: ProblemDetails): JsonObject = JsonObject(
    p.extensions + members("type" to p.type, "title" to p.title, "status" to p.status, "detail" to p.detail, "instance" to p.instance),
)

fun httpKind(e: HttpException): String = when (e) {
    is BadRequestException -> "BadRequestError"
    is UnauthorizedException -> "UnauthorizedError"
    is ForbiddenException -> "ForbiddenError"
    is NotFoundException -> "NotFoundError"
    is MethodNotAllowedException -> "MethodNotAllowedError"
    is NotAcceptableException -> "NotAcceptableError"
    is ConflictException -> "ConflictError"
    is GoneException -> "GoneError"
    is PreconditionFailedException -> "PreconditionFailedError"
    is UnsupportedMediaTypeException -> "UnsupportedMediaTypeError"
    is UnprocessableContentException -> "UnprocessableContentError"
    is NotImplementedException -> "NotImplementedError"
    is InsufficientStorageException -> "InsufficientStorageError"
    else -> "HttpError"
}

fun errorResult(e: Throwable): JsonObject = when (e) {
    is AdapterError -> members("kind" to e.kind, "message" to e.message)
    is HttpException -> members(
        "kind" to httpKind(e),
        "status" to e.status,
        "message" to e.message,
        "problem" to e.problem?.let(::problemResult),
        "allow" to (e as? MethodNotAllowedException)?.allow,
        "acceptPatch" to (e as? UnsupportedMediaTypeException)?.acceptPatch,
    )
    is AuthenticationException -> members(
        "kind" to "AuthenticationError", "status" to e.status, "message" to e.message,
        "oauthError" to e.oauthError, "oauthErrorDescription" to e.oauthErrorDescription,
    )
    is SignatureVerificationException -> members("kind" to "SignatureVerificationError", "message" to e.message)
    is ProtocolException -> members("kind" to "ProtocolError", "message" to e.message)
    is TransportException -> members("kind" to "TransportError", "message" to e.message)
    is IllegalArgumentException -> members("kind" to "InvalidArguments", "message" to (e.message ?: e.toString()))
    else -> {
        val message = e.stackTraceToString()
        System.err.println(message)
        members("kind" to "InternalError", "message" to message)
    }
}

// ---------------------------------------------------------------------------------------------
// The operations

/** An operation: its arguments to its result. */
fun op(f: suspend (Args) -> JsonObject): suspend (Args) -> JsonObject = f

class Adapter {
    /** The client every operation uses; `configure` replaces it. */
    private var client = LwsClient()

    val operations: Map<String, suspend (Args) -> JsonObject> = linkedMapOf(
        "configure" to op { configure(it) },
        "discover_storage" to op { a -> storageResult(client.discoverStorage(a.url("url"))) },
        "get_storage_description" to op { a -> storageResult(client.getStorageDescription(a.url("url"))) },
        "head" to op { a -> metadataResult(client.head(a.url("url"))) },
        "read" to op { read(it) },
        "read_container" to op { a -> pageResult(client.readContainer(a.url("url"))) },
        "list_container" to op { a -> listing(client.listContainer(a.url("url")), a.limit()) },
        "create" to op { create(it) },
        "create_container" to op { a -> createdResult(client.createContainer(a.url("parent"), slug = a.optStr("slug"))) },
        "update" to op { update(it) },
        "patch" to op { a -> updateResult(client.patch(a.url("url"), patchOf(a.raw("patch")), ifMatch = a.optStr("ifMatch"))) },
        "delete" to op { a ->
            client.delete(a.url("url"), ifMatch = a.optStr("ifMatch"), recursive = a.optBool("recursive") ?: false)
            members()
        },
        "linkset_url" to op { a -> members("linkset" to client.linksetUrl(a.url("url"))) },
        "read_linkset" to op { a ->
            val doc = client.readLinkset(a.url("url"))
            members("url" to doc.url, "etag" to doc.etag, "linkset" to doc.linkset.toJson(), "allow" to doc.allow, "acceptPatch" to doc.acceptPatch)
        },
        "update_linkset" to op { updateLinkset(it) },
        "patch_linkset" to op { a -> updateResult(client.patchLinkset(a.url("linksetUrl"), patchOf(a.raw("patch")), ifMatch = a.optStr("ifMatch"))) },
        "subscribe" to op { subscribe(it) },
        "list_subscriptions" to op { a -> listing(client.listSubscriptions(a.url("serviceUrl")), a.limit()) },
        "get_subscription" to op { a -> subscriptionResult(client.getSubscription(a.url("url"))) },
        "unsubscribe" to op { a ->
            client.unsubscribe(a.url("url"))
            members()
        },
        "verify_notification" to op { verifyNotification(it) },
        "request_access" to op { a ->
            val url = a.url("serviceUrl")
            members("location" to client.requestAccess(url, document(a, "request") { AccessRequest.parse(it) }))
        },
        "get_access_request" to op { a -> members("document" to client.getAccessRequest(a.url("url")).document()) },
        "list_access_requests" to op { a -> listing(client.listAccessRequests(a.url("serviceUrl")), a.limit()) },
        "cancel_access_request" to op { a ->
            client.cancelAccessRequest(a.url("url"))
            members()
        },
        "grant_access" to op { a ->
            val url = a.url("serviceUrl")
            members("location" to client.grantAccess(url, document(a, "grant") { AccessGrant.parse(it) }))
        },
        "get_access_grant" to op { a -> members("document" to client.getAccessGrant(a.url("url")).document()) },
        "list_access_grants" to op { a -> listing(client.listAccessGrants(a.url("serviceUrl")), a.limit()) },
        "revoke_access_grant" to op { a ->
            client.revokeAccessGrant(a.url("url"))
            members()
        },
        "read_type_index" to op { a ->
            val p = client.readTypeIndex(a.url("url"))
            members("totalItems" to p.totalItems, "types" to p.types, "first" to p.first, "next" to p.next, "prev" to p.prev, "last" to p.last)
        },
        "list_types" to op { a ->
            val (types, truncated) = take(client.listTypes(a.url("serviceUrl")), a.limit())
            members("types" to types, "truncated" to truncated)
        },
        "search_types" to op { a ->
            val url = a.url("serviceUrl")
            pageResult(client.searchTypes(url, queryOf(a.obj("query"))))
        },
        "search_all" to op { a ->
            val url = a.url("serviceUrl")
            listing(client.searchAll(url, queryOf(a.obj("query"))), a.limit())
        },
        "accepted_query_formats" to op { a -> members("formats" to client.acceptedQueryFormats(a.url("serviceUrl"))) },
        "shutdown" to op { _ -> members() },
    )

    private fun configure(args: Args): JsonObject {
        val auth = Args.of(args.raw("auth") ?: members("type" to "none"), "argument 'auth'")
        val allowInsecureHttp = args.optBool("allowInsecureHttp") ?: false
        val result = linkedMapOf<String, Any?>("library" to LIBRARY)
        fun exchange(credentials: CredentialProvider) = TokenExchangeAuthenticator(credentials, allowInsecureHttp = allowInsecureHttp)
        val authenticator: Authenticator? = when (val type = auth.optStr("type")) {
            "none" -> null
            "bearer" -> BearerTokenAuthenticator(auth.str("token"), auth.optStr("realm")?.let { uri(it, "realm") })
            "openid" -> exchange(OpenIdCredentials(auth.str("idToken")))
            "selfSigned" -> {
                val agent = auth.str("agent")
                val jwk = auth.obj("privateJwk")
                val kid = auth.optStr("kid") ?: (jwk["kid"] as? JsonPrimitive)?.takeIf { it.isString }?.content
                    ?: throw AdapterError.invalid("selfSigned needs 'kid', or a 'kid' in the private JWK")
                val key = try {
                    SigningKey.fromJwk(jwk)
                } catch (e: IllegalArgumentException) {
                    throw AdapterError.invalid("argument 'privateJwk' is not a usable private key: ${e.message}")
                }
                result["agent"] = agent
                result["kid"] = kid
                exchange(SelfSignedCredentials.forAgent(agent, key, kid))
            }
            "didKey" -> {
                val algorithm = auth.optStr("algorithm") ?: "ES256"
                if (algorithm != "ES256" && algorithm != "EdDSA") throw AdapterError.invalid("unknown algorithm '$algorithm'")
                val didKey = SelfSignedCredentials.didKey(SigningKey.generate(algorithm))
                result["agent"] = didKey.agent
                result["kid"] = didKey.keyId
                exchange(didKey)
            }
            else -> throw AdapterError.invalid("unknown auth type '$type'")
        }
        val headers = args.optObj("headers")?.mapValues { (name, value) ->
            (value as? JsonPrimitive)?.takeIf { it.isString }?.content ?: throw AdapterError.invalid("header '$name' must be a string")
        } ?: emptyMap()
        val timeout = args.optInt("timeoutSeconds", 1)
        client = LwsClient(
            authenticator = authenticator,
            userAgent = args.optStr("userAgent") ?: LwsClient.DEFAULT_USER_AGENT,
            defaultHeaders = headers,
            timeout = (timeout ?: 30L).seconds,
        )
        return members(*result.entries.map { it.key to it.value }.toTypedArray())
    }

    private suspend fun read(args: Args): JsonObject {
        val url = args.url("url")
        val start = args.optInt("rangeStart")
        val end = args.optInt("rangeEnd")
        if (start == null && end != null) throw AdapterError.invalid("rangeEnd needs rangeStart")
        val r = client.read(
            url, accept = args.optStr("accept"), range = start?.let { ByteRange.of(it, end) },
            ifNoneMatch = args.optStr("ifNoneMatch"), prefer = args.optStr("prefer"),
        )
        return members("metadata" to metadataResult(r.metadata), "notModified" to r.notModified, "contentRange" to r.contentRange, "body" to bodyResult(r))
    }

    private suspend fun create(args: Args): JsonObject {
        val container = args.url("container")
        val (data, contentType) = bodyOf(args.raw("body"), args.optStr("contentType"))
        val types = (args.optStrings("types") ?: emptyList()).map { uri(it, "types") }
        return createdResult(client.create(container, data, contentType, slug = args.optStr("slug"), types = types, links = linksOf(args.optList("links"))))
    }

    private suspend fun update(args: Args): JsonObject {
        val url = args.url("url")
        if (!args.has("body")) throw AdapterError.invalid("missing argument 'body'")
        val (data, contentType) = bodyOf(args.raw("body"), args.optStr("contentType"))
        return updateResult(client.update(url, data, contentType, ifMatch = args.optStr("ifMatch"), ifNoneMatch = args.optStr("ifNoneMatch")))
    }

    private suspend fun updateLinkset(args: Args): JsonObject {
        val url = args.url("linksetUrl")
        val linkset = try {
            Linkset.parse(args.obj("linkset"))
        } catch (e: ProtocolException) {
            throw AdapterError.invalid("argument 'linkset': ${e.message}")
        }
        return updateResult(client.updateLinkset(url, linkset, ifMatch = args.optStr("ifMatch")))
    }

    private suspend fun subscribe(args: Args): JsonObject {
        val url = args.url("serviceUrl")
        val expires: Instant? = args.optStr("expires")?.let {
            try {
                OffsetDateTime.parse(it).toInstant()
            } catch (_: DateTimeParseException) {
                throw AdapterError.invalid("argument 'expires' is not an RFC 3339 date-time: $it")
            }
        }
        val request = try {
            WebhookSubscriptionRequest(args.strings("topics").map { uri(it, "topics") }, uri(args.str("inbox"), "inbox"), expires)
        } catch (e: IllegalArgumentException) {
            throw AdapterError.invalid(e.message ?: "invalid subscription request")
        }
        return subscriptionResult(client.subscribe(url, request))
    }

    private suspend fun verifyNotification(args: Args): JsonObject {
        val method = args.str("method")
        val url = uri(args.str("url"), "url")
        val headers = headersOf(args.obj("headers"))
        val body = base64(args.str("bodyBase64"), "bodyBase64")
        val trusted = args.optStrings("trustedStorages")
        // Section 4.2: the driver leaves trustedStorages out to accept any storage.
        if (trusted != null && trusted.isEmpty()) throw AdapterError.invalid("argument 'trustedStorages' must not be empty; leave it out to accept any storage")
        val verifier = WebhookVerifier(client, trustedStorages = trusted?.map { uri(it, "trustedStorages") })
        val verified = verifier.verify(method, url, headers, body)
        val activities = verified.notification.activities.map {
            members("id" to it.id, "types" to it.types, "object" to it.`object`.id, "objectTypes" to it.`object`.types)
        }
        return members("storage" to verified.storage, "keyid" to verified.keyId, "activities" to activities, "raw" to verified.notification.raw)
    }

    /** Parses a document argument with the library's parser; a document it rejects is a malformed argument. */
    private fun <T> document(args: Args, name: String, parse: (JsonObject) -> T): T = try {
        parse(args.obj(name))
    } catch (e: ProtocolException) {
        throw AdapterError.invalid("argument '$name': ${e.message}")
    } catch (e: IllegalArgumentException) {
        throw AdapterError.invalid("argument '$name': ${e.message}")
    }
}

// ---------------------------------------------------------------------------------------------
// The protocol loop

private val out = PrintStream(FileOutputStream(FileDescriptor.out), false, Charsets.UTF_8)

/** Writes one protocol line and flushes it. */
fun write(message: JsonObject) {
    out.print(Json.encodeToString(JsonElement.serializer(), message))
    out.print('\n')
    out.flush()
}

fun failure(id: JsonElement, error: JsonObject): JsonObject = JsonObject(mapOf("id" to id, "ok" to JsonPrimitive(false), "error" to error))

fun serve(adapter: Adapter) {
    write(members("hello" to members("protocol" to PROTOCOL, "language" to LANGUAGE, "library" to LIBRARY, "operations" to adapter.operations.keys.toList())))
    val input = System.`in`.bufferedReader(Charsets.UTF_8)
    while (true) {
        val line = input.readLine() ?: return
        if (line.isBlank()) continue
        val request = try {
            Json.parseToJsonElement(line)
        } catch (_: SerializationException) {
            write(failure(JsonNull, errorResult(AdapterError.invalid("the request is not JSON"))))
            continue
        }
        if (request !is JsonObject) {
            write(failure(JsonNull, errorResult(AdapterError.invalid("the request is not a JSON object"))))
            continue
        }
        val id = request["id"] ?: JsonNull
        val op = (request["op"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        val operation = op?.let(adapter.operations::get)
        if (operation == null) {
            write(failure(id, members("kind" to "Unsupported", "message" to "unknown operation ${request["op"] ?: "null"}")))
            continue
        }
        val response = try {
            val result = runBlocking { operation(Args.of(request["args"], "args")) }
            JsonObject(mapOf("id" to id, "ok" to JsonPrimitive(true), "result" to result))
        } catch (e: Exception) {
            failure(id, errorResult(e))
        } catch (e: StackOverflowError) {
            failure(id, errorResult(e))
        } catch (e: LinkageError) {
            failure(id, errorResult(e))
        }
        write(response)
        if (op == "shutdown") return
    }
}

fun main() {
    // stdout carries protocol messages only: every other print goes to stderr.
    System.setOut(System.err)
    serve(Adapter())
    out.flush()
    exitProcess(0)
}
