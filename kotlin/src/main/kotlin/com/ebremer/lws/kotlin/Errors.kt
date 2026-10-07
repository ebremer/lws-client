// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

import com.ebremer.lws.kotlin.http.AuthChallenge
import com.ebremer.lws.kotlin.http.Headers
import com.ebremer.lws.kotlin.http.ProblemDetails
import com.ebremer.lws.kotlin.http.WwwAuthenticate
import com.ebremer.lws.kotlin.internal.HeaderLists
import java.net.URI

/**
 * The errors of the client: [HttpException] (with a subclass per status that has a meaning in LWS),
 * [AuthenticationException], [ProtocolException], [SignatureVerificationException] and [TransportException].
 * The hierarchy is sealed, so a `when` over it can be exhaustive:
 *
 * ```kotlin
 * try {
 *     client.update(url, body, "text/plain", ifMatch = etag)
 * } catch (e: PreconditionFailedException) {
 *     // someone else changed it: read it again
 * }
 * ```
 *
 * Arguments that are not usable (a relative URL as a request target, an invalid header name) are
 * [IllegalArgumentException]s, raised before any request is sent.
 */
public sealed class LwsException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/**
 * A response with an error status. Statuses with a meaning in LWS have a subclass ([NotFoundException],
 * [ConflictException], [PreconditionFailedException], …); others are this class (a 5xx is an unknown error).
 *
 * @property status the HTTP status
 * @property method the request method
 * @property url the URL that answered (after redirects)
 * @property headers the response headers
 * @property problem the RFC 9457 problem details of the response, if it had any
 * @property body the response body as text (at most [BODY_LIMIT] bytes of it)
 */
public open class HttpException internal constructor(
    public val status: Int,
    public val method: String,
    public val url: URI,
    public val headers: Headers,
    body: ByteArray,
) : LwsException(message(status, method, url, headers, body)) {
    public val problem: ProblemDetails? = ProblemDetails.parse(headers["content-type"], body)
    public val body: String = HeaderLists.decode(if (body.size > BODY_LIMIT) body.copyOf(BODY_LIMIT) else body, headers["content-type"])

    public companion object {
        /** The longest body kept, in bytes. */
        public const val BODY_LIMIT: Int = 4096

        private val REASONS = mapOf(
            400 to "Bad Request", 401 to "Unauthorized", 402 to "Payment Required", 403 to "Forbidden", 404 to "Not Found",
            405 to "Method Not Allowed", 406 to "Not Acceptable", 407 to "Proxy Authentication Required",
            408 to "Request Timeout", 409 to "Conflict", 410 to "Gone", 411 to "Length Required",
            412 to "Precondition Failed", 413 to "Content Too Large", 414 to "URI Too Long", 415 to "Unsupported Media Type",
            416 to "Range Not Satisfiable", 417 to "Expectation Failed", 421 to "Misdirected Request",
            422 to "Unprocessable Content", 423 to "Locked", 428 to "Precondition Required", 429 to "Too Many Requests",
            500 to "Internal Server Error", 501 to "Not Implemented", 502 to "Bad Gateway", 503 to "Service Unavailable",
            504 to "Gateway Timeout", 507 to "Insufficient Storage",
        )

        /** The exception for an error response: the status-specific subclass where there is one. */
        public fun fromResponse(status: Int, method: String, url: URI, headers: Headers, body: ByteArray = ByteArray(0)): HttpException =
            when (status) {
                400 -> BadRequestException(method, url, headers, body)
                401 -> UnauthorizedException(method, url, headers, body)
                403 -> ForbiddenException(method, url, headers, body)
                404 -> NotFoundException(method, url, headers, body)
                405 -> MethodNotAllowedException(method, url, headers, body)
                406 -> NotAcceptableException(method, url, headers, body)
                409 -> ConflictException(method, url, headers, body)
                410 -> GoneException(method, url, headers, body)
                412 -> PreconditionFailedException(method, url, headers, body)
                415 -> UnsupportedMediaTypeException(method, url, headers, body)
                422 -> UnprocessableContentException(method, url, headers, body)
                501 -> NotImplementedException(method, url, headers, body)
                507 -> InsufficientStorageException(method, url, headers, body)
                else -> HttpException(status, method, url, headers, body)
            }

        private fun message(status: Int, method: String, url: URI, headers: Headers, body: ByteArray): String {
            val reason = REASONS[status]
            var message = "$method $url → $status" + if (reason == null) "" else " $reason"
            val problem = ProblemDetails.parse(headers["content-type"], body)
            var explanation = problem?.detail ?: problem?.title
            if (explanation == null && body.isNotEmpty() && HeaderLists.essence(headers["content-type"]) == "text/plain") {
                explanation = HeaderLists.decode(body.copyOf(minOf(body.size, 200)), headers["content-type"]).trim()
            }
            if (!explanation.isNullOrEmpty()) message += ": $explanation"
            return message
        }
    }
}

/** A `400 Bad Request`. */
public class BadRequestException internal constructor(method: String, url: URI, headers: Headers, body: ByteArray) :
    HttpException(400, method, url, headers, body)

/** A `401 Unauthorized` that authentication did not resolve (or that no authenticator was there to handle). */
public class UnauthorizedException internal constructor(method: String, url: URI, headers: Headers, body: ByteArray) :
    HttpException(401, method, url, headers, body) {
    /** The parsed `WWW-Authenticate` challenges. */
    public val challenges: List<AuthChallenge> get() = WwwAuthenticate.parse(headers.all("www-authenticate"))
}

/** A `403 Forbidden`: the requester is known but not permitted. */
public class ForbiddenException internal constructor(method: String, url: URI, headers: Headers, body: ByteArray) :
    HttpException(403, method, url, headers, body)

/** A `404 Not Found`. */
public class NotFoundException internal constructor(method: String, url: URI, headers: Headers, body: ByteArray) :
    HttpException(404, method, url, headers, body)

/** A `405 Method Not Allowed` (such as a PUT to a linkset that only allows PATCH). */
public class MethodNotAllowedException internal constructor(method: String, url: URI, headers: Headers, body: ByteArray) :
    HttpException(405, method, url, headers, body) {
    /** The methods the `Allow` header lists. */
    public val allow: List<String> get() = HeaderLists.split(headers.all("allow"))
}

/** A `406 Not Acceptable`. */
public class NotAcceptableException internal constructor(method: String, url: URI, headers: Headers, body: ByteArray) :
    HttpException(406, method, url, headers, body)

/** A `409 Conflict`, such as deleting a non-empty container without `recursive`. */
public class ConflictException internal constructor(method: String, url: URI, headers: Headers, body: ByteArray) :
    HttpException(409, method, url, headers, body)

/** A `410 Gone`, such as an expired pagination link. */
public class GoneException internal constructor(method: String, url: URI, headers: Headers, body: ByteArray) :
    HttpException(410, method, url, headers, body)

/** A `412 Precondition Failed`: the `If-Match` ETag is no longer current. */
public class PreconditionFailedException internal constructor(method: String, url: URI, headers: Headers, body: ByteArray) :
    HttpException(412, method, url, headers, body)

/** A `415 Unsupported Media Type`, with the formats the server accepts instead. */
public class UnsupportedMediaTypeException internal constructor(method: String, url: URI, headers: Headers, body: ByteArray) :
    HttpException(415, method, url, headers, body) {
    /** The patch formats of `Accept-Patch`. */
    public val acceptPatch: List<String> get() = HeaderLists.split(headers.all("accept-patch")).map(HeaderLists::unquote)

    /** The query formats of `Accept-Query`. */
    public val acceptQuery: List<String> get() = HeaderLists.split(headers.all("accept-query")).map(HeaderLists::unquote)
}

/** A `422 Unprocessable Content`, such as a JSON Patch that cannot be applied. */
public class UnprocessableContentException internal constructor(method: String, url: URI, headers: Headers, body: ByteArray) :
    HttpException(422, method, url, headers, body)

/** A `501 Not Implemented`. */
public class NotImplementedException internal constructor(method: String, url: URI, headers: Headers, body: ByteArray) :
    HttpException(501, method, url, headers, body)

/** A `507 Insufficient Storage`: the quota is exceeded. */
public class InsufficientStorageException internal constructor(method: String, url: URI, headers: Headers, body: ByteArray) :
    HttpException(507, method, url, headers, body)

/**
 * Authorization failed: the realm check, the authorization server's transport security or metadata, the
 * credential provider, or the token exchange.
 *
 * @property oauthError the OAuth `error` of a token endpoint's error response (`invalid_grant`, …)
 * @property oauthErrorDescription its `error_description`
 * @property status the HTTP status of the authorization server's response, where there was one
 */
public class AuthenticationException(
    message: String,
    public val oauthError: String? = null,
    public val oauthErrorDescription: String? = null,
    public val status: Int? = null,
    cause: Throwable? = null,
) : LwsException(message, cause)

/** A response that breaks the specification: a missing `Location`, the wrong media type, invalid JSON. */
public class ProtocolException(message: String, cause: Throwable? = null) : LwsException(message, cause)

/** A webhook notification that fails verification. */
public class SignatureVerificationException(message: String, cause: Throwable? = null) : LwsException(message, cause)

/**
 * No response: the connection was refused or reset, TLS failed, or the request timed out.
 *
 * @property isTimeout whether the request timed out
 */
public class TransportException(message: String, public val isTimeout: Boolean = false, cause: Throwable? = null) :
    LwsException(message, cause)
