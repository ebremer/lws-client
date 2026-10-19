// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin.auth

import com.ebremer.lws.kotlin.AuthenticationException
import com.ebremer.lws.kotlin.LinkRelation
import com.ebremer.lws.kotlin.LwsClient
import com.ebremer.lws.kotlin.MediaType
import com.ebremer.lws.kotlin.ProtocolException
import com.ebremer.lws.kotlin.StorageDescription
import com.ebremer.lws.kotlin.TokenType
import com.ebremer.lws.kotlin.Vocabulary
import com.ebremer.lws.kotlin.http.AuthChallenge
import com.ebremer.lws.kotlin.http.Headers
import com.ebremer.lws.kotlin.http.HttpRequest
import com.ebremer.lws.kotlin.http.HttpResponse
import com.ebremer.lws.kotlin.http.HttpTransport
import com.ebremer.lws.kotlin.http.JdkHttpTransport
import com.ebremer.lws.kotlin.http.Link
import com.ebremer.lws.kotlin.http.LinkHeader
import com.ebremer.lws.kotlin.http.WwwAuthenticate
import com.ebremer.lws.kotlin.internal.Base64Url
import com.ebremer.lws.kotlin.internal.HeaderLists
import com.ebremer.lws.kotlin.internal.JsonAccess
import com.ebremer.lws.kotlin.internal.Urls
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.URI
import java.net.URLEncoder
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.Collections
import java.util.UUID
import java.util.WeakHashMap
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

/**
 * How requests are authenticated. The client calls [authorize] before sending each request (and each redirect hop),
 * and [handleChallenge] when one is answered `401`; when that returns true, the request is sent once more, with the
 * credentials of [authorizeRetry]. Implementations must be safe to use from several coroutines at once.
 */
public interface Authenticator {
    /** Returns the request with credentials added, typically an `Authorization` header. */
    public suspend fun authorize(request: AuthRequest): AuthRequest

    /** Reacts to a `401` response, e.g. by obtaining a token; returns whether to send the request again. */
    public suspend fun handleChallenge(request: AuthRequest, response: AuthResponse): Boolean

    /**
     * Returns the request sent once more after [handleChallenge] returned true for [challenged], the request the `401`
     * answered, with credentials added: by default those of [authorize].
     */
    public suspend fun authorizeRetry(request: AuthRequest, challenged: AuthRequest): AuthRequest = authorize(request)
}

/** A request as an [Authenticator] sees it: method, URL and headers. */
public class AuthRequest(public val method: String, public val url: URI, public val headers: Headers = Headers.EMPTY) {
    /** A copy with other headers. */
    public fun withHeaders(headers: Headers): AuthRequest = AuthRequest(method, url, headers)

    /** A copy with `Authorization: Bearer <token>`. */
    public fun withBearerToken(token: String): AuthRequest = withHeaders(headers.with("Authorization", "Bearer $token"))

    override fun toString(): String = "$method $url"
}

/** A `401` response as an [Authenticator] sees it. */
public class AuthResponse(public val url: URI, public val status: Int, public val headers: Headers) {
    /** The parsed `WWW-Authenticate` challenges. */
    public val challenges: List<AuthChallenge> get() = WwwAuthenticate.parse(headers.all("www-authenticate"))
}

/**
 * Sends a known access token.
 *
 * @param realm send the token only to URLs inside this realm (null: everywhere, so use a dedicated client)
 * @param token asked for the token per request (null: send none)
 */
public class BearerTokenAuthenticator(public val realm: URI? = null, private val token: suspend () -> String?) : Authenticator {
    /** A fixed token, sent only inside [realm] (null: everywhere). */
    public constructor(token: String, realm: URI? = null) : this(realm, { token })

    override suspend fun authorize(request: AuthRequest): AuthRequest {
        if (realm != null && !Urls.contains(realm.toString(), request.url.toString())) return request
        return token()?.let(request::withBearerToken) ?: request
    }

    override suspend fun handleChallenge(request: AuthRequest, response: AuthResponse): Boolean = false

    override fun toString(): String = "BearerTokenAuthenticator(realm=$realm)"
}

/**
 * What a [CredentialProvider] is asked for a subject token for.
 *
 * @property issuer the authorization server
 * @property storage the storage the access token is requested for (the realm, for a challenge of the drafts before
 *     19 October 2026)
 * @property metadata the server's metadata, whose `issuer` is the audience of self-signed tokens
 */
public class CredentialContext(public val issuer: String, public val storage: String, public val metadata: AuthorizationServerMetadata)

/** The subject tokens of an authentication suite, exchanged for access tokens. */
public interface CredentialProvider {
    /** The `subject_token_type` URI (see [TokenType]). */
    public val tokenType: String

    /** A subject token for the given authorization server. */
    public suspend fun subjectToken(context: CredentialContext): String
}

/**
 * The OpenID Connect suite (`lws10-authn-openid`): an ID token, fixed or asked for per exchange. Logging in is the
 * application's OIDC library's business; ask it for a token audience-restricted to the authorization server where
 * it can.
 */
public class OpenIdCredentials(private val idTokens: suspend (CredentialContext) -> String) : CredentialProvider {
    /** A fixed ID token. */
    public constructor(idToken: String) : this({ idToken })

    override val tokenType: String get() = TokenType.ID_TOKEN

    override suspend fun subjectToken(context: CredentialContext): String = idTokens(context)

    override fun toString(): String = "OpenIdCredentials"
}

/** The SAML 2.0 suite (`lws10-authn-saml`): base64url-encoded assertions (RFC 8693 section 3), asked per exchange. */
public class SamlCredentials(private val encodedAssertions: suspend (CredentialContext) -> String) : CredentialProvider {
    override val tokenType: String get() = TokenType.SAML2

    override suspend fun subjectToken(context: CredentialContext): String = encodedAssertions(context)

    override fun toString(): String = "SamlCredentials"

    public companion object {
        /** A fixed, already base64url-encoded assertion. */
        public fun fromEncoded(encodedAssertion: String): SamlCredentials = SamlCredentials { encodedAssertion }

        /** A fixed assertion given as XML. */
        public fun fromXml(assertionXml: String): SamlCredentials = fromEncoded(encode(assertionXml))

        /** Base64url-encodes (without padding) an assertion XML document. */
        public fun encode(assertionXml: String): String = Base64Url.encode(assertionXml.toByteArray(Charsets.UTF_8))
    }
}

/**
 * The self-signed identity suite (`lws10-authn-ssi-cid`, `did:key` subjects included): the agent signs its own JWT
 * credential (`urn:ietf:params:oauth:token-type:jwt`) with `sub = iss = client_id = agent`,
 * `aud = [authorization server]`, `iat`, `exp` and a random `jti`. Supports `ES256` (P-256) and `EdDSA` (Ed25519).
 * Tokens are reused per audience until 60 seconds before they expire.
 *
 * ```kotlin
 * val me = SelfSignedCredentials.didKey(SigningKey.generateP256())   // agent = did:key:zDn…
 * ```
 *
 * @property agent the agent identifier (`sub`, `iss` and `client_id`)
 * @property keyId the `kid` of the JWT header
 * @property lifetime how long minted tokens live
 */
public class SelfSignedCredentials private constructor(
    public val agent: String,
    private val key: SigningKey,
    public val keyId: String?,
    public val lifetime: Duration,
    private val clock: Clock,
) : CredentialProvider {
    private val cache = ConcurrentHashMap<String, Pair<String, Instant>>()

    /** A copy whose tokens live for [lifetime]. */
    public fun withLifetime(lifetime: Duration): SelfSignedCredentials = SelfSignedCredentials(agent, key, keyId, lifetime, clock)

    /** A copy using another clock (for tests). */
    public fun withClock(clock: Clock): SelfSignedCredentials = SelfSignedCredentials(agent, key, keyId, lifetime, clock)

    /** The JOSE algorithm: `ES256` or `EdDSA`. */
    public val algorithm: String get() = key.algorithm

    public val publicKey: VerificationKey get() = key.publicKey

    override val tokenType: String get() = TokenType.JWT

    override suspend fun subjectToken(context: CredentialContext): String {
        val audience = context.metadata.issuer
        val now = clock.instant()
        cache[audience]?.let { (token, expires) -> if (now.plusSeconds(REUSE_MARGIN) < expires) return token }
        val token = createToken(audience)
        cache[audience] = token to now.plus(lifetime.toJavaDuration())
        return token
    }

    /** Creates and signs a new credential for [audience]. */
    public fun createToken(audience: String): String {
        val iat = clock.instant().epochSecond
        val header = linkedMapOf<String, JsonElement>("alg" to JsonPrimitive(key.algorithm), "typ" to JsonPrimitive("JWT"))
        if (keyId != null) header["kid"] = JsonPrimitive(keyId)
        val claims = JsonObject(
            linkedMapOf(
                "sub" to JsonPrimitive(agent),
                "iss" to JsonPrimitive(agent),
                "client_id" to JsonPrimitive(agent),
                "aud" to JsonArray(listOf(JsonPrimitive(audience))),
                "iat" to JsonPrimitive(iat),
                "exp" to JsonPrimitive(iat + lifetime.inWholeSeconds),
                "jti" to JsonPrimitive(UUID.randomUUID().toString()),
            ),
        )
        return Jwt.sign(JsonObject(header), claims, key)
    }

    override fun toString(): String = "SelfSignedCredentials(agent=$agent, keyId=$keyId, algorithm=$algorithm)"

    public companion object {
        private const val REUSE_MARGIN = 60L

        /**
         * Credentials for an agent whose controlled identifier document (at [agent]) lists the key under
         * `authentication`; [keyId] identifies that verification method.
         */
        public fun forAgent(agent: String, key: SigningKey, keyId: String?, lifetime: Duration = 300.seconds): SelfSignedCredentials =
            SelfSignedCredentials(agent, key, keyId, lifetime, Clock.systemUTC())

        /**
         * Credentials for a `did:key` agent derived from a P-256 or Ed25519 key.
         *
         * @throws IllegalArgumentException for a P-384 key
         */
        public fun didKey(key: SigningKey, lifetime: Duration = 300.seconds): SelfSignedCredentials =
            SelfSignedCredentials(DidKey.did(key.publicKey), key, DidKey.keyId(key.publicKey), lifetime, Clock.systemUTC())
    }
}

/**
 * An authorization server's metadata (`/.well-known/lws-configuration`, RFC 8414).
 *
 * @property issuer the issuer identifier, as the server states it
 * @property subjectTokenTypesSupported empty when not advertised
 * @property subjectIdentifierTypesSupported `["https"]` when not advertised
 */
public class AuthorizationServerMetadata(
    public val issuer: String,
    public val tokenEndpoint: URI,
    public val jwksUri: URI? = null,
    public val grantTypesSupported: List<String> = emptyList(),
    public val subjectTokenTypesSupported: List<String> = emptyList(),
    public val subjectIdentifierTypesSupported: List<String> = listOf("https"),
    public val raw: JsonObject = JsonObject(emptyMap()),
) {
    /** Whether the server accepts subject tokens of a type (true when it advertises none). */
    public fun supportsSubjectTokenType(tokenType: String): Boolean =
        subjectTokenTypesSupported.isEmpty() || tokenType in subjectTokenTypesSupported

    public companion object {
        /**
         * Parses a metadata document retrieved from [base].
         *
         * @throws ProtocolException without `issuer` or `token_endpoint`
         */
        public fun parse(json: JsonElement, base: URI? = null): AuthorizationServerMetadata {
            val o = JsonAccess.obj(json, "The authorization server metadata")
            val issuer = JsonAccess.str(o, "issuer") ?: throw ProtocolException("The authorization server metadata has no issuer")
            val token = JsonAccess.url(o, "token_endpoint", base) ?: throw ProtocolException("The authorization server metadata has no token_endpoint")
            val idTypes = JsonAccess.strings(o, "subject_identifier_types_supported")
            return AuthorizationServerMetadata(
                issuer, token, JsonAccess.url(o, "jwks_uri", base), JsonAccess.strings(o, "grant_types_supported"),
                JsonAccess.strings(o, "subject_token_types_supported"), idTypes.ifEmpty { listOf("https") }, o,
            )
        }

        /**
         * The metadata URL of an issuer (RFC 8414 section 3.1): `https://as.example` →
         * `https://as.example/.well-known/lws-configuration`; `https://as.example/t1` →
         * `https://as.example/.well-known/lws-configuration/t1`.
         */
        public fun metadataUrl(issuer: String): String {
            val c = Urls.parse(issuer)
            return (c.scheme ?: "https") + "://" + (c.authority ?: "") + Vocabulary.WELL_KNOWN_LWS_CONFIGURATION + c.path.removeSuffix("/")
        }
    }
}

/**
 * A protected resource's metadata (RFC 9728), which the `resource_metadata` parameter of a `401`'s challenge names.
 *
 * @property resource the resource it describes, as the metadata states it
 * @property authorizationServers the issuers of the authorization servers, in order (at least one)
 * @property raw the document
 */
public class ProtectedResourceMetadata(
    public val resource: String,
    public val authorizationServers: List<String>,
    public val raw: JsonObject = JsonObject(emptyMap()),
) {
    public companion object {
        /**
         * Parses a metadata document.
         *
         * @throws ProtocolException without a string `resource`, or without `authorization_servers` as a non-empty
         *     array of strings (lws10-core makes it required)
         */
        public fun parse(json: JsonElement): ProtectedResourceMetadata {
            val o = JsonAccess.obj(json, "The protected resource metadata")
            val resource = JsonAccess.str(o, "resource") ?: throw ProtocolException("The protected resource metadata has no resource")
            val servers = o["authorization_servers"] as? JsonArray
            if (servers.isNullOrEmpty() || servers.any { (it as? JsonPrimitive)?.isString != true }) {
                throw ProtocolException("The protected resource metadata has no authorization_servers (a non-empty array of issuers)")
            }
            return ProtectedResourceMetadata(resource, JsonAccess.strings(servers), o)
        }
    }
}

/**
 * An access token from a token endpoint.
 *
 * @property expiresAt when it expires
 */
public class AccessToken(public val value: String, public val expiresAt: Instant, public val tokenType: String = "Bearer", public val scope: String? = null) {
    /** Whether the token is still usable at [now], keeping [margin] in reserve. */
    public fun isValid(now: Instant, margin: Duration = Duration.ZERO): Boolean = now.plus(margin.toJavaDuration()) < expiresAt

    override fun toString(): String = "AccessToken($tokenType, expires $expiresAt)"

    public companion object {
        /** The lifetime assumed when neither `expires_in` nor a JWT `exp` is available. */
        public val DEFAULT_LIFETIME: Duration = 300.seconds

        /**
         * Parses a token endpoint success response (RFC 6749 section 5.1). The expiry is `expires_in`, else the
         * token's JWT `exp` claim, else [DEFAULT_LIFETIME].
         *
         * @throws AuthenticationException without a token, or with a token type other than Bearer
         */
        public fun fromTokenResponse(json: JsonObject, now: Instant): AccessToken {
            val token = JsonAccess.str(json, "access_token")
            if (token.isNullOrEmpty()) throw AuthenticationException("The token response has no access_token")
            val type = JsonAccess.str(json, "token_type")
            if (type == null || !type.equals("bearer", ignoreCase = true)) throw AuthenticationException("Unsupported token_type: ${type ?: "none"}")
            val expiresIn = (json["expires_in"] as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toDoubleOrNull()
            val expires = if (expiresIn != null && expiresIn.isFinite()) {
                now.plusMillis((expiresIn * 1000).toLong())
            } else {
                Jwt.expiration(token) ?: now.plus(DEFAULT_LIFETIME.toJavaDuration())
            }
            return AccessToken(token, expires, "Bearer", JsonAccess.str(json, "scope"))
        }
    }
}

/**
 * The LWS authorization flow (lws10-core "Authorization Server Discovery" and "Discovery Validation by a Client"). On a
 * `401` with `WWW-Authenticate: Bearer resource_metadata="…"` and a `Link` to the storage, it checks that the metadata
 * is on the requested origin, reads it (RFC 9728) and checks that it describes the URL requested, reads the storage's
 * description and checks that the storage root is on the requested origin, takes the first authorization server that
 * uses HTTPS and that the filter accepts, reads its metadata, exchanges a subject token from [credentials] for an access
 * token for the storage (OAuth 2.0 token exchange, RFC 8693), and has the request sent again with it. A check that fails
 * stops the flow before anything more is fetched or any credential is sent. The `as_uri` and `realm` challenge of the
 * drafts before 19 October 2026 is still followed, once the realm contains the request.
 *
 * Tokens are cached per (authorization server, storage), sent proactively to URLs inside the storage and its root (the
 * realm, for the earlier challenge), and refreshed [refreshMargin] before they expire. Outside those, a token goes
 * only with the retry of a request whose challenge passed the checks; a later `401` there reuses the cached token.
 * Concurrent requests share one exchange. Storage descriptions are cached too, until [clear].
 *
 * ```kotlin
 * val client = LwsClient(authenticator = TokenExchangeAuthenticator(SelfSignedCredentials.didKey(SigningKey.generateP256())))
 * ```
 *
 * @param allowInsecureHttp allow plain-HTTP authorization servers beyond loopback hosts (testing only)
 * @param authorizationServerFilter decides whether to trust an authorization server (its issuer, first argument) for a
 *     storage (second) before any credential is sent to it. A malicious storage can name any server: self-signed tokens
 *     are audience-bound to it, but static OpenID or SAML tokens may not be, so use this filter or
 *     audience-restricted tokens.
 * @param transport for discovery, metadata and token requests; it must not follow redirects
 * @param timeout the time limit of each discovery, metadata and token request
 * @param userAgent the `User-Agent` of those requests
 * @param clock the clock (for tests)
 */
public class TokenExchangeAuthenticator(
    public val credentials: CredentialProvider,
    private val allowInsecureHttp: Boolean = false,
    private val authorizationServerFilter: ((issuer: String, storage: String) -> Boolean)? = null,
    private val transport: HttpTransport = JdkHttpTransport(),
    private val refreshMargin: Duration = 30.seconds,
    private val timeout: Duration = 30.seconds,
    private val userAgent: String? = LwsClient.DEFAULT_USER_AGENT,
    private val clock: Clock = Clock.systemUTC(),
) : Authenticator {
    /** A token and its scopes, the URLs it is sent to without a challenge: the storage and its root, or the realm. */
    private class Entry(val storage: String, val scopes: List<String>, val token: AccessToken)

    /** Where a challenge leads: the authorization server, the storage to ask it a token for, and the token's scopes. */
    private class Grant(val issuer: String, val storage: String, val scopes: List<String>)

    /** (issuer, storage) → token. */
    private val tokens = ConcurrentHashMap<String, Entry>()

    /** issuer → metadata. */
    private val metadata = ConcurrentHashMap<String, AuthorizationServerMetadata>()

    /** storage → its description. */
    private val descriptions = ConcurrentHashMap<String, StorageDescription>()

    /** (issuer, storage) → the lock of its exchange. */
    private val locks = ConcurrentHashMap<String, Mutex>()

    /** A request whose challenge was handled → the (issuer, storage) of the token its retry carries. */
    private val retries: MutableMap<AuthRequest, String> = Collections.synchronizedMap(WeakHashMap())

    override suspend fun authorize(request: AuthRequest): AuthRequest {
        val now = clock.instant()
        val url = request.url.toString()
        // Of the scopes that contain the URL, the longest path wins.
        val best = tokens.values
            .filter { it.token.isValid(now, refreshMargin) }
            .flatMap { e -> e.scopes.filter { Urls.contains(it, url) }.map { e to Urls.path(it).length } }
            .maxByOrNull { it.second }?.first
        return best?.let { request.withBearerToken(it.token.value) } ?: request
    }

    /**
     * @throws AuthenticationException when a check fails (the metadata is on another origin or describes another
     *     resource, the `401` links to no storage, the storage root is on another origin, the request URL is outside
     *     the realm of an earlier challenge), no authorization server is acceptable, or the token exchange failed. A
     *     cached token stays in use when the challenge is refused.
     */
    override suspend fun handleChallenge(request: AuthRequest, response: AuthResponse): Boolean {
        val bearer = response.challenges.filter { it.isScheme("Bearer") }
        val discovery = bearer.firstOrNull { it.resourceMetadata != null }
        val realmChallenge = bearer.firstOrNull { it.asUri != null && it.realm != null }
        // Every check, and the authorization server metadata, comes before the cached token the request carried is
        // touched: a decoy challenge must not evict a working token.
        val grant = when {
            discovery != null -> discover(request.url, discovery.resourceMetadata!!, response.headers)
            realmChallenge != null -> realmGrant(request.url, realmChallenge.asUri!!, realmChallenge.realm!!)
            else -> return false
        }
        serverMetadata(grant.issuer)
        val key = key(grant.issuer, grant.storage)
        locks.computeIfAbsent(key) { Mutex() }.withLock {
            val cached = tokens[key]
            when {
                cached == null -> exchange(grant)
                request.headers["Authorization"]?.let { carries(it, cached.token) } == true -> {
                    // The storage refused the token this request carried: exchange it for another, once.
                    tokens.remove(key)
                    exchange(grant)
                }
                !cached.token.isValid(clock.instant(), refreshMargin) -> exchange(grant)
                // A token obtained otherwise (accessToken) is sent ahead to the storage root too, now that it is known.
                !cached.scopes.containsAll(grant.scopes) -> {
                    tokens[key] = Entry(grant.storage, (cached.scopes + grant.scopes).distinct(), cached.token)
                }
            }
        }
        retries[request] = key
        return true
    }

    /**
     * The retry carries the token of the challenge it answers, even to a URL outside the token's scope: that URL has
     * just passed the checks.
     */
    override suspend fun authorizeRetry(request: AuthRequest, challenged: AuthRequest): AuthRequest {
        val token = retries.remove(challenged)?.let(tokens::get)?.token?.takeIf { it.isValid(clock.instant(), refreshMargin) }
        return token?.let { request.withBearerToken(it.value) } ?: authorize(request)
    }

    /**
     * A valid access token for a storage, performing the token exchange when needed. A token obtained here is sent
     * ahead to URLs inside [storage].
     *
     * @throws AuthenticationException when the exchange fails
     * @throws IllegalArgumentException when [issuer] or [storage] is not an absolute http(s) URL
     */
    public suspend fun accessToken(issuer: String, storage: String): AccessToken {
        require(Urls.isHttp(issuer)) { "issuer is not an absolute http(s) URL: $issuer" }
        require(Urls.isHttp(storage)) { "storage is not an absolute http(s) URL: $storage" }
        val key = key(issuer, storage)
        return locks.computeIfAbsent(key) { Mutex() }.withLock {
            tokens[key]?.token?.takeIf { it.isValid(clock.instant(), refreshMargin) } ?: run {
                requireSecure(issuer, "authorization server")
                exchange(Grant(issuer, storage, listOf(storage)))
            }
        }
    }

    /** Forgets every cached token, metadata document and storage description. */
    public fun clear() {
        tokens.clear()
        metadata.clear()
        descriptions.clear()
    }

    /**
     * The checks of a challenge with `resource_metadata` (RFC 9728), in the order of lws10-core "Discovery Validation
     * by a Client", and the authorization server they lead to.
     */
    private suspend fun discover(url: URI, resourceMetadata: String, headers: Headers): Grant {
        val requested = url.toString()
        val metadataUrl = Urls.resolve(resourceMetadata, requested)?.takeIf(Urls::isHttp)
            ?: throw AuthenticationException("The challenge resource_metadata is not a URL: $resourceMetadata")
        if (!Urls.sameOrigin(metadataUrl, requested)) {
            throw AuthenticationException("The protected resource metadata $metadataUrl is not on the origin of $requested")
        }
        val storage = Link.first(LinkHeader.parse(headers.all("link"), url), LinkRelation.STORAGE)?.href?.toString()
            ?: throw AuthenticationException("The 401 for $requested has no storage link (rel=\"${LinkRelation.STORAGE}\")")
        if (!Urls.isHttp(storage)) throw AuthenticationException("The storage of $requested is not an http(s) URL: $storage")
        val prm = protectedResourceMetadata(metadataUrl)
        if (!Urls.sameResource(prm.resource, requested)) {
            throw AuthenticationException("The protected resource metadata $metadataUrl describes ${prm.resource}, not $requested")
        }
        val root = storageRoot(storage)
        if (!Urls.sameOrigin(root, requested)) {
            throw AuthenticationException("The storage root $root of $storage is not on the origin of $requested")
        }
        val refusals = mutableListOf<String>()
        for (issuer in prm.authorizationServers) {
            refusals += refusal(issuer, storage) ?: return Grant(issuer, storage, listOf(storage, root))
        }
        throw AuthenticationException("No authorization server of $metadataUrl is acceptable: ${refusals.joinToString("; ")}")
    }

    /** The challenge of the drafts before 19 October 2026: the realm must contain the request, and is the storage. */
    private fun realmGrant(url: URI, asUri: String, realm: String): Grant {
        if (!Urls.isHttp(asUri)) throw AuthenticationException("The challenge as_uri is not an absolute URL: $asUri")
        if (!Urls.isHttp(realm)) throw AuthenticationException("The challenge realm is not an absolute URL: $realm")
        if (!Urls.contains(realm, url.toString())) throw AuthenticationException("Request URL $url is not within the challenge realm $realm")
        refusal(asUri, realm)?.let { throw AuthenticationException(it) }
        return Grant(asUri, realm, listOf(realm))
    }

    /** Why an authorization server must not be asked for a token for a storage, or null when it may. */
    private fun refusal(issuer: String, storage: String): String? = when {
        !Urls.isHttp(issuer) -> "The authorization server $issuer is not an absolute http(s) URL"
        !isSecure(issuer) -> "Refusing to use the insecure authorization server $issuer (HTTPS required)"
        authorizationServerFilter?.invoke(issuer, storage) == false -> "Authorization server $issuer was rejected by the authorization server filter"
        else -> null
    }

    private suspend fun exchange(grant: Grant): AccessToken {
        val md = serverMetadata(grant.issuer)
        requireSecure(md.tokenEndpoint.toString(), "token endpoint")
        val type = credentials.tokenType
        if (!md.supportsSubjectTokenType(type)) {
            throw AuthenticationException(
                "Authorization server ${grant.issuer} does not accept subject tokens of type $type (supported: ${md.subjectTokenTypesSupported.joinToString(", ")})",
            )
        }
        val subjectToken = credentials.subjectToken(CredentialContext(grant.issuer, grant.storage, md))
        val form = listOf(
            "grant_type" to Vocabulary.GRANT_TYPE_TOKEN_EXCHANGE,
            "resource" to grant.storage,
            "subject_token" to subjectToken,
            "subject_token_type" to type,
        ).joinToString("&") { (k, v) -> k + "=" + URLEncoder.encode(v, Charsets.UTF_8) }
        val r = send(
            HttpRequest("POST", md.tokenEndpoint, Headers.of("Content-Type" to MediaType.FORM, "Accept" to MediaType.JSON), form.toByteArray()),
            "token endpoint",
        )
        val json = if (r.body.isEmpty()) {
            null
        } else {
            try {
                JsonAccess.decode(r.body) as? JsonObject
            } catch (_: Exception) {
                null
            }
        }
        if (r.status / 100 != 2) {
            val error = json?.let { JsonAccess.str(it, "error") }
            val description = json?.let { JsonAccess.str(it, "error_description") }
            throw AuthenticationException(
                "Token exchange at ${md.tokenEndpoint} failed with HTTP ${r.status}" + (error?.let { ": $it" } ?: "") + (description?.let { " ($it)" } ?: ""),
                error, description, r.status,
            )
        }
        if (json == null) throw AuthenticationException("The token endpoint returned no JSON object", status = r.status)
        val token = try {
            AccessToken.fromTokenResponse(json, clock.instant())
        } catch (e: AuthenticationException) {
            throw AuthenticationException(e.message ?: "Invalid token response", status = r.status, cause = e)
        }
        tokens[key(grant.issuer, grant.storage)] = Entry(grant.storage, grant.scopes, token)
        return token
    }

    /** The protected resource metadata (not cached: it describes one resource). */
    private suspend fun protectedResourceMetadata(url: String): ProtectedResourceMetadata {
        val (json, r) = document(url, MediaType.JSON, "protected resource metadata")
        return try {
            ProtectedResourceMetadata.parse(json)
        } catch (e: ProtocolException) {
            throw AuthenticationException("Invalid protected resource metadata at $url: ${e.message}", status = r.status, cause = e)
        }
    }

    /** The root of a storage, from its description (cached per storage). */
    private suspend fun storageRoot(storage: String): String {
        val description = descriptions[storage] ?: run {
            val (json, r) = document(storage, LwsClient.ACCEPT_DESCRIPTION, "storage description")
            val parsed = try {
                StorageDescription.parse(json, r.url)
            } catch (e: ProtocolException) {
                throw AuthenticationException("Invalid storage description at $storage: ${e.message}", status = r.status, cause = e)
            }
            descriptions[storage] = parsed
            parsed
        }
        return try {
            description.storageRoot().toString()
        } catch (e: ProtocolException) {
            throw AuthenticationException(e.message ?: "The storage description $storage has no StorageRoot service", cause = e)
        }
    }

    private suspend fun serverMetadata(issuer: String): AuthorizationServerMetadata {
        metadata[issuer]?.let { return it }
        val url = AuthorizationServerMetadata.metadataUrl(issuer)
        val (json, r) = document(url, MediaType.JSON, "authorization server metadata")
        val md = try {
            AuthorizationServerMetadata.parse(json, r.url)
        } catch (e: ProtocolException) {
            throw AuthenticationException("Invalid authorization server metadata at $url: ${e.message}", status = r.status, cause = e)
        }
        val same = Urls.equalsIgnoringTrailingSlash(md.issuer, issuer) ||
            (Urls.isHttp(md.issuer) && Urls.equalsIgnoringTrailingSlash(Urls.canonical(md.issuer), Urls.canonical(issuer)))
        if (!same) throw AuthenticationException("The authorization server metadata issuer ${md.issuer} does not match the issuer $issuer", status = r.status)
        metadata[issuer] = md
        return md
    }

    /**
     * GETs a discovery or metadata document, without credentials; anything but a `200` with a JSON body (a storage
     * description included) is an [AuthenticationException].
     */
    private suspend fun document(url: String, accept: String, what: String): Pair<JsonElement, HttpResponse> {
        val target = Urls.toUri(url) ?: throw AuthenticationException("Invalid $what URL $url")
        val r = send(HttpRequest("GET", target, Headers.of("Accept" to accept)), what)
        if (r.status != 200) throw AuthenticationException("Cannot read the $what $url: HTTP ${r.status}", status = r.status)
        val type = r.headers["content-type"]
        if (type != null && !HeaderLists.isJson(type) && HeaderLists.essence(type) != MediaType.LWS_CID) {
            throw AuthenticationException("The $what $url is not JSON", status = r.status)
        }
        val json = try {
            JsonAccess.parse(r.body, "The $what")
        } catch (e: ProtocolException) {
            throw AuthenticationException("Invalid $what at $url: ${e.message}", status = r.status, cause = e)
        }
        return json to r
    }

    /**
     * Sends a discovery, metadata or token request; a redirect is refused, since it would carry credentials (or the
     * flow) to another URL.
     */
    private suspend fun send(request: HttpRequest, what: String): HttpResponse {
        val headers = userAgent?.let { request.headers.with("User-Agent", it) } ?: request.headers
        val response = transport.send(HttpRequest(request.method, request.url, headers, request.body, timeout))
        if (response.status in 300..399 || response.url != request.url) {
            val location = response.headers["location"]
            throw AuthenticationException(
                "Refusing the redirect" + (location?.let { " to $it" } ?: "") +
                    " of the $what request ${request.url} (HTTP ${response.status}): it would carry credentials to another URL",
                status = response.status,
            )
        }
        return response
    }

    private fun isSecure(url: String): Boolean {
        val scheme = Urls.scheme(url)
        return scheme == "https" || (scheme == "http" && (allowInsecureHttp || Urls.isLoopback(url)))
    }

    private fun requireSecure(url: String, what: String) {
        if (!isSecure(url)) throw AuthenticationException("Refusing to use the insecure $what $url (HTTPS required)")
    }

    /** Whether an `Authorization` header carries the token (compared in constant time). */
    private fun carries(authorization: String, token: AccessToken): Boolean =
        MessageDigest.isEqual(("Bearer " + token.value).toByteArray(), authorization.toByteArray())

    private fun key(issuer: String, storage: String): String = "$issuer $storage"

    override fun toString(): String = "TokenExchangeAuthenticator($credentials, storages=${tokens.values.map { it.storage }})"
}
