// SPDX-License-Identifier: MIT
package com.ebremer.lws.kotlin

/**
 * LWS namespaces and contexts, OAuth and access profile identifiers, and type matching.
 *
 * JSON documents use short terms (`Container`), compact IRIs (`lws:Container`) and full IRIs
 * (`https://www.w3.org/ns/lws#Container`) interchangeably; [typeMatches] treats them as equal.
 */
public object Vocabulary {
    public const val LWS_NS: String = "https://www.w3.org/ns/lws#"
    public const val LWS_CONTEXT: String = "https://www.w3.org/ns/lws/v1"
    public const val CID_CONTEXT: String = "https://www.w3.org/ns/cid/v1"
    public const val ACTIVITYSTREAMS_CONTEXT: String = "https://www.w3.org/ns/activitystreams"
    public const val GRANT_TYPE_TOKEN_EXCHANGE: String = "urn:ietf:params:oauth:grant-type:token-exchange"
    public const val WELL_KNOWN_LWS_CONFIGURATION: String = "/.well-known/lws-configuration"
    public const val OPENID_PROVIDER_SERVICE: String = "https://www.w3.org/ns/lws#OpenIdProvider"
    public const val ACCESS_PROFILE: String = "https://www.w3.org/ns/lws#AccessProfile"
    public const val PUBLIC_AGENT: String = "http://xmlns.com/foaf/0.1/Agent"

    /** The full IRI of a type value: `Container` and `lws:Container` become `https://www.w3.org/ns/lws#Container`. */
    public fun expandType(type: String): String = when {
        type.startsWith("lws:") -> LWS_NS + type.substring(4)
        ':' in type -> type
        else -> LWS_NS + type
    }

    /** Whether two type values name the same type (short term, `lws:` compact IRI or full IRI). */
    public fun typeMatches(a: String, b: String): Boolean = a == b || expandType(a) == expandType(b)

    /** Whether [types] holds [type], in any of its forms. */
    public fun hasType(types: Iterable<String>, type: String): Boolean = types.any { typeMatches(it, type) }
}

/** Link relation types. */
public object LinkRelation {
    public const val STORAGE: String = "https://www.w3.org/ns/lws#storage"
    public const val LINKSET: String = "linkset"
    public const val UP: String = "up"
    public const val TYPE: String = "type"
    public const val FIRST: String = "first"
    public const val NEXT: String = "next"
    public const val PREV: String = "prev"
    public const val LAST: String = "last"
}

/**
 * Resource and document types. The three resource types are full IRIs (short terms are equivalent, see
 * [Vocabulary.typeMatches]).
 */
public object ResourceType {
    public const val CONTAINER: String = "https://www.w3.org/ns/lws#Container"
    public const val DATA_RESOURCE: String = "https://www.w3.org/ns/lws#DataResource"
    public const val STORAGE_RESOURCE: String = "https://www.w3.org/ns/lws#StorageResource"
    public const val STORAGE: String = "Storage"
    public const val NOTIFICATION: String = "Notification"
    public const val CONTAINER_PAGE: String = "ContainerPage"
    public const val TYPE_INDEX: String = "TypeIndex"
    public const val ACCESS_REQUEST: String = "AccessRequest"
    public const val ACCESS_GRANT: String = "AccessGrant"
    public const val ACCESS_POLICY: String = "AccessPolicy"
}

/** Media types. */
public object MediaType {
    public const val LWS_JSON: String = "application/lws+json"
    public const val LWS_CID: String = "application/lws+cid"
    public const val LINKSET_JSON: String = "application/linkset+json"
    public const val JSON_PATCH: String = "application/json-patch+json"
    public const val LWS_QUERY_JSON: String = "application/lws-query+json"
    public const val LD_JSON: String = "application/ld+json"
    public const val JSON: String = "application/json"
    public const val PROBLEM_JSON: String = "application/problem+json"
    public const val FORM: String = "application/x-www-form-urlencoded"
}

/** Service types of a storage description (`service[].type`). */
public object ServiceType {
    public const val STORAGE_ROOT: String = "StorageRoot"
    public const val NOTIFICATION: String = "NotificationService"
    public const val ACCESS_REQUEST: String = "AccessRequestService"
    public const val ACCESS_GRANT: String = "AccessGrantService"
    public const val TYPE_INDEX: String = "TypeIndexService"
    public const val TYPE_SEARCH: String = "TypeSearchService"
}

/** Notification subscription types. */
public object SubscriptionType {
    public const val WEBHOOK: String = "WebhookSubscription"
}

/** OAuth 2.0 token type URIs (RFC 8693) of the LWS authentication suites. */
public object TokenType {
    public const val ID_TOKEN: String = "urn:ietf:params:oauth:token-type:id_token"
    public const val SAML2: String = "urn:ietf:params:oauth:token-type:saml2"
    public const val JWT: String = "urn:ietf:params:oauth:token-type:jwt"
    public const val ACCESS_TOKEN: String = "urn:ietf:params:oauth:token-type:access_token"
}

/** Access profile actions. */
public object AccessAction {
    public const val READ: String = "read"
    public const val MODIFY: String = "modify"
    public const val CREATE: String = "create"
    public const val DELETE: String = "delete"
}

/** Access policy constraint left operands. */
public object ConstraintOperand {
    public const val CLIENT: String = "client"
    public const val FORMAT: String = "format"
    public const val TYPE: String = "type"
    public const val PURPOSE: String = "purpose"
    public const val DATE_TIME: String = "dateTime"
}

/** Access policy constraint operators. */
public object ConstraintOperator {
    public const val EQ: String = "eq"
    public const val IS_ANY_OF: String = "isAnyOf"
    public const val GTEQ: String = "gteq"
    public const val LTEQ: String = "lteq"
}

/** `Prefer` header values. */
public object Prefer {
    public const val SET_LINKSET: String = "set-linkset"
    public const val LINK_RELATIONS: String = "https://www.w3.org/ns/lws#PreferLinkRelations"
}

/** Notification activity types. */
public object ActivityType {
    public const val CREATE: String = "Create"
    public const val UPDATE: String = "Update"
    public const val DELETE: String = "Delete"
}
