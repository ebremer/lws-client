// SPDX-License-Identifier: MIT

/// Namespaces, contexts and identifiers of the Linked Web Storage protocol family, and type matching.
///
/// JSON documents use short terms (`"Container"`), compact IRIs (`"lws:Container"`) and full IRIs
/// (`"https://www.w3.org/ns/lws#Container"`) interchangeably; ``typeMatches(_:_:)`` treats them as equal.
public enum Vocabulary {
    /// The LWS vocabulary namespace.
    public static let namespace = "https://www.w3.org/ns/lws#"
    /// The LWS JSON-LD context.
    public static let context = "https://www.w3.org/ns/lws/v1"
    /// The W3C Controlled Identifiers JSON-LD context.
    public static let cidContext = "https://www.w3.org/ns/cid/v1"
    /// The Activity Streams 2.0 JSON-LD context.
    public static let activityStreamsContext = "https://www.w3.org/ns/activitystreams"
    /// The OAuth 2.0 token exchange grant type (RFC 8693).
    public static let grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
    /// The well-known path of LWS authorization server metadata.
    public static let wellKnownLWSConfiguration = "/.well-known/lws-configuration"
    /// The service type of an OpenID provider in a controlled identifier document.
    public static let openIDProviderService = namespace + "OpenIdProvider"
    /// The LWS ODRL-based access profile.
    public static let accessProfile = namespace + "AccessProfile"
    /// The public access assignee (`foaf:Agent`).
    public static let publicAgent = "http://xmlns.com/foaf/0.1/Agent"

    /// Expands an LWS term to its full IRI: `Container` and `lws:Container` become
    /// `https://www.w3.org/ns/lws#Container`; values that already are IRIs are returned unchanged.
    public static func expandType(_ type: String) -> String {
        if type.hasPrefix("lws:") { return namespace + type.dropFirst(4) }
        if !type.contains(":") { return namespace + type }
        return type
    }

    /// Whether two type values denote the same type (`Term`, `lws:Term` and the full IRI are equal).
    public static func typeMatches(_ a: String, _ b: String) -> Bool {
        a == b || expandType(a) == expandType(b)
    }

    /// Whether `types` contains a value matching `type`.
    public static func hasType<S: Sequence>(_ types: S, _ type: String) -> Bool where S.Element == String {
        types.contains { typeMatches($0, type) }
    }
}

/// Link relation types.
public enum LinkRelation {
    /// The storage a resource belongs to.
    public static let storage = Vocabulary.namespace + "storage"
    /// The linkset (metadata) resource.
    public static let linkset = "linkset"
    /// The parent container.
    public static let up = "up"
    /// A resource type.
    public static let type = "type"
    /// The first page.
    public static let first = "first"
    /// The next page.
    public static let next = "next"
    /// The previous page.
    public static let prev = "prev"
    /// The last page.
    public static let last = "last"
}

/// Resource and document types.
public enum ResourceType {
    /// A container.
    public static let container = Vocabulary.namespace + "Container"
    /// A data resource.
    public static let dataResource = Vocabulary.namespace + "DataResource"
    /// Any storage resource (container or data resource).
    public static let storageResource = Vocabulary.namespace + "StorageResource"
    /// A storage description.
    public static let storage = "Storage"
    /// A notification envelope.
    public static let notification = "Notification"
    /// A page of type search results.
    public static let containerPage = "ContainerPage"
    /// A type index page.
    public static let typeIndex = "TypeIndex"
    /// An access request.
    public static let accessRequest = "AccessRequest"
    /// An access grant.
    public static let accessGrant = "AccessGrant"
    /// An access policy.
    public static let accessPolicy = "AccessPolicy"
}

/// Media types used by LWS.
public enum MediaType {
    /// `application/lws+json`.
    public static let lwsJSON = "application/lws+json"
    /// `application/lws+cid` (storage descriptions).
    public static let lwsCID = "application/lws+cid"
    /// `application/linkset+json` (RFC 9264).
    public static let linksetJSON = "application/linkset+json"
    /// `application/json-patch+json` (RFC 6902), the baseline PATCH format.
    public static let jsonPatch = "application/json-patch+json"
    /// `application/lws-query+json` (type search filters).
    public static let lwsQueryJSON = "application/lws-query+json"
    /// `application/ld+json`.
    public static let ldJSON = "application/ld+json"
    /// `application/json`.
    public static let json = "application/json"
    /// `application/problem+json` (RFC 9457).
    public static let problemJSON = "application/problem+json"
    /// `application/x-www-form-urlencoded`.
    public static let form = "application/x-www-form-urlencoded"
}

/// Storage description service types (`service[].type`).
public enum ServiceType {
    /// The storage root container.
    public static let storageRoot = "StorageRoot"
    /// The notification service.
    public static let notification = "NotificationService"
    /// The access request service.
    public static let accessRequest = "AccessRequestService"
    /// The access grant service.
    public static let accessGrant = "AccessGrantService"
    /// The type index service.
    public static let typeIndex = "TypeIndexService"
    /// The type search service.
    public static let typeSearch = "TypeSearchService"
}

/// Notification subscription types.
public enum SubscriptionType {
    /// The webhook subscription type.
    public static let webhook = "WebhookSubscription"
}

/// OAuth token type identifiers used by the LWS authentication suites.
public enum TokenType {
    /// OpenID Connect suite: an ID token.
    public static let idToken = "urn:ietf:params:oauth:token-type:id_token"
    /// SAML 2.0 suite: a base64url-encoded assertion.
    public static let saml2 = "urn:ietf:params:oauth:token-type:saml2"
    /// Self-signed (controlled identifier, did:key) suites: a JWT.
    public static let jwt = "urn:ietf:params:oauth:token-type:jwt"
    /// An OAuth access token.
    public static let accessToken = "urn:ietf:params:oauth:token-type:access_token"
}

/// Access profile actions.
public enum AccessAction {
    /// `read`.
    public static let read = "read"
    /// `modify`.
    public static let modify = "modify"
    /// `create`.
    public static let create = "create"
    /// `delete`.
    public static let delete = "delete"
}

/// Access profile constraint left operands.
public enum ConstraintOperand {
    /// `client`.
    public static let client = "client"
    /// `format`.
    public static let format = "format"
    /// `type`.
    public static let type = "type"
    /// `purpose`.
    public static let purpose = "purpose"
    /// `dateTime`.
    public static let dateTime = "dateTime"
}

/// Access profile constraint operators.
public enum ConstraintOperator {
    /// `eq`.
    public static let eq = "eq"
    /// `isAnyOf`.
    public static let isAnyOf = "isAnyOf"
    /// `gteq`.
    public static let gteq = "gteq"
    /// `lteq`.
    public static let lteq = "lteq"
}

/// `Prefer` header values.
public enum Prefer {
    /// Update the content and the linkset atomically.
    public static let setLinkset = "set-linkset"
    /// The link relation preference.
    public static let linkRelations = Vocabulary.namespace + "PreferLinkRelations"
}

/// Activity Streams activity types used in notifications.
public enum ActivityType {
    /// A resource was created.
    public static let create = "Create"
    /// A resource was updated.
    public static let update = "Update"
    /// A resource was deleted.
    public static let delete = "Delete"
}
