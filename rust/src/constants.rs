// SPDX-License-Identifier: MIT
//! Shared protocol constants (namespaces, link relations, media types, service types, OAuth
//! identifiers, access-profile terms).
//!
//! The values are identical across all `lws-client` implementations; see the cross-language
//! API contract.

/// The LWS vocabulary namespace.
pub const LWS_NS: &str = "https://www.w3.org/ns/lws#";
/// The LWS JSON-LD context.
pub const LWS_CONTEXT: &str = "https://www.w3.org/ns/lws/v1";
/// The W3C Controlled Identifiers JSON-LD context.
pub const CID_CONTEXT: &str = "https://www.w3.org/ns/cid/v1";
/// The Activity Streams 2.0 JSON-LD context.
pub const ACTIVITYSTREAMS_CONTEXT: &str = "https://www.w3.org/ns/activitystreams";
/// The `.well-known` path of LWS authorization server metadata (RFC 8414 style).
pub const WELL_KNOWN_LWS_CONFIGURATION: &str = "/.well-known/lws-configuration";

/// Link relation types used by LWS.
pub mod rel {
    /// Link to the storage (description) a resource belongs to.
    pub const STORAGE: &str = "https://www.w3.org/ns/lws#storage";
    /// Link to a resource's linkset (metadata) resource.
    pub const LINKSET: &str = "linkset";
    /// Link to the parent container.
    pub const UP: &str = "up";
    /// Link to a type of the resource.
    pub const TYPE: &str = "type";
    /// First page of a paginated listing.
    pub const FIRST: &str = "first";
    /// Next page of a paginated listing.
    pub const NEXT: &str = "next";
    /// Previous page of a paginated listing.
    pub const PREV: &str = "prev";
    /// Last page of a paginated listing.
    pub const LAST: &str = "last";
}

/// Resource type IRIs. Short terms (`"Container"`) and compact IRIs (`"lws:Container"`) are
/// equivalent; see [`crate::types::type_matches`].
pub mod types {
    /// `lws:Container`.
    pub const CONTAINER: &str = "https://www.w3.org/ns/lws#Container";
    /// `lws:DataResource`.
    pub const DATA_RESOURCE: &str = "https://www.w3.org/ns/lws#DataResource";
    /// `lws:StorageResource` (matches any storage resource in access targets).
    pub const STORAGE_RESOURCE: &str = "https://www.w3.org/ns/lws#StorageResource";
    /// `lws:Storage` (the type of a storage description).
    pub const STORAGE: &str = "https://www.w3.org/ns/lws#Storage";
}

/// Media types.
pub mod media_type {
    /// LWS container representations, access documents, subscriptions.
    pub const LWS_JSON: &str = "application/lws+json";
    /// Storage description documents.
    pub const LWS_CID: &str = "application/lws+cid";
    /// RFC 9264 linksets.
    pub const LINKSET_JSON: &str = "application/linkset+json";
    /// RFC 6902 JSON Patch.
    pub const JSON_PATCH: &str = "application/json-patch+json";
    /// Type Search Service filter documents.
    pub const LWS_QUERY_JSON: &str = "application/lws-query+json";
    /// JSON-LD.
    pub const LD_JSON: &str = "application/ld+json";
    /// JSON.
    pub const JSON: &str = "application/json";
    /// RFC 9457 problem details.
    pub const PROBLEM_JSON: &str = "application/problem+json";
    /// HTML form encoding (token requests).
    pub const FORM: &str = "application/x-www-form-urlencoded";
}

/// Service types found in a storage description's `service` array.
pub mod service {
    /// The storage root container.
    pub const STORAGE_ROOT: &str = "StorageRoot";
    /// Notification subscriptions.
    pub const NOTIFICATION: &str = "NotificationService";
    /// Access request endpoint.
    pub const ACCESS_REQUEST: &str = "AccessRequestService";
    /// Access grant endpoint.
    pub const ACCESS_GRANT: &str = "AccessGrantService";
    /// Type Index Service.
    pub const TYPE_INDEX: &str = "TypeIndexService";
    /// Type Search Service.
    pub const TYPE_SEARCH: &str = "TypeSearchService";
    /// Webhook subscription type.
    pub const SUBSCRIPTION_WEBHOOK: &str = "WebhookSubscription";
}

/// OAuth 2.0 / authentication suite identifiers.
pub mod oauth {
    /// RFC 8693 token exchange grant type.
    pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
    /// OpenID Connect ID token (OpenID Connect authentication suite).
    pub const TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
    /// SAML 2.0 assertion (SAML authentication suite).
    pub const TOKEN_TYPE_SAML2: &str = "urn:ietf:params:oauth:token-type:saml2";
    /// Self-issued JWT (self-signed CID / did:key authentication suites).
    pub const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
    /// OAuth access token.
    pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
    /// Service type marking an agent's OpenID provider in its CID document.
    pub const OPENID_PROVIDER_SERVICE: &str = "https://www.w3.org/ns/lws#OpenIdProvider";
}

/// Access requests and grants (ODRL-based access profile).
pub mod access {
    /// The LWS access profile identifier.
    pub const ACCESS_PROFILE: &str = "https://www.w3.org/ns/lws#AccessProfile";
    /// Type of an access request document.
    pub const TYPE_ACCESS_REQUEST: &str = "AccessRequest";
    /// Type of an access grant document.
    pub const TYPE_ACCESS_GRANT: &str = "AccessGrant";
    /// Type of an access policy.
    pub const TYPE_ACCESS_POLICY: &str = "AccessPolicy";
    /// Read action (GET, HEAD).
    pub const ACTION_READ: &str = "read";
    /// Modify action (PUT, PATCH).
    pub const ACTION_MODIFY: &str = "modify";
    /// Create action (POST).
    pub const ACTION_CREATE: &str = "create";
    /// Delete action (DELETE).
    pub const ACTION_DELETE: &str = "delete";
    /// Constraint operand: client identifier.
    pub const OPERAND_CLIENT: &str = "client";
    /// Constraint operand: media type of the target.
    pub const OPERAND_FORMAT: &str = "format";
    /// Constraint operand: resource type.
    pub const OPERAND_TYPE: &str = "type";
    /// Constraint operand: purpose.
    pub const OPERAND_PURPOSE: &str = "purpose";
    /// Constraint operand: current date-time.
    pub const OPERAND_DATE_TIME: &str = "dateTime";
    /// Operator: equal.
    pub const OPERATOR_EQ: &str = "eq";
    /// Operator: any of.
    pub const OPERATOR_IS_ANY_OF: &str = "isAnyOf";
    /// Operator: greater than or equal.
    pub const OPERATOR_GTEQ: &str = "gteq";
    /// Operator: less than or equal.
    pub const OPERATOR_LTEQ: &str = "lteq";
    /// The public agent class (FOAF), used to grant public access.
    pub const PUBLIC_AGENT: &str = "http://xmlns.com/foaf/0.1/Agent";
}

/// `Prefer` header values.
pub mod prefer {
    /// Apply `Link` headers sent with PUT/PATCH to the resource's linkset.
    pub const SET_LINKSET: &str = "set-linkset";
    /// Preference URI for including or omitting link relations.
    pub const LINK_RELATIONS: &str = "https://www.w3.org/ns/lws#PreferLinkRelations";
}

/// Activity Streams activity types used in notifications.
pub mod activity {
    /// A resource was created.
    pub const CREATE: &str = "Create";
    /// A resource was updated.
    pub const UPDATE: &str = "Update";
    /// A resource was deleted.
    pub const DELETE: &str = "Delete";
}

/// Default `User-Agent` sent by [`crate::Client`].
pub const USER_AGENT: &str = concat!("lws-client-rust/", env!("CARGO_PKG_VERSION"));
