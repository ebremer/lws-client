// SPDX-License-Identifier: MIT
/**
 * Shared constants of the W3C Linked Web Storage protocol family
 * (lws10-core, auth suites, webhook notifications, type index/search).
 *
 * @module
 */

/** Package version. */
export const VERSION = "0.1.0";

/** The LWS vocabulary namespace. */
export const LWS_NS = "https://www.w3.org/ns/lws#";
/** The LWS JSON-LD context. */
export const LWS_CONTEXT = "https://www.w3.org/ns/lws/v1";
/** The W3C Controlled Identifiers v1 JSON-LD context. */
export const CID_CONTEXT = "https://www.w3.org/ns/cid/v1";
/** The Activity Streams 2.0 JSON-LD context. */
export const ACTIVITYSTREAMS_CONTEXT = "https://www.w3.org/ns/activitystreams";
/** The Activity Streams 2.0 namespace. */
export const ACTIVITYSTREAMS_NS = "https://www.w3.org/ns/activitystreams#";

/** Link relation types used by LWS. */
export const Rel = {
  STORAGE: "https://www.w3.org/ns/lws#storage",
  LINKSET: "linkset",
  UP: "up",
  TYPE: "type",
  FIRST: "first",
  NEXT: "next",
  PREV: "prev",
  LAST: "last",
} as const;

/** LWS resource types (full IRIs). */
export const LwsType = {
  CONTAINER: "https://www.w3.org/ns/lws#Container",
  DATA_RESOURCE: "https://www.w3.org/ns/lws#DataResource",
  STORAGE_RESOURCE: "https://www.w3.org/ns/lws#StorageResource",
} as const;

/** Media types used by LWS. */
export const MediaType = {
  LWS_JSON: "application/lws+json",
  LWS_CID: "application/lws+cid",
  LINKSET_JSON: "application/linkset+json",
  JSON_PATCH: "application/json-patch+json",
  LWS_QUERY_JSON: "application/lws-query+json",
  LD_JSON: "application/ld+json",
  JSON: "application/json",
  PROBLEM_JSON: "application/problem+json",
  FORM: "application/x-www-form-urlencoded",
} as const;

/** Service types found in a storage description's `service` array. */
export const ServiceType = {
  STORAGE_ROOT: "StorageRoot",
  NOTIFICATION: "NotificationService",
  ACCESS_REQUEST: "AccessRequestService",
  ACCESS_GRANT: "AccessGrantService",
  TYPE_INDEX: "TypeIndexService",
  TYPE_SEARCH: "TypeSearchService",
} as const;

/** The webhook notification suite's subscription type. */
export const SUBSCRIPTION_WEBHOOK = "WebhookSubscription";

/** OAuth 2.0 Token Exchange grant type (RFC 8693). */
export const GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

/** Subject token types of the LWS authentication suites. */
export const TokenType = {
  /** OpenID Connect suite (lws10-authn-openid). */
  ID_TOKEN: "urn:ietf:params:oauth:token-type:id_token",
  /** SAML 2.0 suite (lws10-authn-saml). */
  SAML2: "urn:ietf:params:oauth:token-type:saml2",
  /** Self-signed suites (lws10-authn-ssi-cid, did:key). */
  JWT: "urn:ietf:params:oauth:token-type:jwt",
  ACCESS_TOKEN: "urn:ietf:params:oauth:token-type:access_token",
} as const;

/** Path of the LWS authorization server metadata document. */
export const WELL_KNOWN_LWS_CONFIGURATION = "/.well-known/lws-configuration";
/** CID service type pointing at an agent's OpenID provider. */
export const OPENID_PROVIDER_SERVICE = "https://www.w3.org/ns/lws#OpenIdProvider";

/** The ODRL-based LWS access profile. */
export const ACCESS_PROFILE = "https://www.w3.org/ns/lws#AccessProfile";

/** Document types of access requests, grants and policies. */
export const AccessType = {
  REQUEST: "AccessRequest",
  GRANT: "AccessGrant",
  POLICY: "AccessPolicy",
} as const;

/** Access actions. */
export const Action = {
  READ: "read",
  MODIFY: "modify",
  CREATE: "create",
  DELETE: "delete",
} as const;

/** Constraint left operands supported by the LWS access profile. */
export const Operand = {
  CLIENT: "client",
  FORMAT: "format",
  TYPE: "type",
  PURPOSE: "purpose",
  DATE_TIME: "dateTime",
} as const;

/** Constraint operators. */
export const Operator = {
  EQ: "eq",
  IS_ANY_OF: "isAnyOf",
  GTEQ: "gteq",
  LTEQ: "lteq",
} as const;

/** The FOAF Agent class, used as assignee for public access. */
export const PUBLIC_AGENT = "http://xmlns.com/foaf/0.1/Agent";

/** `Prefer` header values. */
export const Prefer = {
  SET_LINKSET: "set-linkset",
  LINK_RELATIONS: "https://www.w3.org/ns/lws#PreferLinkRelations",
} as const;

/** Activity Streams activity types used in notifications. */
export const ActivityType = {
  CREATE: "Create",
  UPDATE: "Update",
  DELETE: "Delete",
} as const;
