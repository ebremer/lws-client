// SPDX-License-Identifier: MIT

package lws

// Version is the version of this client library.
const Version = "0.1.0"

// DefaultUserAgent is the User-Agent sent when none is configured.
const DefaultUserAgent = "lws-client-go/" + Version

// Namespaces and JSON-LD contexts.
const (
	LWSNamespace           = "https://www.w3.org/ns/lws#"
	LWSContext             = "https://www.w3.org/ns/lws/v1"
	CIDContext             = "https://www.w3.org/ns/cid/v1"
	ActivityStreamsContext = "https://www.w3.org/ns/activitystreams"
)

// Link relation types used by LWS.
const (
	RelStorage = LWSNamespace + "storage"
	RelLinkset = "linkset"
	RelUp      = "up"
	RelType    = "type"
	RelFirst   = "first"
	RelNext    = "next"
	RelPrev    = "prev"
	RelLast    = "last"
)

// Resource types. The short terms "Container", "DataResource" and
// "StorageResource" (and their "lws:" compact forms) are equivalent; see
// [TypeEquals].
const (
	TypeContainer       = LWSNamespace + "Container"
	TypeDataResource    = LWSNamespace + "DataResource"
	TypeStorageResource = LWSNamespace + "StorageResource"
	TypeStorage         = "Storage"
)

// Media types.
const (
	MediaLWSJSON      = "application/lws+json"
	MediaLWSCID       = "application/lws+cid"
	MediaLinksetJSON  = "application/linkset+json"
	MediaJSONPatch    = "application/json-patch+json"
	MediaLWSQueryJSON = "application/lws-query+json"
	MediaLDJSON       = "application/ld+json"
	MediaJSON         = "application/json"
	MediaProblemJSON  = "application/problem+json"
	MediaForm         = "application/x-www-form-urlencoded"
)

// Storage description service types and subscription types.
const (
	ServiceStorageRoot    = "StorageRoot"
	ServiceNotification   = "NotificationService"
	ServiceAccessRequest  = "AccessRequestService"
	ServiceAccessGrant    = "AccessGrantService"
	ServiceTypeIndex      = "TypeIndexService"
	ServiceTypeSearch     = "TypeSearchService"
	SubscriptionWebhook   = "WebhookSubscription"
	OpenIDProviderService = LWSNamespace + "OpenIdProvider"
)

// OAuth 2.0 token exchange and authentication suite token types.
const (
	GrantTypeTokenExchange    = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeIDToken          = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeSAML2            = "urn:ietf:params:oauth:token-type:saml2"
	TokenTypeJWT              = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeAccessToken      = "urn:ietf:params:oauth:token-type:access_token"
	WellKnownLWSConfiguration = "/.well-known/lws-configuration"
)

// Access requests and grants (ODRL-based Access Profile).
const (
	AccessProfile     = LWSNamespace + "AccessProfile"
	TypeAccessRequest = "AccessRequest"
	TypeAccessGrant   = "AccessGrant"
	TypeAccessPolicy  = "AccessPolicy"

	ActionRead   = "read"
	ActionModify = "modify"
	ActionCreate = "create"
	ActionDelete = "delete"

	OperandClient   = "client"
	OperandFormat   = "format"
	OperandType     = "type"
	OperandPurpose  = "purpose"
	OperandDateTime = "dateTime"

	OperatorEq      = "eq"
	OperatorIsAnyOf = "isAnyOf"
	OperatorGteq    = "gteq"
	OperatorLteq    = "lteq"

	// PublicAgent denotes public access (foaf:Agent).
	PublicAgent = "http://xmlns.com/foaf/0.1/Agent"
)

// Prefer header values.
const (
	PreferSetLinkset    = "set-linkset"
	PreferLinkRelations = LWSNamespace + "PreferLinkRelations"
)

// Activity Streams activity types used in notifications.
const (
	ActivityCreate = "Create"
	ActivityUpdate = "Update"
	ActivityDelete = "Delete"
	// TypeNotification is the type of a notification envelope.
	TypeNotification = "Notification"
)
