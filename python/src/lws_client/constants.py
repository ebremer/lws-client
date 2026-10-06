# SPDX-License-Identifier: MIT
"""Shared LWS vocabulary: namespaces, link relations, media types, service types and
OAuth identifiers used throughout the client (design contract §2)."""

from __future__ import annotations

__all__ = [
    "LWS_NS",
    "LWS_CONTEXT",
    "CID_CONTEXT",
    "ACTIVITYSTREAMS_CONTEXT",
    "Rel",
    "Types",
    "MediaType",
    "ServiceType",
    "SUBSCRIPTION_WEBHOOK",
    "TokenType",
    "GRANT_TYPE_TOKEN_EXCHANGE",
    "WELL_KNOWN_LWS_CONFIGURATION",
    "OPENID_PROVIDER_SERVICE",
    "ACCESS_PROFILE",
    "TYPE_ACCESS_REQUEST",
    "TYPE_ACCESS_GRANT",
    "TYPE_ACCESS_POLICY",
    "Action",
    "Operand",
    "Operator",
    "PUBLIC_AGENT",
    "PREFER_SET_LINKSET",
    "PREFER_LINK_RELATIONS",
    "ActivityType",
    "USER_AGENT",
    "VERSION",
]

VERSION = "0.1.0"
USER_AGENT = f"lws-client-python/{VERSION}"

# Namespaces / JSON-LD contexts
LWS_NS = "https://www.w3.org/ns/lws#"
LWS_CONTEXT = "https://www.w3.org/ns/lws/v1"
CID_CONTEXT = "https://www.w3.org/ns/cid/v1"
ACTIVITYSTREAMS_CONTEXT = "https://www.w3.org/ns/activitystreams"


class Rel:
    """Link relation types used by LWS."""

    STORAGE = "https://www.w3.org/ns/lws#storage"
    LINKSET = "linkset"
    UP = "up"
    TYPE = "type"
    FIRST = "first"
    NEXT = "next"
    PREV = "prev"
    LAST = "last"


class Types:
    """Resource type IRIs. Short terms (``Container``) and compact IRIs (``lws:Container``)
    are equivalent; see :func:`lws_client.has_type`."""

    CONTAINER = "https://www.w3.org/ns/lws#Container"
    DATA_RESOURCE = "https://www.w3.org/ns/lws#DataResource"
    STORAGE_RESOURCE = "https://www.w3.org/ns/lws#StorageResource"
    STORAGE = "https://www.w3.org/ns/lws#Storage"


class MediaType:
    """Media types used by the protocol."""

    LWS_JSON = "application/lws+json"
    LWS_CID = "application/lws+cid"
    LINKSET_JSON = "application/linkset+json"
    JSON_PATCH = "application/json-patch+json"
    LWS_QUERY_JSON = "application/lws-query+json"
    LD_JSON = "application/ld+json"
    JSON = "application/json"
    PROBLEM_JSON = "application/problem+json"
    FORM = "application/x-www-form-urlencoded"


class ServiceType:
    """``type`` values of services in a storage description."""

    STORAGE_ROOT = "StorageRoot"
    NOTIFICATION = "NotificationService"
    ACCESS_REQUEST = "AccessRequestService"
    ACCESS_GRANT = "AccessGrantService"
    TYPE_INDEX = "TypeIndexService"
    TYPE_SEARCH = "TypeSearchService"


SUBSCRIPTION_WEBHOOK = "WebhookSubscription"


class TokenType:
    """OAuth 2.0 token type URIs (RFC 8693) used by the LWS authentication suites."""

    ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
    SAML2 = "urn:ietf:params:oauth:token-type:saml2"
    JWT = "urn:ietf:params:oauth:token-type:jwt"
    ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"


GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
WELL_KNOWN_LWS_CONFIGURATION = "/.well-known/lws-configuration"
OPENID_PROVIDER_SERVICE = "https://www.w3.org/ns/lws#OpenIdProvider"

# Access requests / grants (ODRL-based access profile)
ACCESS_PROFILE = "https://www.w3.org/ns/lws#AccessProfile"
TYPE_ACCESS_REQUEST = "AccessRequest"
TYPE_ACCESS_GRANT = "AccessGrant"
TYPE_ACCESS_POLICY = "AccessPolicy"


class Action:
    """Actions supported by the LWS access profile."""

    READ = "read"
    MODIFY = "modify"
    CREATE = "create"
    DELETE = "delete"


class Operand:
    """``leftOperand`` values supported by the LWS access profile."""

    CLIENT = "client"
    FORMAT = "format"
    TYPE = "type"
    PURPOSE = "purpose"
    DATE_TIME = "dateTime"


class Operator:
    """ODRL operators used by the LWS access profile."""

    EQ = "eq"
    IS_ANY_OF = "isAnyOf"
    GTEQ = "gteq"
    LTEQ = "lteq"


PUBLIC_AGENT = "http://xmlns.com/foaf/0.1/Agent"

PREFER_SET_LINKSET = "set-linkset"
PREFER_LINK_RELATIONS = "https://www.w3.org/ns/lws#PreferLinkRelations"


class ActivityType:
    """Activity Streams 2.0 activity types used in notifications."""

    CREATE = "Create"
    UPDATE = "Update"
    DELETE = "Delete"
