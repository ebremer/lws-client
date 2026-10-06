// SPDX-License-Identifier: MIT
package com.ebremer.lws;

import java.util.Collection;

/**
 * Constants of the Linked Web Storage protocol family and helpers for matching LWS type terms.
 *
 * <p>JSON documents use short terms ({@code "Container"}), compact IRIs ({@code "lws:Container"}) and
 * full IRIs ({@code "https://www.w3.org/ns/lws#Container"}) interchangeably; {@link #typeMatches}
 * treats them as equal.
 */
public final class Lws {
    private Lws() {}

    /** The LWS vocabulary namespace. */
    public static final String LWS_NS = "https://www.w3.org/ns/lws#";
    /** The LWS JSON-LD context. */
    public static final String LWS_CONTEXT = "https://www.w3.org/ns/lws/v1";
    /** The W3C Controlled Identifiers JSON-LD context. */
    public static final String CID_CONTEXT = "https://www.w3.org/ns/cid/v1";
    /** The Activity Streams 2.0 JSON-LD context. */
    public static final String ACTIVITYSTREAMS_CONTEXT = "https://www.w3.org/ns/activitystreams";

    /** OAuth 2.0 token exchange grant type (RFC 8693). */
    public static final String GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    /** Well-known path of LWS authorization server metadata. */
    public static final String WELL_KNOWN_LWS_CONFIGURATION = "/.well-known/lws-configuration";
    /** Service type of an OpenID provider in a controlled identifier document. */
    public static final String OPENID_PROVIDER_SERVICE = LWS_NS + "OpenIdProvider";
    /** Public access assignee (foaf:Agent). */
    public static final String PUBLIC_AGENT = "http://xmlns.com/foaf/0.1/Agent";
    /** The LWS ODRL-based access profile. */
    public static final String ACCESS_PROFILE = LWS_NS + "AccessProfile";

    /** Link relation types. */
    public static final class Rel {
        private Rel() {}
        public static final String STORAGE = LWS_NS + "storage";
        public static final String LINKSET = "linkset";
        public static final String UP = "up";
        public static final String TYPE = "type";
        public static final String FIRST = "first";
        public static final String NEXT = "next";
        public static final String PREV = "prev";
        public static final String LAST = "last";
    }

    /** Resource type IRIs. */
    public static final class Type {
        private Type() {}
        public static final String CONTAINER = LWS_NS + "Container";
        public static final String DATA_RESOURCE = LWS_NS + "DataResource";
        public static final String STORAGE_RESOURCE = LWS_NS + "StorageResource";
        public static final String STORAGE = "Storage";
        public static final String NOTIFICATION = "Notification";
        public static final String CONTAINER_PAGE = "ContainerPage";
        public static final String TYPE_INDEX = "TypeIndex";
        public static final String ACCESS_REQUEST = "AccessRequest";
        public static final String ACCESS_GRANT = "AccessGrant";
        public static final String ACCESS_POLICY = "AccessPolicy";
    }

    /** Media types used by LWS. */
    public static final class MediaType {
        private MediaType() {}
        public static final String LWS_JSON = "application/lws+json";
        public static final String LWS_CID = "application/lws+cid";
        public static final String LINKSET_JSON = "application/linkset+json";
        public static final String JSON_PATCH = "application/json-patch+json";
        public static final String LWS_QUERY_JSON = "application/lws-query+json";
        public static final String LD_JSON = "application/ld+json";
        public static final String JSON = "application/json";
        public static final String PROBLEM_JSON = "application/problem+json";
        public static final String FORM = "application/x-www-form-urlencoded";
        /** {@code application/ld+json} with the LWS profile, equivalent to {@link #LWS_JSON}. */
        public static final String LD_JSON_LWS = "application/ld+json; profile=\"" + LWS_CONTEXT + "\"";
    }

    /** Storage description service types. */
    public static final class Service {
        private Service() {}
        public static final String STORAGE_ROOT = "StorageRoot";
        public static final String NOTIFICATION = "NotificationService";
        public static final String ACCESS_REQUEST = "AccessRequestService";
        public static final String ACCESS_GRANT = "AccessGrantService";
        public static final String TYPE_INDEX = "TypeIndexService";
        public static final String TYPE_SEARCH = "TypeSearchService";
    }

    /** Notification subscription types. */
    public static final class Subscription {
        private Subscription() {}
        public static final String WEBHOOK = "WebhookSubscription";
    }

    /** OAuth token type identifiers used by the LWS authentication suites. */
    public static final class TokenType {
        private TokenType() {}
        /** OpenID Connect suite. */
        public static final String ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";
        /** SAML 2.0 suite. */
        public static final String SAML2 = "urn:ietf:params:oauth:token-type:saml2";
        /** Self-signed (controlled identifier / did:key) suites. */
        public static final String JWT = "urn:ietf:params:oauth:token-type:jwt";
        public static final String ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
    }

    /** Access profile actions, constraint operands and operators. */
    public static final class Access {
        private Access() {}
        public static final String ACTION_READ = "read";
        public static final String ACTION_MODIFY = "modify";
        public static final String ACTION_CREATE = "create";
        public static final String ACTION_DELETE = "delete";
        public static final String OPERAND_CLIENT = "client";
        public static final String OPERAND_FORMAT = "format";
        public static final String OPERAND_TYPE = "type";
        public static final String OPERAND_PURPOSE = "purpose";
        public static final String OPERAND_DATE_TIME = "dateTime";
        public static final String OPERATOR_EQ = "eq";
        public static final String OPERATOR_IS_ANY_OF = "isAnyOf";
        public static final String OPERATOR_GTEQ = "gteq";
        public static final String OPERATOR_LTEQ = "lteq";
    }

    /** {@code Prefer} header values. */
    public static final class Prefer {
        private Prefer() {}
        public static final String SET_LINKSET = "set-linkset";
        public static final String LINK_RELATIONS = LWS_NS + "PreferLinkRelations";
    }

    /** Activity Streams activity types used in notifications. */
    public static final class Activity {
        private Activity() {}
        public static final String CREATE = "Create";
        public static final String UPDATE = "Update";
        public static final String DELETE = "Delete";
    }

    /**
     * Expands an LWS term to its full IRI: {@code Container} and {@code lws:Container} become
     * {@code https://www.w3.org/ns/lws#Container}; values that already are IRIs are returned unchanged.
     */
    public static String expandType(String type) {
        if (type == null) return null;
        if (type.startsWith("lws:")) return LWS_NS + type.substring(4);
        if (type.indexOf(':') < 0) return LWS_NS + type;
        return type;
    }

    /** Whether two type values denote the same type, treating {@code Term}, {@code lws:Term} and the full IRI as equal. */
    public static boolean typeMatches(String a, String b) {
        if (a == null || b == null) return false;
        return a.equals(b) || expandType(a).equals(expandType(b));
    }

    /** Whether {@code types} contains a value matching {@code type} (see {@link #typeMatches}). */
    public static boolean hasType(Collection<String> types, String type) {
        if (types == null) return false;
        for (String t : types) {
            if (typeMatches(t, type)) return true;
        }
        return false;
    }
}
