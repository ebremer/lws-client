// SPDX-License-Identifier: MIT
namespace Ebremer.Lws;

/// <summary>
/// Constants of the Linked Web Storage protocol family, and helpers for matching LWS type terms.
/// </summary>
/// <remarks>
/// JSON documents use short terms (<c>"Container"</c>), compact IRIs (<c>"lws:Container"</c>) and full IRIs
/// (<c>"https://www.w3.org/ns/lws#Container"</c>) interchangeably; <see cref="TypeMatches"/> treats them as equal.
/// </remarks>
public static class Lws
{
    /// <summary>The LWS vocabulary namespace.</summary>
    public const string Namespace = "https://www.w3.org/ns/lws#";

    /// <summary>The LWS JSON-LD context.</summary>
    public const string Context = "https://www.w3.org/ns/lws/v1";

    /// <summary>The W3C Controlled Identifiers JSON-LD context.</summary>
    public const string CidContext = "https://www.w3.org/ns/cid/v1";

    /// <summary>The Activity Streams 2.0 JSON-LD context.</summary>
    public const string ActivityStreamsContext = "https://www.w3.org/ns/activitystreams";

    /// <summary>The OAuth 2.0 token exchange grant type (RFC 8693).</summary>
    public const string GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";

    /// <summary>The well-known path of LWS authorization server metadata.</summary>
    public const string WellKnownLwsConfiguration = "/.well-known/lws-configuration";

    /// <summary>The service type of an OpenID provider in a controlled identifier document.</summary>
    public const string OpenIdProviderService = Namespace + "OpenIdProvider";

    /// <summary>The LWS ODRL-based access profile.</summary>
    public const string AccessProfile = Namespace + "AccessProfile";

    /// <summary>The public access assignee (<c>foaf:Agent</c>).</summary>
    public const string PublicAgent = "http://xmlns.com/foaf/0.1/Agent";

    /// <summary>Link relation types.</summary>
    public static class Rel
    {
        /// <summary>The storage a resource belongs to.</summary>
        public const string Storage = Namespace + "storage";

        /// <summary>The linkset (metadata) resource.</summary>
        public const string Linkset = "linkset";

        /// <summary>The parent container.</summary>
        public const string Up = "up";

        /// <summary>A resource type.</summary>
        public const string Type = "type";

        /// <summary>The first page.</summary>
        public const string First = "first";

        /// <summary>The next page.</summary>
        public const string Next = "next";

        /// <summary>The previous page.</summary>
        public const string Prev = "prev";

        /// <summary>The last page.</summary>
        public const string Last = "last";
    }

    /// <summary>Resource and document types.</summary>
    public static class Types
    {
        /// <summary>A container.</summary>
        public const string Container = Namespace + "Container";

        /// <summary>A data resource.</summary>
        public const string DataResource = Namespace + "DataResource";

        /// <summary>Any storage resource (container or data resource).</summary>
        public const string StorageResource = Namespace + "StorageResource";

        /// <summary>A storage description.</summary>
        public const string Storage = "Storage";

        /// <summary>A notification envelope.</summary>
        public const string Notification = "Notification";

        /// <summary>A page of type search results.</summary>
        public const string ContainerPage = "ContainerPage";

        /// <summary>A type index page.</summary>
        public const string TypeIndex = "TypeIndex";

        /// <summary>An access request.</summary>
        public const string AccessRequest = "AccessRequest";

        /// <summary>An access grant.</summary>
        public const string AccessGrant = "AccessGrant";

        /// <summary>An access policy.</summary>
        public const string AccessPolicy = "AccessPolicy";
    }

    /// <summary>Media types used by LWS.</summary>
    public static class MediaType
    {
        /// <summary><c>application/lws+json</c>.</summary>
        public const string LwsJson = "application/lws+json";

        /// <summary><c>application/lws+cid</c> (storage descriptions).</summary>
        public const string LwsCid = "application/lws+cid";

        /// <summary><c>application/linkset+json</c> (RFC 9264).</summary>
        public const string LinksetJson = "application/linkset+json";

        /// <summary><c>application/json-patch+json</c> (RFC 6902), the baseline PATCH format.</summary>
        public const string JsonPatch = "application/json-patch+json";

        /// <summary><c>application/lws-query+json</c> (type search filters).</summary>
        public const string LwsQueryJson = "application/lws-query+json";

        /// <summary><c>application/ld+json</c>.</summary>
        public const string LdJson = "application/ld+json";

        /// <summary><c>application/json</c>.</summary>
        public const string Json = "application/json";

        /// <summary><c>application/problem+json</c> (RFC 9457).</summary>
        public const string ProblemJson = "application/problem+json";

        /// <summary><c>application/x-www-form-urlencoded</c>.</summary>
        public const string Form = "application/x-www-form-urlencoded";
    }

    /// <summary>Storage description service types (<c>service[].type</c>).</summary>
    public static class ServiceType
    {
        /// <summary>The storage root container.</summary>
        public const string StorageRoot = "StorageRoot";

        /// <summary>The notification service.</summary>
        public const string Notification = "NotificationService";

        /// <summary>The access request service.</summary>
        public const string AccessRequest = "AccessRequestService";

        /// <summary>The access grant service.</summary>
        public const string AccessGrant = "AccessGrantService";

        /// <summary>The type index service.</summary>
        public const string TypeIndex = "TypeIndexService";

        /// <summary>The type search service.</summary>
        public const string TypeSearch = "TypeSearchService";
    }

    /// <summary>Notification subscription types.</summary>
    public static class SubscriptionType
    {
        /// <summary>The webhook subscription type.</summary>
        public const string Webhook = "WebhookSubscription";
    }

    /// <summary>OAuth token type identifiers used by the LWS authentication suites.</summary>
    public static class TokenType
    {
        /// <summary>OpenID Connect suite: an ID token.</summary>
        public const string IdToken = "urn:ietf:params:oauth:token-type:id_token";

        /// <summary>SAML 2.0 suite: a base64url-encoded assertion.</summary>
        public const string Saml2 = "urn:ietf:params:oauth:token-type:saml2";

        /// <summary>Self-signed (controlled identifier, did:key) suites: a JWT.</summary>
        public const string Jwt = "urn:ietf:params:oauth:token-type:jwt";

        /// <summary>An OAuth access token.</summary>
        public const string AccessToken = "urn:ietf:params:oauth:token-type:access_token";
    }

    /// <summary>Access profile actions.</summary>
    public static class Actions
    {
        /// <summary><c>read</c>.</summary>
        public const string Read = "read";

        /// <summary><c>modify</c>.</summary>
        public const string Modify = "modify";

        /// <summary><c>create</c>.</summary>
        public const string Create = "create";

        /// <summary><c>delete</c>.</summary>
        public const string Delete = "delete";
    }

    /// <summary>Access profile constraint left operands.</summary>
    public static class Operands
    {
        /// <summary><c>client</c>.</summary>
        public const string Client = "client";

        /// <summary><c>format</c>.</summary>
        public const string Format = "format";

        /// <summary><c>type</c>.</summary>
        public const string Type = "type";

        /// <summary><c>purpose</c>.</summary>
        public const string Purpose = "purpose";

        /// <summary><c>dateTime</c>.</summary>
        public const string DateTime = "dateTime";
    }

    /// <summary>Access profile constraint operators.</summary>
    public static class Operators
    {
        /// <summary><c>eq</c>.</summary>
        public const string Eq = "eq";

        /// <summary><c>isAnyOf</c>.</summary>
        public const string IsAnyOf = "isAnyOf";

        /// <summary><c>gteq</c>.</summary>
        public const string GtEq = "gteq";

        /// <summary><c>lteq</c>.</summary>
        public const string LtEq = "lteq";
    }

    /// <summary><c>Prefer</c> header values.</summary>
    public static class Prefer
    {
        /// <summary>Update the content and the linkset atomically.</summary>
        public const string SetLinkset = "set-linkset";

        /// <summary>The link relation preference.</summary>
        public const string LinkRelations = Namespace + "PreferLinkRelations";
    }

    /// <summary>Activity Streams activity types used in notifications.</summary>
    public static class Activities
    {
        /// <summary>A resource was created.</summary>
        public const string Create = "Create";

        /// <summary>A resource was updated.</summary>
        public const string Update = "Update";

        /// <summary>A resource was deleted.</summary>
        public const string Delete = "Delete";
    }

    /// <summary>
    /// Expands an LWS term to its full IRI: <c>Container</c> and <c>lws:Container</c> become
    /// <c>https://www.w3.org/ns/lws#Container</c>; values that already are IRIs are returned unchanged.
    /// </summary>
    /// <param name="type">A type value.</param>
    /// <returns>The full IRI.</returns>
    public static string ExpandType(string type)
    {
        ArgumentNullException.ThrowIfNull(type);
        if (type.StartsWith("lws:", StringComparison.Ordinal)) return Namespace + type[4..];
        if (!type.Contains(':', StringComparison.Ordinal)) return Namespace + type;
        return type;
    }

    /// <summary>Whether two type values denote the same type (<c>Term</c>, <c>lws:Term</c> and the full IRI are equal).</summary>
    /// <param name="a">A type value.</param>
    /// <param name="b">Another type value.</param>
    /// <returns>Whether they match.</returns>
    public static bool TypeMatches(string? a, string? b)
    {
        if (a is null || b is null) return false;
        return a == b || ExpandType(a) == ExpandType(b);
    }

    /// <summary>Whether <paramref name="types"/> contains a value matching <paramref name="type"/>.</summary>
    /// <param name="types">Type values.</param>
    /// <param name="type">The type looked for.</param>
    /// <returns>Whether one matches.</returns>
    public static bool HasType(IEnumerable<string>? types, string type)
    {
        if (types is null) return false;
        foreach (string t in types)
        {
            if (TypeMatches(t, type)) return true;
        }
        return false;
    }
}
