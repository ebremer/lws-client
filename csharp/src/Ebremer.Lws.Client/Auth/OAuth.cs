// SPDX-License-Identifier: MIT
using System.Text;
using System.Text.Json;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws.Auth;

/// <summary>Authorization server metadata (RFC 8414) served at <c>/.well-known/lws-configuration</c>.</summary>
public sealed class AuthorizationServerMetadata
{
    private AuthorizationServerMetadata(string issuer, Uri tokenEndpoint, Uri? jwksUri, IReadOnlyList<string> grantTypes,
        IReadOnlyList<string> subjectTokenTypes, IReadOnlyList<string> subjectIdentifierTypes, JsonElement raw)
    {
        Issuer = issuer;
        TokenEndpoint = tokenEndpoint;
        JwksUri = jwksUri;
        GrantTypesSupported = grantTypes;
        SubjectTokenTypesSupported = subjectTokenTypes;
        SubjectIdentifierTypesSupported = subjectIdentifierTypes;
        Raw = raw;
    }

    /// <summary>The issuer identifier, as the server states it.</summary>
    public string Issuer { get; }

    /// <summary>The token endpoint.</summary>
    public Uri TokenEndpoint { get; }

    /// <summary>The JWK set URL, if any.</summary>
    public Uri? JwksUri { get; }

    /// <summary>The supported grant types.</summary>
    public IReadOnlyList<string> GrantTypesSupported { get; }

    /// <summary>The supported <c>subject_token_type</c> values (empty when not advertised).</summary>
    public IReadOnlyList<string> SubjectTokenTypesSupported { get; }

    /// <summary>The supported subject identifier types (defaults to <c>["https"]</c>).</summary>
    public IReadOnlyList<string> SubjectIdentifierTypesSupported { get; }

    /// <summary>The JSON document.</summary>
    public JsonElement Raw { get; }

    /// <summary>Whether the server accepts subject tokens of <paramref name="tokenType"/> (true when it advertises none).</summary>
    /// <param name="tokenType">The token type.</param>
    /// <returns>Whether it is supported.</returns>
    public bool SupportsSubjectTokenType(string tokenType) =>
        SubjectTokenTypesSupported.Count == 0 || SubjectTokenTypesSupported.Contains(tokenType);

    /// <summary>Parses a metadata document retrieved from <paramref name="baseUri"/>.</summary>
    /// <param name="json">The document.</param>
    /// <param name="baseUri">The metadata URL.</param>
    /// <returns>The metadata.</returns>
    /// <exception cref="ProtocolException">The document lacks <c>issuer</c> or <c>token_endpoint</c>.</exception>
    public static AuthorizationServerMetadata Parse(JsonElement json, Uri? baseUri)
    {
        LwsJson.RequireObject(json, "Authorization server metadata");
        string issuer = LwsJson.GetString(json, "issuer") ?? throw new ProtocolException("Authorization server metadata has no issuer");
        Uri token = LwsJson.GetUri(json, "token_endpoint", baseUri) ?? throw new ProtocolException("Authorization server metadata has no token_endpoint");
        IReadOnlyList<string> idTypes = LwsJson.StringOrArray(LwsJson.Get(json, "subject_identifier_types_supported"));
        return new AuthorizationServerMetadata(issuer, token, LwsJson.GetUri(json, "jwks_uri", baseUri),
            LwsJson.StringOrArray(LwsJson.Get(json, "grant_types_supported")),
            LwsJson.StringOrArray(LwsJson.Get(json, "subject_token_types_supported")),
            idTypes.Count == 0 ? ["https"] : idTypes, json.Clone());
    }

    /// <summary>
    /// The metadata URL of an issuer (RFC 8414 section 3.1): <c>https://as.example</c> →
    /// <c>https://as.example/.well-known/lws-configuration</c>; <c>https://as.example/t1</c> →
    /// <c>https://as.example/.well-known/lws-configuration/t1</c>.
    /// </summary>
    /// <param name="issuer">The issuer.</param>
    /// <returns>The metadata URL.</returns>
    public static Uri MetadataUrl(Uri issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        string path = issuer.AbsolutePath;
        if (path.EndsWith('/')) path = path[..^1];
        return new Uri(issuer.GetLeftPart(UriPartial.Authority) + Lws.WellKnownLwsConfiguration + path);
    }
}

/// <summary>
/// Protected resource metadata (RFC 9728), named by the <c>resource_metadata</c> parameter of a storage's <c>401</c>:
/// the resource it describes and the authorization servers that issue tokens for it.
/// </summary>
public sealed class ProtectedResourceMetadata
{
    private ProtectedResourceMetadata(string resource, IReadOnlyList<string> authorizationServers, JsonElement raw)
    {
        Resource = resource;
        AuthorizationServers = authorizationServers;
        Raw = raw;
    }

    /// <summary>The resource identifier, as the server states it.</summary>
    public string Resource { get; }

    /// <summary>The issuer identifiers of the authorization servers, in the server's order (at least one).</summary>
    public IReadOnlyList<string> AuthorizationServers { get; }

    /// <summary>The JSON document.</summary>
    public JsonElement Raw { get; }

    /// <summary>Parses a protected resource metadata document.</summary>
    /// <param name="json">The document.</param>
    /// <returns>The metadata.</returns>
    /// <exception cref="ProtocolException">
    /// The document is not an object, its <c>resource</c> is not a string (RFC 9728 makes it REQUIRED), or its
    /// <c>authorization_servers</c> is not a non-empty array of strings (lws10-core makes it REQUIRED).
    /// </exception>
    public static ProtectedResourceMetadata Parse(JsonElement json)
    {
        LwsJson.RequireObject(json, "Protected resource metadata");
        string resource = LwsJson.GetString(json, "resource") ?? throw new ProtocolException("Protected resource metadata has no resource string");
        if (LwsJson.Get(json, "authorization_servers") is not { ValueKind: JsonValueKind.Array } servers
            || servers.GetArrayLength() == 0
            || servers.EnumerateArray().Any(s => s.ValueKind != JsonValueKind.String))
        {
            throw new ProtocolException("Protected resource metadata has no authorization_servers array of issuer strings");
        }
        return new ProtectedResourceMetadata(resource, LwsJson.StringOrArray(servers), json.Clone());
    }
}

/// <summary>An access token issued by an authorization server.</summary>
public sealed class AccessToken
{
    /// <summary>The lifetime assumed when neither <c>expires_in</c> nor a JWT <c>exp</c> is available.</summary>
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromSeconds(300);

    /// <summary>Creates a token.</summary>
    /// <param name="value">The token.</param>
    /// <param name="tokenType">The token type (<c>Bearer</c>).</param>
    /// <param name="expiresAt">When it expires.</param>
    /// <param name="scope">The granted scope, if any.</param>
    public AccessToken(string value, string tokenType, DateTimeOffset expiresAt, string? scope = null)
    {
        Value = value ?? throw new ArgumentNullException(nameof(value));
        TokenType = tokenType ?? throw new ArgumentNullException(nameof(tokenType));
        ExpiresAt = expiresAt;
        Scope = scope;
    }

    /// <summary>The token.</summary>
    public string Value { get; }

    /// <summary>The token type.</summary>
    public string TokenType { get; }

    /// <summary>When the token expires.</summary>
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>The granted scope, if any.</summary>
    public string? Scope { get; }

    /// <summary>
    /// Parses a token endpoint success response (RFC 6749 section 5.1). The expiry is <c>expires_in</c>, else the
    /// token's JWT <c>exp</c> claim, else <see cref="DefaultLifetime"/>.
    /// </summary>
    /// <param name="json">The response body.</param>
    /// <param name="now">The current time.</param>
    /// <returns>The token.</returns>
    /// <exception cref="AuthenticationException">The response has no token or a token type other than Bearer.</exception>
    public static AccessToken FromTokenResponse(JsonElement json, DateTimeOffset now)
    {
        string token = LwsJson.GetString(json, "access_token") is { Length: > 0 } t
            ? t
            : throw new AuthenticationException("The token response has no access_token");
        string? type = LwsJson.GetString(json, "token_type");
        if (!string.Equals(type, "Bearer", StringComparison.OrdinalIgnoreCase))
        {
            throw new AuthenticationException($"Unsupported token_type: {type}");
        }
        DateTimeOffset expires = LwsJson.Get(json, "expires_in") is { ValueKind: JsonValueKind.Number } ei && ei.TryGetDouble(out double seconds)
            ? now.AddSeconds(seconds)
            : Jwt.Expiration(token) ?? now + DefaultLifetime;
        return new AccessToken(token, "Bearer", expires, LwsJson.GetString(json, "scope"));
    }

    /// <summary>Whether the token is still usable at <paramref name="now"/>, keeping <paramref name="margin"/> in reserve.</summary>
    /// <param name="now">The current time.</param>
    /// <param name="margin">The refresh margin.</param>
    /// <returns>Whether it is valid.</returns>
    public bool IsValid(DateTimeOffset now, TimeSpan margin) => now + margin < ExpiresAt;

    /// <inheritdoc/>
    public override string ToString() => new StringBuilder("AccessToken(").Append(TokenType).Append(", expires ").Append(ExpiresAt.ToString("O", System.Globalization.CultureInfo.InvariantCulture)).Append(')').ToString();
}
