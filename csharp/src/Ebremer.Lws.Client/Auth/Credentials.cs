// SPDX-License-Identifier: MIT
using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json.Nodes;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws.Auth;

/// <summary>Where a subject token will be presented.</summary>
/// <param name="Issuer">The authorization server (<c>as_uri</c>).</param>
/// <param name="Realm">The protection realm the access token is requested for.</param>
/// <param name="Metadata">The authorization server metadata; its <c>Issuer</c> is the audience of self-signed tokens.</param>
public sealed record CredentialContext(Uri Issuer, Uri Realm, AuthorizationServerMetadata Metadata);

/// <summary>
/// Supplies the subject token (an LWS authentication credential) presented to an authorization server in the OAuth
/// 2.0 token exchange. One implementation per LWS authentication suite: <see cref="OpenIdCredentials"/>,
/// <see cref="SamlCredentials"/>, <see cref="SelfSignedCredentials"/>. Implementations must be thread-safe.
/// </summary>
public interface ICredentialProvider
{
    /// <summary>The <c>subject_token_type</c> URI (see <see cref="Lws.TokenType"/>).</summary>
    string TokenType { get; }

    /// <summary>Returns a subject token for the given authorization server.</summary>
    /// <param name="context">Where the token will be presented.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The subject token.</returns>
    ValueTask<string> GetSubjectTokenAsync(CredentialContext context, CancellationToken cancellationToken = default);
}

/// <summary>
/// OpenID Connect authentication suite (<c>lws10-authn-openid</c>): presents an OpenID Connect ID token
/// (<c>urn:ietf:params:oauth:token-type:id_token</c>). Interactive login is up to the application (use your OIDC
/// library); this provider hands the resulting ID token to the authorization server.
/// </summary>
/// <remarks>
/// Security: prefer ID tokens whose <c>aud</c> includes the authorization server, or pick one per authorization
/// server with the <see cref="CredentialContext"/> supplier.
/// </remarks>
public sealed class OpenIdCredentials : ICredentialProvider
{
    private readonly Func<CredentialContext, CancellationToken, ValueTask<string>> _tokens;

    /// <summary>A fixed ID token.</summary>
    /// <param name="idToken">The ID token.</param>
    public OpenIdCredentials(string idToken)
    {
        ArgumentNullException.ThrowIfNull(idToken);
        _tokens = (_, _) => ValueTask.FromResult(idToken);
    }

    /// <summary>ID tokens chosen per authorization server (asked whenever a new access token is needed).</summary>
    /// <param name="idTokens">The token source.</param>
    public OpenIdCredentials(Func<CredentialContext, CancellationToken, ValueTask<string>> idTokens) =>
        _tokens = idTokens ?? throw new ArgumentNullException(nameof(idTokens));

    /// <inheritdoc/>
    public string TokenType => Lws.TokenType.IdToken;

    /// <inheritdoc/>
    public async ValueTask<string> GetSubjectTokenAsync(CredentialContext context, CancellationToken cancellationToken = default) =>
        await _tokens(context, cancellationToken).ConfigureAwait(false)
        ?? throw new InvalidOperationException("The ID token supplier returned null");
}

/// <summary>
/// SAML 2.0 authentication suite (<c>lws10-authn-saml</c>): presents a signed SAML 2.0 assertion
/// (<c>urn:ietf:params:oauth:token-type:saml2</c>). Per RFC 8693 the subject token is the base64url-encoded
/// assertion; <see cref="FromXml"/> performs the encoding.
/// </summary>
public sealed class SamlCredentials : ICredentialProvider
{
    private readonly Func<CredentialContext, CancellationToken, ValueTask<string>> _assertions;

    /// <summary>Base64url-encoded assertions chosen per authorization server.</summary>
    /// <param name="encodedAssertions">The assertion source.</param>
    public SamlCredentials(Func<CredentialContext, CancellationToken, ValueTask<string>> encodedAssertions) =>
        _assertions = encodedAssertions ?? throw new ArgumentNullException(nameof(encodedAssertions));

    /// <summary>A fixed, already base64url-encoded assertion.</summary>
    /// <param name="encodedAssertion">The encoded assertion.</param>
    /// <returns>The credentials.</returns>
    public static SamlCredentials FromEncoded(string encodedAssertion)
    {
        ArgumentNullException.ThrowIfNull(encodedAssertion);
        return new SamlCredentials((_, _) => ValueTask.FromResult(encodedAssertion));
    }

    /// <summary>A fixed assertion given as XML; it is base64url-encoded for the token exchange.</summary>
    /// <param name="assertionXml">The assertion.</param>
    /// <returns>The credentials.</returns>
    public static SamlCredentials FromXml(string assertionXml) => FromEncoded(Encode(assertionXml));

    /// <summary>Base64url-encodes (without padding) an assertion XML document.</summary>
    /// <param name="assertionXml">The assertion.</param>
    /// <returns>The encoded assertion.</returns>
    public static string Encode(string assertionXml)
    {
        ArgumentNullException.ThrowIfNull(assertionXml);
        return Base64Url.EncodeToString(Encoding.UTF8.GetBytes(assertionXml));
    }

    /// <inheritdoc/>
    public string TokenType => Lws.TokenType.Saml2;

    /// <inheritdoc/>
    public async ValueTask<string> GetSubjectTokenAsync(CredentialContext context, CancellationToken cancellationToken = default) =>
        await _assertions(context, cancellationToken).ConfigureAwait(false)
        ?? throw new InvalidOperationException("The SAML assertion supplier returned null");
}

/// <summary>
/// Self-signed identity authentication suite (<c>lws10-authn-ssi-cid</c>, including <c>did:key</c> subjects): the
/// agent signs its own JWT credential (<c>urn:ietf:params:oauth:token-type:jwt</c>) with
/// <c>sub = iss = client_id = agent</c>, <c>aud = [authorization server]</c>, <c>iat</c>, <c>exp</c> and a random
/// <c>jti</c>. Supports <c>ES256</c> (P-256) and <c>EdDSA</c> (Ed25519). Tokens are cached per audience until 60
/// seconds before they expire.
/// <code>var credentials = SelfSignedCredentials.DidKey(SigningKey.GenerateP256());   // agent = did:key:zDn…</code>
/// </summary>
public sealed class SelfSignedCredentials : ICredentialProvider
{
    private static readonly TimeSpan ReuseMargin = TimeSpan.FromSeconds(60);

    private readonly SigningKey _key;
    private readonly ConcurrentDictionary<string, (string Token, DateTimeOffset Expires)> _cache = new(StringComparer.Ordinal);

    private SelfSignedCredentials(string agent, SigningKey key, string? keyId, TimeSpan lifetime, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(agent);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(time);
        if (lifetime <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(lifetime), "The lifetime must be positive");
        Agent = agent;
        _key = key;
        KeyId = keyId;
        Lifetime = lifetime;
        TimeProvider = time;
    }

    /// <summary>
    /// Credentials for an agent whose controlled identifier document (at <paramref name="agent"/>) lists the key under
    /// <c>authentication</c>; <paramref name="keyId"/> identifies that verification method.
    /// </summary>
    /// <param name="agent">The agent identifier (an HTTPS URL or a DID).</param>
    /// <param name="key">The private key.</param>
    /// <param name="keyId">The JWT <c>kid</c>, or null.</param>
    /// <returns>The credentials.</returns>
    public static SelfSignedCredentials ForAgent(string agent, SigningKey key, string? keyId) =>
        new(agent, key, keyId, TimeSpan.FromSeconds(300), TimeProvider.System);

    /// <summary>Credentials for an agent with a URL identifier.</summary>
    /// <param name="agent">The agent identifier.</param>
    /// <param name="key">The private key.</param>
    /// <param name="keyId">The JWT <c>kid</c>, or null.</param>
    /// <returns>The credentials.</returns>
    public static SelfSignedCredentials ForAgent(Uri agent, SigningKey key, string? keyId) =>
        ForAgent(Uris.ToText(agent ?? throw new ArgumentNullException(nameof(agent))), key, keyId);

    /// <summary>Credentials for a <c>did:key</c> agent derived from a P-256 or Ed25519 key.</summary>
    /// <param name="key">The private key.</param>
    /// <returns>The credentials.</returns>
    public static SelfSignedCredentials DidKey(SigningKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new(global::Ebremer.Lws.Auth.DidKey.FromPublicKey(key.PublicKey), key,
            global::Ebremer.Lws.Auth.DidKey.KeyId(key.PublicKey), TimeSpan.FromSeconds(300), TimeProvider.System);
    }

    /// <summary>The agent identifier (<c>sub</c>, <c>iss</c> and <c>client_id</c>).</summary>
    public string Agent { get; }

    /// <summary>The key id placed in the JWT header, or null.</summary>
    public string? KeyId { get; }

    /// <summary>The JOSE algorithm (<c>ES256</c>, <c>EdDSA</c>).</summary>
    public string Algorithm => _key.Algorithm;

    /// <summary>The public key.</summary>
    public VerificationKey PublicKey => _key.PublicKey;

    /// <summary>How long minted tokens live (default 300 seconds).</summary>
    public TimeSpan Lifetime { get; }

    /// <summary>The clock.</summary>
    public TimeProvider TimeProvider { get; }

    /// <inheritdoc/>
    public string TokenType => Lws.TokenType.Jwt;

    /// <summary>Returns a copy whose tokens live for <paramref name="lifetime"/>.</summary>
    /// <param name="lifetime">The lifetime.</param>
    /// <returns>The credentials.</returns>
    public SelfSignedCredentials WithLifetime(TimeSpan lifetime) => new(Agent, _key, KeyId, lifetime, TimeProvider);

    /// <summary>Returns a copy using another clock (for tests).</summary>
    /// <param name="timeProvider">The clock.</param>
    /// <returns>The credentials.</returns>
    public SelfSignedCredentials WithTimeProvider(TimeProvider timeProvider) => new(Agent, _key, KeyId, Lifetime, timeProvider);

    /// <inheritdoc/>
    public ValueTask<string> GetSubjectTokenAsync(CredentialContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        string audience = context.Metadata.Issuer;
        DateTimeOffset now = TimeProvider.GetUtcNow();
        if (_cache.TryGetValue(audience, out (string Token, DateTimeOffset Expires) c) && now + ReuseMargin < c.Expires)
        {
            return ValueTask.FromResult(c.Token);
        }
        string token = CreateToken(audience);
        _cache[audience] = (token, now + Lifetime);
        return ValueTask.FromResult(token);
    }

    /// <summary>Creates and signs a new credential for <paramref name="audience"/>.</summary>
    /// <param name="audience">The authorization server issuer.</param>
    /// <returns>The JWT.</returns>
    public string CreateToken(string audience)
    {
        ArgumentNullException.ThrowIfNull(audience);
        long now = TimeProvider.GetUtcNow().ToUnixTimeSeconds();
        var header = new JsonObject { ["alg"] = _key.Algorithm, ["typ"] = "JWT" };
        if (KeyId is not null) header["kid"] = KeyId;
        var claims = new JsonObject
        {
            ["sub"] = Agent,
            ["iss"] = Agent,
            ["client_id"] = Agent,
            ["aud"] = new JsonArray(audience),
            ["iat"] = now,
            ["exp"] = now + (long)Lifetime.TotalSeconds,
            ["jti"] = Guid.NewGuid().ToString(),
        };
        return Jwt.Sign(header, claims, _key);
    }
}
