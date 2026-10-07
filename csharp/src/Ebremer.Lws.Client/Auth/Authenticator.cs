// SPDX-License-Identifier: MIT
using Ebremer.Lws.Http;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws.Auth;

/// <summary>
/// Pluggable request authentication for <see cref="LwsClient"/>. The client calls <see cref="AuthorizeAsync"/>
/// before every request attempt (every redirect hop included, each for its own URL). When an attempt is answered
/// <c>401 Unauthorized</c> it calls <see cref="HandleChallengeAsync"/>; returning true makes it send the request once
/// more (authorizing it again first).
/// </summary>
/// <remarks>
/// Provided implementations: <see cref="TokenExchangeAuthenticator"/> (the LWS OAuth 2.0 token exchange flow) and
/// <see cref="BearerTokenAuthenticator"/> (a known access token). Implementations must be thread-safe.
/// </remarks>
public interface IAuthenticator
{
    /// <summary>Adds credentials (typically an <c>Authorization</c> header) to an outgoing request.</summary>
    /// <param name="request">The request attempt.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A task.</returns>
    ValueTask AuthorizeAsync(AuthRequest request, CancellationToken cancellationToken = default);

    /// <summary>Reacts to a <c>401</c> response, e.g. by obtaining a token.</summary>
    /// <param name="request">The request attempt that was refused, with the headers it carried.</param>
    /// <param name="response">The <c>401</c> response.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>Whether the request should be sent again.</returns>
    ValueTask<bool> HandleChallengeAsync(AuthRequest request, AuthResponse response, CancellationToken cancellationToken = default);
}

/// <summary>A request attempt as seen by an <see cref="IAuthenticator"/>: method, target and mutable headers.</summary>
public sealed class AuthRequest
{
    private readonly List<KeyValuePair<string, string>> _headers;

    /// <summary>Creates a request attempt.</summary>
    /// <param name="method">The request method.</param>
    /// <param name="uri">The request URL.</param>
    /// <param name="headers">The request headers.</param>
    public AuthRequest(string method, Uri uri, IEnumerable<KeyValuePair<string, string>>? headers = null)
    {
        Method = method ?? throw new ArgumentNullException(nameof(method));
        Uri = uri ?? throw new ArgumentNullException(nameof(uri));
        _headers = headers is null ? [] : [.. headers];
    }

    /// <summary>The request method.</summary>
    public string Method { get; }

    /// <summary>The request URL.</summary>
    public Uri Uri { get; }

    /// <summary>The request headers, in order (a name may repeat, e.g. <c>Link</c>).</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Headers => _headers.AsReadOnly();

    /// <summary>The first value of a header (case-insensitive name), or null.</summary>
    /// <param name="name">The header name.</param>
    /// <returns>The value.</returns>
    public string? GetHeader(string name)
    {
        foreach (KeyValuePair<string, string> h in _headers)
        {
            if (string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)) return h.Value;
        }
        return null;
    }

    /// <summary>Sets (replaces) a header.</summary>
    /// <param name="name">The header name.</param>
    /// <param name="value">The value.</param>
    public void SetHeader(string name, string value)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(value);
        RemoveHeader(name);
        _headers.Add(new(name, value));
    }

    /// <summary>Adds a header value (keeping existing ones).</summary>
    /// <param name="name">The header name.</param>
    /// <param name="value">The value.</param>
    public void AddHeader(string name, string value)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(value);
        _headers.Add(new(name, value));
    }

    /// <summary>Removes every value of a header.</summary>
    /// <param name="name">The header name.</param>
    public void RemoveHeader(string name) =>
        _headers.RemoveAll(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase));

    /// <inheritdoc/>
    public override string ToString() => $"{Method} {Uris.ToText(Uri)}";
}

/// <summary>A <c>401</c> response passed to <see cref="IAuthenticator.HandleChallengeAsync"/>.</summary>
public sealed class AuthResponse
{
    /// <summary>Creates the response.</summary>
    /// <param name="uri">The request URL.</param>
    /// <param name="status">The status code.</param>
    /// <param name="headers">The response headers.</param>
    public AuthResponse(Uri uri, int status, HeaderMap headers)
    {
        Uri = uri ?? throw new ArgumentNullException(nameof(uri));
        Status = status;
        Headers = headers ?? throw new ArgumentNullException(nameof(headers));
    }

    /// <summary>The request URL.</summary>
    public Uri Uri { get; }

    /// <summary>The status code.</summary>
    public int Status { get; }

    /// <summary>The response headers.</summary>
    public HeaderMap Headers { get; }

    /// <summary>The parsed <c>WWW-Authenticate</c> challenges.</summary>
    public IReadOnlyList<AuthChallenge> Challenges => WwwAuthenticate.Parse(Headers.GetAll("www-authenticate"));
}

/// <summary>
/// Sends a known access token as <c>Authorization: Bearer …</c>, optionally only to URLs inside a realm
/// (recommended, so the token never reaches another server).
/// </summary>
public sealed class BearerTokenAuthenticator : IAuthenticator
{
    private readonly Func<CancellationToken, ValueTask<string?>> _token;

    /// <summary>Sends <paramref name="token"/>, only to URLs inside <paramref name="realm"/> when one is given.</summary>
    /// <param name="token">The access token.</param>
    /// <param name="realm">The protection realm; null sends the token everywhere (use a dedicated client).</param>
    public BearerTokenAuthenticator(string token, Uri? realm = null)
    {
        ArgumentNullException.ThrowIfNull(token);
        _token = _ => ValueTask.FromResult<string?>(token);
        Realm = realm;
    }

    /// <summary>Sends a token from <paramref name="tokenSupplier"/> (asked per request; null sends none).</summary>
    /// <param name="tokenSupplier">The token source.</param>
    /// <param name="realm">The protection realm; null sends the token everywhere.</param>
    public BearerTokenAuthenticator(Func<CancellationToken, ValueTask<string?>> tokenSupplier, Uri? realm = null)
    {
        _token = tokenSupplier ?? throw new ArgumentNullException(nameof(tokenSupplier));
        Realm = realm;
    }

    /// <summary>The realm the token is restricted to, or null.</summary>
    public Uri? Realm { get; }

    /// <inheritdoc/>
    public async ValueTask AuthorizeAsync(AuthRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (Realm is not null && !Uris.Contains(Realm, request.Uri)) return;
        string? token = await _token(cancellationToken).ConfigureAwait(false);
        if (token is not null) request.SetHeader("Authorization", "Bearer " + token);
    }

    /// <inheritdoc/>
    public ValueTask<bool> HandleChallengeAsync(AuthRequest request, AuthResponse response, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(false);
}
