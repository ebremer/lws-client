// SPDX-License-Identifier: MIT
using System.Collections.Concurrent;
using System.Text.Json;
using Ebremer.Lws.Http;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws.Auth;

/// <summary>Options of <see cref="TokenExchangeAuthenticator"/>.</summary>
public sealed record TokenExchangeOptions
{
    /// <summary>Allow plain-HTTP authorization servers beyond loopback hosts (testing only).</summary>
    public bool AllowInsecureHttp { get; init; }

    /// <summary>
    /// Decides whether to trust an authorization server (<c>as_uri</c>, first argument) for a realm (second argument)
    /// before any credential is sent to it. Default: trust every server that passes the realm and HTTPS checks.
    /// </summary>
    /// <remarks>
    /// A malicious storage can name any authorization server. Self-signed tokens are audience-bound to that server,
    /// but static OpenID or SAML tokens may not be: use this filter or audience-restricted tokens.
    /// </remarks>
    public Func<Uri, Uri, bool>? AuthorizationServerFilter { get; init; }

    /// <summary>
    /// The handler for metadata and token requests. It must not follow redirects: a redirect would carry the subject
    /// token, a credential, to its target. <see cref="HttpClientHandler"/> and <see cref="SocketsHttpHandler"/> with
    /// <c>AllowAutoRedirect</c> are refused.
    /// </summary>
    public HttpMessageHandler? HttpMessageHandler { get; init; }

    /// <summary>
    /// The HTTP client for metadata and token requests (instead of <see cref="HttpMessageHandler"/>). It must not
    /// follow redirects; a request that was redirected anyway fails with <see cref="AuthenticationException"/>.
    /// </summary>
    public HttpClient? HttpClient { get; init; }

    /// <summary>Refresh tokens this long before they expire (default 30 seconds).</summary>
    public TimeSpan RefreshMargin { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>The timeout of each metadata and token request (default 30 seconds).</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>The <c>User-Agent</c> of metadata and token requests.</summary>
    public string? UserAgent { get; init; } = LwsClient.DefaultUserAgent;

    /// <summary>The clock (default <see cref="TimeProvider.System"/>).</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}

/// <summary>
/// The LWS authorization flow (OAuth 2.0 token exchange, RFC 8693):
/// <list type="number">
/// <item>a request is answered <c>401</c> with <c>WWW-Authenticate: Bearer as_uri="…", realm="…"</c>;</item>
/// <item>the request URL must lie inside the realm, the authorization server must use HTTPS (loopback hosts
/// excepted) and pass the optional filter;</item>
/// <item>the authorization server metadata is read from <c>/.well-known/lws-configuration</c> (never following a
/// redirect) and its <c>issuer</c> checked;</item>
/// <item>the <see cref="ICredentialProvider"/>'s subject token is exchanged for an access token with
/// <c>resource = realm</c>;</item>
/// <item>the request is sent again with the token, and the token is reused (until 30 seconds before it expires) for
/// every URL inside the realm, and never sent outside it.</item>
/// </list>
/// Instances are thread-safe; concurrent requests share a single in-flight exchange per realm.
/// </summary>
public sealed class TokenExchangeAuthenticator : IAuthenticator, IDisposable
{
    private readonly TokenExchangeOptions _options;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly ConcurrentDictionary<string, Entry> _tokens = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, AuthorizationServerMetadata> _metadata = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Task<Entry>> _inflight = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();

    private sealed record Entry(string Issuer, string RealmText, Uri Realm, AccessToken Token);

    /// <summary>Creates the authenticator.</summary>
    /// <param name="credentials">The authentication suite's credential provider.</param>
    /// <param name="options">The options.</param>
    /// <exception cref="ArgumentException">The handler follows redirects.</exception>
    public TokenExchangeAuthenticator(ICredentialProvider credentials, TokenExchangeOptions? options = null)
    {
        Credentials = credentials ?? throw new ArgumentNullException(nameof(credentials));
        _options = options ?? new TokenExchangeOptions();
        if (_options.HttpClient is not null)
        {
            _http = _options.HttpClient;
        }
        else if (_options.HttpMessageHandler is not null)
        {
            RefuseRedirectingHandler(_options.HttpMessageHandler);
            _http = new HttpClient(_options.HttpMessageHandler, disposeHandler: false) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
            _ownsHttp = true;
        }
        else
        {
            _http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false }) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
            _ownsHttp = true;
        }
    }

    /// <summary>The credential provider.</summary>
    public ICredentialProvider Credentials { get; }

    private static void RefuseRedirectingHandler(HttpMessageHandler handler)
    {
        for (HttpMessageHandler? h = handler; h is not null; h = (h as DelegatingHandler)?.InnerHandler)
        {
            if (h is HttpClientHandler { AllowAutoRedirect: true } or SocketsHttpHandler { AllowAutoRedirect: true })
            {
                throw new ArgumentException("The authorization server handler must not follow redirects (set AllowAutoRedirect = false)", nameof(handler));
            }
        }
    }

    /// <inheritdoc/>
    public ValueTask AuthorizeAsync(AuthRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        Entry? best = null;
        DateTimeOffset now = _options.TimeProvider.GetUtcNow();
        foreach (Entry e in _tokens.Values)
        {
            if (!e.Token.IsValid(now, _options.RefreshMargin) || !Uris.Contains(e.Realm, request.Uri)) continue;
            if (best is null || e.Realm.AbsolutePath.Length > best.Realm.AbsolutePath.Length) best = e;
        }
        if (best is not null) request.SetHeader("Authorization", "Bearer " + best.Token.Value);
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    /// <exception cref="AuthenticationException">
    /// The request URL is outside the challenge realm, the authorization server is insecure or rejected, or the
    /// token exchange failed. A cached token stays in use when the challenge is refused.
    /// </exception>
    public async ValueTask<bool> HandleChallengeAsync(AuthRequest request, AuthResponse response, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(response);
        AuthChallenge? challenge = response.Challenges.FirstOrDefault(c => c.IsScheme("Bearer") && c.AsUri is not null && c.Realm is not null);
        if (challenge is null) return false;
        string asText = challenge.AsUri!;
        string realmText = challenge.Realm!;
        Uri asUri = Uris.Resolve(null, asText) ?? throw new AuthenticationException($"The challenge as_uri is not an absolute URL: {asText}");
        Uri realm = Uris.Resolve(null, realmText) ?? throw new AuthenticationException($"The challenge realm is not an absolute URL: {realmText}");

        // Every check comes before the cached token the request carried is touched: a decoy challenge must not
        // evict a working token.
        if (!Uris.Contains(realm, request.Uri))
        {
            throw new AuthenticationException($"Request URL {Uris.ToText(request.Uri)} is not within the challenge realm {realmText}");
        }
        RequireSecure(asUri, "authorization server");
        if (_options.AuthorizationServerFilter is { } filter && !filter(asUri, realm))
        {
            throw new AuthenticationException($"Authorization server {asText} was rejected by the authorization server filter");
        }

        if (request.GetHeader("Authorization") is { } sent)
        {
            foreach (KeyValuePair<string, Entry> kv in _tokens)
            {
                if ("Bearer " + kv.Value.Token.Value == sent) _tokens.TryRemove(kv);
            }
        }
        string key = Key(asText, realmText);
        if (_tokens.TryGetValue(key, out Entry? cached) && cached.Token.IsValid(_options.TimeProvider.GetUtcNow(), _options.RefreshMargin))
        {
            return true; // obtained concurrently: retry with it
        }
        await ObtainAsync(asText, asUri, realmText, realm, cancellationToken).ConfigureAwait(false);
        return true;
    }

    /// <summary>Returns a valid access token for a realm, performing the token exchange when needed.</summary>
    /// <param name="asUri">The authorization server (<c>as_uri</c>).</param>
    /// <param name="realm">The realm.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The token.</returns>
    /// <exception cref="AuthenticationException">The exchange failed.</exception>
    public async Task<AccessToken> GetAccessTokenAsync(string asUri, string realm, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(asUri);
        ArgumentNullException.ThrowIfNull(realm);
        if (_tokens.TryGetValue(Key(asUri, realm), out Entry? e) && e.Token.IsValid(_options.TimeProvider.GetUtcNow(), _options.RefreshMargin))
        {
            return e.Token;
        }
        Uri issuer = Uris.Resolve(null, asUri) ?? throw new ArgumentException($"Not an absolute URL: {asUri}", nameof(asUri));
        Uri realmUri = Uris.Resolve(null, realm) ?? throw new ArgumentException($"Not an absolute URL: {realm}", nameof(realm));
        RequireSecure(issuer, "authorization server");
        return (await ObtainAsync(asUri, issuer, realm, realmUri, cancellationToken).ConfigureAwait(false)).Token;
    }

    /// <summary>Forgets every cached token and metadata document.</summary>
    public void Clear()
    {
        _tokens.Clear();
        _metadata.Clear();
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }

    private Task<Entry> ObtainAsync(string asText, Uri asUri, string realmText, Uri realm, CancellationToken cancellationToken)
    {
        string key = Key(asText, realmText);
        TaskCompletionSource<Entry>? mine = null;
        Task<Entry>? task;
        lock (_gate)
        {
            if (!_inflight.TryGetValue(key, out task))
            {
                mine = new TaskCompletionSource<Entry>(TaskCreationOptions.RunContinuationsAsynchronously);
                task = mine.Task;
                _inflight[key] = task;
            }
        }
        if (mine is not null) _ = RunExchangeAsync(mine, key, asText, asUri, realmText, realm);
        return task.WaitAsync(cancellationToken);
    }

    private async Task RunExchangeAsync(TaskCompletionSource<Entry> completion, string key, string asText, Uri asUri, string realmText, Uri realm)
    {
        try
        {
            AccessToken token = await ExchangeAsync(asText, asUri, realmText, realm).ConfigureAwait(false);
            var entry = new Entry(asText, realmText, realm, token);
            _tokens[key] = entry;
            completion.TrySetResult(entry);
        }
        catch (Exception e)
        {
            completion.TrySetException(e);
            _ = completion.Task.Exception; // observed here; callers rethrow it
        }
        finally
        {
            lock (_gate) _inflight.Remove(key);
        }
    }

    private async Task<AccessToken> ExchangeAsync(string asText, Uri asUri, string realmText, Uri realm)
    {
        AuthorizationServerMetadata md = await GetMetadataAsync(asText, asUri).ConfigureAwait(false);
        RequireSecure(md.TokenEndpoint, "token endpoint");
        if (!md.SupportsSubjectTokenType(Credentials.TokenType))
        {
            throw new AuthenticationException($"Authorization server {asText} does not accept subject tokens of type {Credentials.TokenType} "
                + $"(supported: {string.Join(", ", md.SubjectTokenTypesSupported)})");
        }
        string subjectToken;
        using (var cts = new CancellationTokenSource(_options.Timeout))
        {
            subjectToken = await Credentials.GetSubjectTokenAsync(new CredentialContext(asUri, realm, md), cts.Token).ConfigureAwait(false);
        }
        using var request = new HttpRequestMessage(HttpMethod.Post, md.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", Lws.GrantTypeTokenExchange),
                new("resource", realmText),
                new("subject_token", subjectToken),
                new("subject_token_type", Credentials.TokenType),
            ]),
        };
        request.Headers.TryAddWithoutValidation("Accept", Lws.MediaType.Json);
        (int status, HeaderMap _, byte[] body) = await SendAsync(request, "token endpoint").ConfigureAwait(false);
        JsonElement? json = null;
        if (body.Length > 0)
        {
            try
            {
                json = LwsJson.Parse(body, "token response");
            }
            catch (ProtocolException)
            {
                json = null;
            }
        }
        if (status / 100 != 2)
        {
            string? error = json is { ValueKind: JsonValueKind.Object } j ? LwsJson.GetString(j, "error") : null;
            string? description = json is { ValueKind: JsonValueKind.Object } k ? LwsJson.GetString(k, "error_description") : null;
            throw new AuthenticationException(
                $"Token exchange at {Uris.ToText(md.TokenEndpoint)} failed with HTTP {status}"
                + (error is null ? "" : $": {error}") + (description is null ? "" : $" ({description})"),
                error, description, status);
        }
        if (json is not { ValueKind: JsonValueKind.Object } tokenResponse)
        {
            throw new AuthenticationException("The token endpoint returned no JSON object", null, null, status);
        }
        return AccessToken.FromTokenResponse(tokenResponse, _options.TimeProvider.GetUtcNow());
    }

    private async Task<AuthorizationServerMetadata> GetMetadataAsync(string asText, Uri asUri)
    {
        if (_metadata.TryGetValue(asText, out AuthorizationServerMetadata? cached)) return cached;
        Uri url = AuthorizationServerMetadata.MetadataUrl(asUri);
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Accept", Lws.MediaType.Json);
        (int status, HeaderMap headers, byte[] body) = await SendAsync(request, "authorization server metadata").ConfigureAwait(false);
        if (status != 200)
        {
            throw new AuthenticationException($"Cannot read authorization server metadata {Uris.ToText(url)}: HTTP {status}", null, null, status);
        }
        if (!HeaderLists.IsJson(headers.GetFirst("content-type") ?? Lws.MediaType.Json))
        {
            throw new AuthenticationException($"Authorization server metadata {Uris.ToText(url)} is not JSON", null, null, status);
        }
        AuthorizationServerMetadata md;
        try
        {
            md = AuthorizationServerMetadata.Parse(LwsJson.Parse(body, "Authorization server metadata"), url);
        }
        catch (ProtocolException e)
        {
            throw new AuthenticationException($"Invalid authorization server metadata at {Uris.ToText(url)}: {e.Message}", null, null, status, e);
        }
        bool sameIssuer = Uris.EqualsIgnoringTrailingSlash(md.Issuer, asText)
            || (Uris.Resolve(null, md.Issuer) is { } issuerUri && Uris.EqualsIgnoringTrailingSlash(issuerUri.AbsoluteUri, asUri.AbsoluteUri));
        if (!sameIssuer)
        {
            throw new AuthenticationException($"Authorization server metadata issuer {md.Issuer} does not match as_uri {asText}", null, null, status);
        }
        _metadata[asText] = md;
        return md;
    }

    /// <summary>Sends a metadata or token request without following redirects; a redirect is refused.</summary>
    private async Task<(int Status, HeaderMap Headers, byte[] Body)> SendAsync(HttpRequestMessage request, string what)
    {
        if (_options.UserAgent is { } ua) request.Headers.TryAddWithoutValidation("User-Agent", ua);
        Uri target = request.RequestUri!;
        using var cts = new CancellationTokenSource(_options.Timeout);
        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
        }
        catch (HttpRequestException e)
        {
            throw new LwsTransportException($"{request.Method} {Uris.ToText(target)} failed: {e.Message}", e);
        }
        catch (OperationCanceledException e)
        {
            throw new LwsTransportException($"{request.Method} {Uris.ToText(target)} timed out", new TimeoutException(e.Message, e));
        }
        using (response)
        {
            int status = (int)response.StatusCode;
            if (status is >= 300 and < 400 || response.RequestMessage?.RequestUri is { } final && final != target)
            {
                string location = response.Headers.Location is { } l ? $" to {l.OriginalString}" : "";
                throw new AuthenticationException(
                    $"Refusing the redirect{location} of the {what} request {Uris.ToText(target)} (HTTP {status}): it would carry credentials to another URL",
                    null, null, status);
            }
            byte[] body;
            try
            {
                body = await response.Content.ReadAsByteArrayAsync(cts.Token).ConfigureAwait(false);
            }
            catch (Exception e) when (e is HttpRequestException or IOException)
            {
                throw new LwsTransportException($"{request.Method} {Uris.ToText(target)} failed: {e.Message}", e);
            }
            catch (OperationCanceledException e)
            {
                throw new LwsTransportException($"{request.Method} {Uris.ToText(target)} timed out", new TimeoutException(e.Message, e));
            }
            return (status, HeaderMap.From(response), body);
        }
    }

    private void RequireSecure(Uri uri, string what)
    {
        if (uri.Scheme == Uri.UriSchemeHttps) return;
        if (uri.Scheme == Uri.UriSchemeHttp && (_options.AllowInsecureHttp || Uris.IsLoopback(uri))) return;
        throw new AuthenticationException($"Refusing to use the insecure {what} {Uris.ToText(uri)} (HTTPS required)");
    }

    private static string Key(string asUri, string realm) => asUri + " " + realm;
}
