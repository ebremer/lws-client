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
    /// Decides whether to trust an authorization server (its issuer, first argument) for a storage (second argument)
    /// before any credential is sent to it. Default: trust every server that passes the discovery and HTTPS checks.
    /// </summary>
    /// <remarks>
    /// A malicious storage can name any authorization server. Self-signed tokens are audience-bound to that server,
    /// but static OpenID or SAML tokens may not be: use this filter or audience-restricted tokens.
    /// </remarks>
    public Func<Uri, Uri, bool>? AuthorizationServerFilter { get; init; }

    /// <summary>
    /// The handler for discovery, metadata and token requests. It must not follow redirects: a redirect would carry the
    /// subject token, a credential, to its target. <see cref="HttpClientHandler"/> and <see cref="SocketsHttpHandler"/>
    /// with <c>AllowAutoRedirect</c> are refused.
    /// </summary>
    public HttpMessageHandler? HttpMessageHandler { get; init; }

    /// <summary>
    /// The HTTP client for discovery, metadata and token requests (instead of <see cref="HttpMessageHandler"/>). It must
    /// not follow redirects; a request that was redirected anyway fails with <see cref="AuthenticationException"/>.
    /// </summary>
    public HttpClient? HttpClient { get; init; }

    /// <summary>Refresh tokens this long before they expire (default 30 seconds).</summary>
    public TimeSpan RefreshMargin { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>The timeout of each discovery, metadata and token request (default 30 seconds).</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>The <c>User-Agent</c> of discovery, metadata and token requests.</summary>
    public string? UserAgent { get; init; } = LwsClient.DefaultUserAgent;

    /// <summary>The clock (default <see cref="TimeProvider.System"/>).</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}

/// <summary>
/// The LWS authorization flow (RFC 9728 discovery, then the OAuth 2.0 token exchange of RFC 8693):
/// <list type="number">
/// <item>a request is answered <c>401</c> with <c>WWW-Authenticate: Bearer resource_metadata="…"</c> and a <c>Link</c>
/// to the storage that holds the resource;</item>
/// <item>before asking for a token the client checks what the <c>401</c> told it against the URL that drew it: the
/// protected resource metadata is on the requested origin and names the requested URL, and the storage's root (from
/// its storage description) is on that origin too;</item>
/// <item>the first of the metadata's authorization servers that uses HTTPS (loopback hosts excepted) and passes the
/// optional filter is the issuer; its metadata is read from <c>/.well-known/lws-configuration</c> and its
/// <c>issuer</c> checked;</item>
/// <item>the <see cref="ICredentialProvider"/>'s subject token is exchanged for an access token with
/// <c>resource = storage</c>;</item>
/// <item>the request is sent again with the token, and the token is sent ahead of a <c>401</c> (until 30 seconds before
/// it expires) to every URL inside the storage or its root, and to no other; another URL's <c>401</c> that names the
/// same issuer and storage reuses it.</item>
/// </list>
/// Discovery, metadata and token requests never follow a redirect. The challenge of the drafts before 19 October 2026
/// (<c>Bearer as_uri="…", realm="…"</c>, without <c>resource_metadata</c>) is still followed: its realm must contain
/// the request URL, and is both the storage and the token's scope. Instances are thread-safe; concurrent requests share
/// a single in-flight exchange per issuer and storage.
/// </summary>
public sealed class TokenExchangeAuthenticator : IAuthenticator, IDisposable
{
    private readonly TokenExchangeOptions _options;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly ConcurrentDictionary<string, Entry> _tokens = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, AuthorizationServerMetadata> _metadata = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, StorageDescription> _storages = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Task<Entry>> _inflight = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();

    /// <summary>A cached token, the issuer and storage it was asked for, and the URLs it is sent to without a 401.</summary>
    private sealed record Entry(string Issuer, string Storage, IReadOnlyList<Uri> Scopes, AccessToken Token);

    /// <summary>What a 401 named, once every check passed: the issuer and its metadata, the storage, the token's scope.</summary>
    private sealed record Discovered(string IssuerText, Uri Issuer, AuthorizationServerMetadata Metadata, string StorageText, Uri Storage,
        IReadOnlyList<Uri> Scopes);

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
    /// <remarks>A token goes ahead of a <c>401</c> to the URLs inside its storage or the storage root; where several tokens'
    /// scopes contain the URL, the longest scope path wins.</remarks>
    public ValueTask AuthorizeAsync(AuthRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        Entry? best = null;
        int bestLength = -1;
        DateTimeOffset now = _options.TimeProvider.GetUtcNow();
        foreach (Entry e in _tokens.Values)
        {
            if (!e.Token.IsValid(now, _options.RefreshMargin)) continue;
            foreach (Uri scope in e.Scopes)
            {
                if (scope.AbsolutePath.Length > bestLength && Uris.Contains(scope, request.Uri))
                {
                    best = e;
                    bestLength = scope.AbsolutePath.Length;
                }
            }
        }
        if (best is not null) request.SetHeader("Authorization", "Bearer " + best.Token.Value);
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// The token is set on <paramref name="request"/>, so that the retry carries it even when the request URL lies outside
    /// the token's scope: that URL has just passed the checks.
    /// </remarks>
    /// <exception cref="AuthenticationException">
    /// A discovery check failed (the protected resource metadata is on another origin, unreadable or for another
    /// resource; the 401 links to no storage, or to one whose root is on another origin), the request URL is outside
    /// the realm of a challenge of the drafts before 19 October 2026, no authorization server is secure and accepted, or
    /// the token exchange failed. A cached token stays in use when the challenge is refused.
    /// </exception>
    public async ValueTask<bool> HandleChallengeAsync(AuthRequest request, AuthResponse response, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(response);
        IReadOnlyList<AuthChallenge> challenges = response.Challenges;
        Discovered discovered;
        if (challenges.FirstOrDefault(c => c.IsScheme("Bearer") && c.ResourceMetadata is not null) is { } challenge)
        {
            discovered = await DiscoverAsync(request.Uri, challenge.ResourceMetadata!, response.Headers, cancellationToken).ConfigureAwait(false);
        }
        else if (challenges.FirstOrDefault(c => c.IsScheme("Bearer") && c.AsUri is not null && c.Realm is not null) is { } legacy)
        {
            discovered = await FollowRealmAsync(request.Uri, legacy.AsUri!, legacy.Realm!, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            return false;
        }

        // Every check came before the cached token the request carried is touched: a decoy challenge must not evict a
        // working token. A token refused for the issuer and storage it was obtained for is dropped and exchanged again.
        string key = Key(discovered.IssuerText, discovered.StorageText);
        if (request.GetHeader("Authorization") is { } sent && _tokens.TryGetValue(key, out Entry? used) && "Bearer " + used.Token.Value == sent)
        {
            _tokens.TryRemove(new KeyValuePair<string, Entry>(key, used));
        }
        // A valid cached token (obtained concurrently, or for a URL outside its scope) is reused without an exchange.
        if (!_tokens.TryGetValue(key, out Entry? entry) || !entry.Token.IsValid(_options.TimeProvider.GetUtcNow(), _options.RefreshMargin))
        {
            entry = await ObtainAsync(discovered, cancellationToken).ConfigureAwait(false);
        }
        // The retry carries the token even outside its scope: the request URL has just passed the checks.
        request.SetHeader("Authorization", "Bearer " + entry.Token.Value);
        return true;
    }

    /// <summary>
    /// Returns a valid access token for a storage, performing the token exchange when needed. A token obtained here is
    /// sent ahead of a <c>401</c> to the URLs inside <paramref name="storage"/>.
    /// </summary>
    /// <param name="issuer">The authorization server's issuer.</param>
    /// <param name="storage">The storage (the token request's <c>resource</c>).</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The token.</returns>
    /// <exception cref="AuthenticationException">The exchange failed.</exception>
    public async Task<AccessToken> GetAccessTokenAsync(string issuer, string storage, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(storage);
        if (_tokens.TryGetValue(Key(issuer, storage), out Entry? e) && e.Token.IsValid(_options.TimeProvider.GetUtcNow(), _options.RefreshMargin))
        {
            return e.Token;
        }
        Uri issuerUri = Uris.Resolve(null, issuer) ?? throw new ArgumentException($"Not an absolute URL: {issuer}", nameof(issuer));
        Uri storageUri = Uris.Resolve(null, storage) ?? throw new ArgumentException($"Not an absolute URL: {storage}", nameof(storage));
        RequireSecure(issuerUri, "authorization server");
        AuthorizationServerMetadata md = await GetMetadataAsync(issuer, issuerUri, cancellationToken).ConfigureAwait(false);
        RequireSecure(md.TokenEndpoint, "token endpoint");
        return (await ObtainAsync(new Discovered(issuer, issuerUri, md, storage, storageUri, [storageUri]), cancellationToken).ConfigureAwait(false)).Token;
    }

    /// <summary>Forgets every cached token, authorization server metadata document and storage description.</summary>
    public void Clear()
    {
        _tokens.Clear();
        _metadata.Clear();
        _storages.Clear();
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }

    // ============================================================================================
    // Discovery (lws10-core "Authorization Server Discovery" and "Discovery Validation by a Client")
    // ============================================================================================

    /// <summary>Checks a <c>resource_metadata</c> challenge against the URL that drew it, and finds its issuer.</summary>
    private async Task<Discovered> DiscoverAsync(Uri requested, string metadataText, HeaderMap headers, CancellationToken cancellationToken)
    {
        // The metadata is on the requested origin, else it is not fetched.
        Uri metadataUrl = Uris.Resolve(requested, metadataText)
            ?? throw new AuthenticationException($"The challenge resource_metadata is not a URL: {metadataText}");
        if (!Uris.SameOrigin(metadataUrl, requested))
        {
            throw new AuthenticationException(
                $"The protected resource metadata {Uris.ToText(metadataUrl)} is not on the origin of the request URL {Uris.ToText(requested)}");
        }

        // The storage the 401 links to is what the token is for.
        Uri storage = LinkHeader.First(LinkHeader.Parse(headers.GetAll("link"), requested), Lws.Rel.Storage)?.Href
            ?? throw new AuthenticationException($"The 401 for {Uris.ToText(requested)} has no storage link (rel=\"{Lws.Rel.Storage}\")");
        if (storage.Scheme is not ("http" or "https"))
        {
            throw new AuthenticationException($"The storage {Uris.ToText(storage)} of the 401 for {Uris.ToText(requested)} is not an http(s) URL");
        }

        // The metadata describes the URL requested, and nothing else.
        ProtectedResourceMetadata prm = await GetProtectedResourceMetadataAsync(metadataUrl, cancellationToken).ConfigureAwait(false);
        if (!Uris.SameResource(Uris.ToText(requested), prm.Resource))
        {
            throw new AuthenticationException(
                $"The protected resource metadata {Uris.ToText(metadataUrl)} describes {prm.Resource}, not the request URL {Uris.ToText(requested)}");
        }

        // The storage's root is on the requested origin: a token for a storage elsewhere could be replayed there.
        Uri root = (await GetStorageDescriptionAsync(storage, cancellationToken).ConfigureAwait(false)).GetStorageRoot();
        if (!Uris.SameOrigin(root, requested))
        {
            throw new AuthenticationException(
                $"The root {Uris.ToText(root)} of the storage {Uris.ToText(storage)} is not on the origin of the request URL {Uris.ToText(requested)}");
        }

        // The issuer: the first authorization server that uses HTTPS and passes the filter.
        foreach (string server in prm.AuthorizationServers)
        {
            if (Uris.Resolve(null, server) is not { } issuer || !IsSecure(issuer) || !Trusted(issuer, storage)) continue;
            AuthorizationServerMetadata md = await GetMetadataAsync(server, issuer, cancellationToken).ConfigureAwait(false);
            RequireSecure(md.TokenEndpoint, "token endpoint");
            return new Discovered(server, issuer, md, Uris.ToText(storage), storage, [storage, root]);
        }
        throw new AuthenticationException(
            $"None of the authorization servers [{string.Join(", ", prm.AuthorizationServers)}] of {Uris.ToText(metadataUrl)} uses HTTPS "
            + "(loopback hosts excepted) and passes the authorization server filter");
    }

    /// <summary>Checks a challenge of the drafts before 19 October 2026 (<c>as_uri</c> and <c>realm</c>).</summary>
    private async Task<Discovered> FollowRealmAsync(Uri requested, string asText, string realmText, CancellationToken cancellationToken)
    {
        Uri issuer = Uris.Resolve(null, asText) ?? throw new AuthenticationException($"The challenge as_uri is not an absolute URL: {asText}");
        Uri realm = Uris.Resolve(null, realmText) ?? throw new AuthenticationException($"The challenge realm is not an absolute URL: {realmText}");
        if (!Uris.Contains(realm, requested))
        {
            throw new AuthenticationException($"Request URL {Uris.ToText(requested)} is not within the challenge realm {realmText}");
        }
        RequireSecure(issuer, "authorization server");
        if (!Trusted(issuer, realm))
        {
            throw new AuthenticationException($"Authorization server {asText} was rejected by the authorization server filter");
        }
        AuthorizationServerMetadata md = await GetMetadataAsync(asText, issuer, cancellationToken).ConfigureAwait(false);
        RequireSecure(md.TokenEndpoint, "token endpoint");
        return new Discovered(asText, issuer, md, realmText, realm, [realm]);
    }

    private async Task<ProtectedResourceMetadata> GetProtectedResourceMetadataAsync(Uri url, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Accept", Lws.MediaType.Json);
        (int status, HeaderMap headers, byte[] body) = await SendAsync(request, "protected resource metadata", cancellationToken).ConfigureAwait(false);
        if (status != 200)
        {
            throw new AuthenticationException($"Cannot read the protected resource metadata {Uris.ToText(url)}: HTTP {status}", null, null, status);
        }
        if (!HeaderLists.IsJson(headers.GetFirst("content-type") ?? Lws.MediaType.Json))
        {
            throw new AuthenticationException($"The protected resource metadata {Uris.ToText(url)} is not JSON", null, null, status);
        }
        try
        {
            return ProtectedResourceMetadata.Parse(LwsJson.Parse(body, "Protected resource metadata"));
        }
        catch (ProtocolException e)
        {
            throw new AuthenticationException($"Invalid protected resource metadata at {Uris.ToText(url)}: {e.Message}", null, null, status, e);
        }
    }

    /// <summary>A storage description with a storage root, read anonymously and cached per storage URL.</summary>
    private async Task<StorageDescription> GetStorageDescriptionAsync(Uri storage, CancellationToken cancellationToken)
    {
        string key = Uris.ToText(storage);
        if (_storages.TryGetValue(key, out StorageDescription? cached)) return cached;
        using var request = new HttpRequestMessage(HttpMethod.Get, storage);
        request.Headers.TryAddWithoutValidation("Accept", LwsClient.AcceptDescription);
        (int status, HeaderMap headers, byte[] body) = await SendAsync(request, "storage description", cancellationToken).ConfigureAwait(false);
        if (status != 200)
        {
            throw new AuthenticationException($"Cannot read the storage description {key}: HTTP {status}", null, null, status);
        }
        string? contentType = headers.GetFirst("content-type");
        if (contentType is not null && !HeaderLists.IsJson(contentType) && HeaderLists.Essence(contentType) != Lws.MediaType.LwsCid)
        {
            throw new AuthenticationException($"The storage description {key} has the unexpected media type {contentType}", null, null, status);
        }
        StorageDescription description;
        try
        {
            description = StorageDescription.Parse(LwsJson.Parse(body, "Storage description"), storage);
            description.GetStorageRoot();
        }
        catch (ProtocolException e)
        {
            throw new AuthenticationException($"Invalid storage description at {key}: {e.Message}", null, null, status, e);
        }
        _storages[key] = description;
        return description;
    }

    // ============================================================================================
    // The token exchange
    // ============================================================================================

    private Task<Entry> ObtainAsync(Discovered discovered, CancellationToken cancellationToken)
    {
        string key = Key(discovered.IssuerText, discovered.StorageText);
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
        if (mine is not null) _ = RunExchangeAsync(mine, key, discovered);
        return task.WaitAsync(cancellationToken);
    }

    private async Task RunExchangeAsync(TaskCompletionSource<Entry> completion, string key, Discovered discovered)
    {
        try
        {
            AccessToken token = await ExchangeAsync(discovered).ConfigureAwait(false);
            var entry = new Entry(discovered.IssuerText, discovered.StorageText, discovered.Scopes, token);
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

    private async Task<AccessToken> ExchangeAsync(Discovered discovered)
    {
        AuthorizationServerMetadata md = discovered.Metadata;
        if (!md.SupportsSubjectTokenType(Credentials.TokenType))
        {
            throw new AuthenticationException($"Authorization server {discovered.IssuerText} does not accept subject tokens of type {Credentials.TokenType} "
                + $"(supported: {string.Join(", ", md.SubjectTokenTypesSupported)})");
        }
        string subjectToken;
        using (var cts = new CancellationTokenSource(_options.Timeout))
        {
            subjectToken = await Credentials.GetSubjectTokenAsync(new CredentialContext(discovered.Issuer, discovered.Storage, md), cts.Token)
                .ConfigureAwait(false);
        }
        using var request = new HttpRequestMessage(HttpMethod.Post, md.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", Lws.GrantTypeTokenExchange),
                new("resource", discovered.StorageText),
                new("subject_token", subjectToken),
                new("subject_token_type", Credentials.TokenType),
            ]),
        };
        request.Headers.TryAddWithoutValidation("Accept", Lws.MediaType.Json);
        (int status, HeaderMap _, byte[] body) = await SendAsync(request, "token endpoint", CancellationToken.None).ConfigureAwait(false);
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

    private async Task<AuthorizationServerMetadata> GetMetadataAsync(string issuerText, Uri issuer, CancellationToken cancellationToken)
    {
        if (_metadata.TryGetValue(issuerText, out AuthorizationServerMetadata? cached)) return cached;
        Uri url = AuthorizationServerMetadata.MetadataUrl(issuer);
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Accept", Lws.MediaType.Json);
        (int status, HeaderMap headers, byte[] body) = await SendAsync(request, "authorization server metadata", cancellationToken).ConfigureAwait(false);
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
        bool sameIssuer = Uris.EqualsIgnoringTrailingSlash(md.Issuer, issuerText)
            || (Uris.Resolve(null, md.Issuer) is { } issuerUri && Uris.EqualsIgnoringTrailingSlash(issuerUri.AbsoluteUri, issuer.AbsoluteUri));
        if (!sameIssuer)
        {
            throw new AuthenticationException($"Authorization server metadata issuer {md.Issuer} does not match the issuer {issuerText}", null, null, status);
        }
        _metadata[issuerText] = md;
        return md;
    }

    /// <summary>
    /// Sends a discovery, metadata or token request without following redirects; a redirect is refused. The caller's
    /// cancellation is rethrown, the timeout is a transport failure.
    /// </summary>
    private async Task<(int Status, HeaderMap Headers, byte[] Body)> SendAsync(HttpRequestMessage request, string what, CancellationToken cancellationToken)
    {
        if (_options.UserAgent is { } ua) request.Headers.TryAddWithoutValidation("User-Agent", ua);
        Uri target = request.RequestUri!;
        using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(_options.Timeout);
        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
        }
        catch (HttpRequestException e)
        {
            throw new LwsTransportException($"{request.Method} {Uris.ToText(target)} failed: {e.Message}", e);
        }
        catch (OperationCanceledException e) when (!cancellationToken.IsCancellationRequested)
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
                    $"Refusing the redirect{location} of the {what} request {Uris.ToText(target)} (HTTP {status}): discovery, metadata and token "
                    + "requests follow no redirect, which could carry credentials to another URL",
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
            catch (OperationCanceledException e) when (!cancellationToken.IsCancellationRequested)
            {
                throw new LwsTransportException($"{request.Method} {Uris.ToText(target)} timed out", new TimeoutException(e.Message, e));
            }
            return (status, HeaderMap.From(response), body);
        }
    }

    private bool IsSecure(Uri uri) =>
        uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && (_options.AllowInsecureHttp || Uris.IsLoopback(uri)));

    private void RequireSecure(Uri uri, string what)
    {
        if (!IsSecure(uri)) throw new AuthenticationException($"Refusing to use the insecure {what} {Uris.ToText(uri)} (HTTPS required)");
    }

    private bool Trusted(Uri issuer, Uri storage) => _options.AuthorizationServerFilter is not { } filter || filter(issuer, storage);

    private static string Key(string issuer, string storage) => issuer + " " + storage;
}
