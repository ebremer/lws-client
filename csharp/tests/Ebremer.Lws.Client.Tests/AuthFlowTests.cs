// SPDX-License-Identifier: MIT
using System.Text.Json;
using Ebremer.Lws.Auth;
using Ebremer.Lws.Tests.Support;

namespace Ebremer.Lws.Tests;

/// <summary>
/// The LWS authorization flow (<c>401 → protected resource metadata → storage description → AS metadata → token
/// exchange → retry</c>) and its security checks, against a fake storage protected by a fake authorization server.
/// </summary>
public sealed class AuthFlowTests : IDisposable
{
    private const string Base = "https://storage.example";
    private const string Storage = Base + "/";
    private const string Root = Base + "/root/";
    private const string Prm = Base + "/.well-known/oauth-protected-resource";
    private const string As = "https://as.example";
    private const string Metadata = As + "/.well-known/lws-configuration";
    private const string TokenEndpoint = As + "/token";

    private readonly FakeServer _server = new();
    private readonly HashSet<string> _validTokens = [];
    private readonly FakeClock _clock = new(DateTimeOffset.FromUnixTimeSeconds(1_790_000_000));
    private int _exchanges;
    private int _expiresIn = 300;

    public AuthFlowTests()
    {
        _server.On("GET", Metadata, () => Respond.Json(200, MetadataJson(As)));
        _server.On("POST", TokenEndpoint, _ =>
        {
            int n = Interlocked.Increment(ref _exchanges);
            string token = "at-" + n;
            lock (_validTokens) _validTokens.Add(token);
            return Respond.Json(200, $"{{\"access_token\":\"{token}\",\"token_type\":\"Bearer\",\"expires_in\":{_expiresIn}}}");
        });
        Describe(Storage, Root);
        Protect("GET", Base + "/root/a", () => Respond.Text(200, "a"));
        Protect("GET", Base + "/root/b", () => Respond.Text(200, "b"));
        Protect("POST", Base + "/root/", () => Respond.Status(201, ("Location", "/root/new")));
        Protect("HEAD", Base + "/root/", () => Respond.Status(200));
    }

    public void Dispose()
    {
    }

    private static string MetadataJson(string issuer, string tokenEndpoint = TokenEndpoint) =>
        $"{{\"issuer\":\"{issuer}\",\"token_endpoint\":\"{tokenEndpoint}\",\"grant_types_supported\":[\"{Lws.GrantTypeTokenExchange}\"],"
        + $"\"subject_token_types_supported\":[\"{Lws.TokenType.Jwt}\",\"{Lws.TokenType.IdToken}\"]}}";

    /// <summary>Serves a storage description for <paramref name="storage"/> with its root.</summary>
    private void Describe(string storage, string root) =>
        _server.On("GET", storage, () => Respond.Json(200,
            $"{{\"@context\":[\"{Lws.CidContext}\",\"{Lws.Context}\"],\"id\":\"{storage}\",\"type\":\"Storage\","
            + $"\"service\":[{{\"type\":\"StorageRoot\",\"serviceEndpoint\":\"{root}\"}}]}}", "application/lws+cid"));

    /// <summary>The protected resource metadata URL of a resource, on its origin.</summary>
    private static string MetadataUrl(string url)
    {
        var resource = new Uri(url);
        return resource.GetLeftPart(UriPartial.Authority) + Lws.WellKnownOAuthProtectedResource + resource.PathAndQuery;
    }

    /// <summary>Serves the protected resource metadata of <paramref name="url"/>, naming the given authorization servers.</summary>
    private void DescribeResource(string url, params string[] authorizationServers)
    {
        string servers = string.Join(",", (authorizationServers.Length == 0 ? [As] : authorizationServers).Select(s => $"\"{s}\""));
        _server.On("GET", MetadataUrl(url), () => Respond.Json(200, $"{{\"resource\":\"{url}\",\"authorization_servers\":[{servers}]}}"));
    }

    /// <summary>The 401 of the storage: the resource's protected resource metadata, and a link to the storage.</summary>
    private static HttpResponseMessage Challenge(string url, string storage = Storage) =>
        Respond.Status(401, ("WWW-Authenticate", $"Bearer resource_metadata=\"{MetadataUrl(url)}\", error=\"invalid_token\""),
            ("Link", $"<{storage}>; rel=\"{Lws.Rel.Storage}\""));

    /// <summary>The 401 of the drafts before 19 October 2026.</summary>
    private static HttpResponseMessage LegacyChallenge(string asUri = As, string realm = Storage) =>
        Respond.Status(401, ("WWW-Authenticate", $"Bearer as_uri=\"{asUri}\", realm=\"{realm}\", error=\"invalid_token\""));

    private bool Authorized(Recorded r)
    {
        if (r.Header("Authorization") is not { } a || !a.StartsWith("Bearer ", StringComparison.Ordinal)) return false;
        lock (_validTokens) return _validTokens.Contains(a[7..]);
    }

    private void Protect(string method, string url, Func<HttpResponseMessage> ok, string storage = Storage)
    {
        _server.On(method, url, r => Authorized(r) ? ok() : Challenge(url, storage));
        DescribeResource(url);
    }

    private TokenExchangeAuthenticator Authenticator(ICredentialProvider? credentials = null, TokenExchangeOptions? options = null) =>
        new(credentials ?? new OpenIdCredentials("id-token"), (options ?? new TokenExchangeOptions()) with { HttpMessageHandler = _server, TimeProvider = _clock });

    private LwsClient Client(IAuthenticator authenticator) => new(new LwsClientOptions { HttpMessageHandler = _server, Authenticator = authenticator });

    private IEnumerable<string> Trace() => _server.Requests.Select(r => $"{r.Method} {r.Url}");

    private static Dictionary<string, string> Form(Recorded post) =>
        post.Text.Split('&').Select(p => p.Split('=', 2))
            .ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1].Replace('+', ' ')));

    private static Uri U(string url) => new(url);

    // ------------------------------------------------------------------------------------------------ the flow

    [Fact]
    public async Task FullFlowWithSelfSignedCredentials()
    {
        SigningKey key = SigningKey.GenerateP256();
        SelfSignedCredentials credentials = SelfSignedCredentials.DidKey(key).WithTimeProvider(_clock);
        using TokenExchangeAuthenticator auth = Authenticator(credentials);
        using LwsClient client = Client(auth);

        Resource r = await client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct);
        Assert.Equal("a", r.GetText());
        Assert.Equal(
            [$"GET {Base}/root/a", $"GET {Prm}/root/a", $"GET {Storage}", $"GET {Metadata}", $"POST {TokenEndpoint}", $"GET {Base}/root/a"],
            Trace());
        Recorded prm = _server.RequestsTo("GET", Prm + "/root/a").Single();
        Assert.Equal("application/json", prm.Header("Accept"));
        Assert.Null(prm.Header("Authorization"));
        Assert.Equal(LwsClient.DefaultUserAgent, prm.Header("User-Agent"));
        Recorded description = _server.RequestsTo("GET", Storage).Single();
        Assert.Equal("application/lws+cid, application/ld+json;q=0.9, application/json;q=0.8", description.Header("Accept"));
        Assert.Null(description.Header("Authorization"));
        Recorded exchange = _server.RequestsTo("POST", TokenEndpoint).Single();
        Assert.Equal("application/x-www-form-urlencoded", exchange.Header("Content-Type"));
        Dictionary<string, string> form = Form(exchange);
        Assert.Equal(Lws.GrantTypeTokenExchange, form["grant_type"]);
        Assert.Equal(Storage, form["resource"]);
        Assert.Equal(Lws.TokenType.Jwt, form["subject_token_type"]);
        string jwt = form["subject_token"];
        Assert.True(Jwt.Verify(jwt, key.PublicKey));
        JsonElement header = Jwt.DecodeHeader(jwt);
        Assert.Equal("ES256", header.GetProperty("alg").GetString());
        Assert.Equal("JWT", header.GetProperty("typ").GetString());
        Assert.Equal(credentials.KeyId, header.GetProperty("kid").GetString());
        JsonElement claims = Jwt.DecodeClaims(jwt);
        Assert.Equal(credentials.Agent, claims.GetProperty("sub").GetString());
        Assert.Equal(credentials.Agent, claims.GetProperty("iss").GetString());
        Assert.Equal(credentials.Agent, claims.GetProperty("client_id").GetString());
        Assert.StartsWith("did:key:zDn", credentials.Agent, StringComparison.Ordinal);
        Assert.Equal([As], claims.GetProperty("aud").EnumerateArray().Select(a => a.GetString()));
        Assert.Equal(1_790_000_000, claims.GetProperty("iat").GetInt64());
        Assert.Equal(1_790_000_300, claims.GetProperty("exp").GetInt64());
        Assert.True(Guid.TryParse(claims.GetProperty("jti").GetString(), out _));
        Assert.Equal("Bearer at-1", _server.Requests[^1].Header("Authorization"));
        Assert.Equal(LwsClient.DefaultUserAgent, _server.RequestsTo("GET", Metadata).Single().Header("User-Agent"));
    }

    [Fact]
    public async Task ProactiveReuseInsideTheScopeOnly()
    {
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        _server.On("GET", "https://elsewhere.example/x", () => Respond.Text(200, "x"));
        await client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct);
        int before = _server.Requests.Count;
        await client.ReadAsync(U(Base + "/root/b"), cancellationToken: Ct);
        Assert.Equal("Bearer at-1", _server.Requests[before].Header("Authorization"));
        Assert.Equal(before + 1, _server.Requests.Count);
        await client.ReadAsync(U("https://elsewhere.example/x"), cancellationToken: Ct);
        Assert.Null(_server.Requests[^1].Header("Authorization"));
        await client.ReadAsync(U("http://storage.example/root/a"), new ReadOptions(), Ct).ContinueWith(_ => { }, Ct);
        Assert.Null(_server.Requests[^1].Header("Authorization"));
        Assert.Equal(1, _exchanges);
        Assert.Equal("at-1", (await auth.GetAccessTokenAsync(As, Storage, Ct)).Value);
    }

    [Fact]
    public async Task TheScopeIsTheStorageAndItsRootAndTheLongestScopeWins()
    {
        // A storage described at /s1 whose root is /data/s1/, and another whose storage and root are /data/.
        Describe(Base + "/s1", Base + "/data/s1/");
        Describe(Base + "/data/", Base + "/data/");
        Protect("GET", Base + "/data/s1/x", () => Respond.Text(200, "x"), storage: Base + "/s1");
        Protect("GET", Base + "/data/other", () => Respond.Text(200, "other"), storage: Base + "/data/");
        foreach (string url in new[] { Base + "/s1/meta", Base + "/data/s1/y", Base + "/data/more", Base + "/elsewhere" })
        {
            _server.On("GET", url, () => Respond.Text(200, "ok"));
        }
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);

        await client.ReadAsync(U(Base + "/data/s1/x"), cancellationToken: Ct);
        Assert.Equal(Base + "/s1", Form(_server.RequestsTo("POST", TokenEndpoint).Single())["resource"]);
        await client.ReadAsync(U(Base + "/data/other"), cancellationToken: Ct);
        Assert.Equal(Base + "/data/", Form(_server.RequestsTo("POST", TokenEndpoint).Last())["resource"]);

        async Task<string?> SentTo(string url)
        {
            await client.ReadAsync(U(url), cancellationToken: Ct);
            return _server.Requests[^1].Header("Authorization");
        }
        Assert.Equal("Bearer at-1", await SentTo(Base + "/s1/meta"));    // inside the storage
        Assert.Equal("Bearer at-1", await SentTo(Base + "/data/s1/y"));  // inside both roots: /data/s1/ is longer than /data/
        Assert.Equal("Bearer at-2", await SentTo(Base + "/data/more"));
        Assert.Null(await SentTo(Base + "/elsewhere"));
        Assert.Equal(2, _exchanges);
    }

    [Fact]
    public async Task TheRetryCarriesTheTokenOutsideItsScope()
    {
        // A service endpoint outside the storage (/s1) and its root (/data/s1/) passes the checks: its retry carries
        // the token, and another one's 401 reuses it without a second exchange; neither gets it ahead of a 401.
        Describe(Base + "/s1", Base + "/data/s1/");
        Protect("GET", Base + "/services/inbox", () => Respond.Text(200, "inbox"), storage: Base + "/s1");
        Protect("GET", Base + "/services/other", () => Respond.Text(200, "other"), storage: Base + "/s1");
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        Assert.Equal("inbox", (await client.ReadAsync(U(Base + "/services/inbox"), cancellationToken: Ct)).GetText());
        Assert.Equal([null, "Bearer at-1"], _server.RequestsTo("GET", Base + "/services/inbox").Select(r => r.Header("Authorization")));
        Assert.Equal("other", (await client.ReadAsync(U(Base + "/services/other"), cancellationToken: Ct)).GetText());
        Assert.Equal([null, "Bearer at-1"], _server.RequestsTo("GET", Base + "/services/other").Select(r => r.Header("Authorization")));
        Assert.Equal(1, _exchanges);
    }

    [Fact]
    public async Task OpenIdAndSamlSubjectTokens()
    {
        using (TokenExchangeAuthenticator oidc = Authenticator(new OpenIdCredentials((ctx, _) =>
               {
                   Assert.Equal(As, ctx.Metadata.Issuer);
                   Assert.Equal(As + "/", ctx.Issuer.AbsoluteUri);
                   Assert.Equal(Storage, ctx.Storage.AbsoluteUri);
                   return ValueTask.FromResult("my-id-token");
               })))
        using (LwsClient client = Client(oidc))
        {
            await client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct);
        }
        Recorded first = _server.RequestsTo("POST", TokenEndpoint).Single();
        Assert.Contains("subject_token=my-id-token", first.Text, StringComparison.Ordinal);
        Assert.Contains("subject_token_type=" + Uri.EscapeDataString(Lws.TokenType.IdToken), first.Text, StringComparison.Ordinal);

        _server.On("GET", Metadata, () => Respond.Json(200, $"{{\"issuer\":\"{As}\",\"token_endpoint\":\"{TokenEndpoint}\"}}"));
        using TokenExchangeAuthenticator saml = Authenticator(SamlCredentials.FromXml("<saml:Assertion/>"));
        using LwsClient samlClient = Client(saml);
        await samlClient.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct);
        Recorded second = _server.RequestsTo("POST", TokenEndpoint).Last();
        Assert.Contains("subject_token=" + SamlCredentials.Encode("<saml:Assertion/>"), second.Text, StringComparison.Ordinal);
        Assert.Contains("subject_token_type=" + Uri.EscapeDataString(Lws.TokenType.Saml2), second.Text, StringComparison.Ordinal);
        Assert.Equal("PHNhbWw6QXNzZXJ0aW9uLz4", SamlCredentials.Encode("<saml:Assertion/>"));
    }

    [Fact]
    public async Task ARejectedTokenIsDroppedAndExchangedOnce()
    {
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        await client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct);
        lock (_validTokens) _validTokens.Clear(); // the server revokes at-1
        await client.ReadAsync(U(Base + "/root/b"), cancellationToken: Ct);
        Assert.Equal(2, _exchanges);
        Assert.Equal(["Bearer at-1", "Bearer at-2"], _server.RequestsTo("GET", Base + "/root/b").Select(r => r.Header("Authorization")));
    }

    [Fact]
    public async Task ATokenIsDroppedOnlyWhenItsOwnStorageRefusesIt()
    {
        // /root/other refuses at-1 with a 401 that links to another storage (its root on this origin, below /root/): the
        // client gets a token for that storage and keeps at-1 for its own.
        const string other = Base + "/root/other";
        Describe(Base + "/other-storage", other + "/");
        DescribeResource(other);
        _server.On("GET", other, r => r.Header("Authorization") == "Bearer at-2" ? Respond.Text(200, "other") : Challenge(other, Base + "/other-storage"));
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        await client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct);
        Assert.Equal("other", (await client.ReadAsync(U(other), cancellationToken: Ct)).GetText());
        Assert.Equal(["Bearer at-1", "Bearer at-2"], _server.RequestsTo("GET", other).Select(r => r.Header("Authorization")));
        Assert.Equal(Base + "/other-storage", Form(_server.RequestsTo("POST", TokenEndpoint).Last())["resource"]);
        await client.ReadAsync(U(Base + "/root/b"), cancellationToken: Ct);
        Assert.Equal("Bearer at-1", _server.Requests[^1].Header("Authorization"));
        Assert.Equal(2, _exchanges);
    }

    [Fact]
    public async Task ExpiringTokensAreRefreshedBeforeTheyExpire()
    {
        _expiresIn = 60;
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        await client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct);
        _clock.Advance(TimeSpan.FromSeconds(29));
        await client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct);
        Assert.Equal(1, _exchanges);
        _clock.Advance(TimeSpan.FromSeconds(2)); // inside the 30 s refresh margin
        int before = _server.Requests.Count;
        await client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct);
        Assert.Null(_server.Requests[before].Header("Authorization"));
        Assert.Equal(2, _exchanges);
    }

    [Fact]
    public async Task ConcurrentRequestsShareOneExchange()
    {
        var gate = new TaskCompletionSource();
        _server.BeforeRespond = async (r, token) =>
        {
            if (r.Url == TokenEndpoint) await gate.Task.WaitAsync(token);
        };
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        Task<Resource>[] reads = [.. Enumerable.Range(0, 8).Select(_ => client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct))];
        await Task.Delay(200, Ct);
        gate.SetResult();
        Resource[] results = await Task.WhenAll(reads);
        Assert.All(results, r => Assert.Equal("a", r.GetText()));
        Assert.Equal(1, _exchanges);
    }

    [Fact]
    public async Task StorageDescriptionsAreCachedUntilCleared()
    {
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        await client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct);
        lock (_validTokens) _validTokens.Clear();
        await client.ReadAsync(U(Base + "/root/b"), cancellationToken: Ct);
        Assert.Equal(2, _exchanges);
        Assert.Equal(2, _server.RequestsTo("GET", Prm + "/root/a").Count() + _server.RequestsTo("GET", Prm + "/root/b").Count());
        Assert.Single(_server.RequestsTo("GET", Storage));
        Assert.Single(_server.RequestsTo("GET", Metadata));
        auth.Clear();
        await client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct);
        Assert.Equal(2, _server.RequestsTo("GET", Storage).Count());
        Assert.Equal(2, _server.RequestsTo("GET", Metadata).Count());
        Assert.Equal(3, _exchanges);
    }

    [Fact]
    public async Task PostIsRetriedOnceAfterA401Only()
    {
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        CreateResult created = await client.CreateTextAsync(U(Base + "/root/"), "hello", cancellationToken: Ct);
        Assert.Equal(Base + "/root/new", created.Location.AbsoluteUri);
        Assert.Equal([null, "Bearer at-1"], _server.RequestsTo("POST", Base + "/root/").Select(r => r.Header("Authorization")));
        Assert.All(_server.RequestsTo("POST", Base + "/root/"), r => Assert.Equal("hello", r.Text));

        // A server that keeps refusing: exactly one retry, then UnauthorizedException.
        _server.On("POST", Base + "/root/stubborn/", _ => Challenge(Base + "/root/stubborn/"));
        DescribeResource(Base + "/root/stubborn/");
        await Assert.ThrowsAsync<UnauthorizedException>(() => client.CreateTextAsync(U(Base + "/root/stubborn/"), "x", cancellationToken: Ct));
        Assert.Equal(2, _server.RequestsTo("POST", Base + "/root/stubborn/").Count());
    }

    [Fact]
    public async Task AStreamedBodyEstablishesTheTokenFirst()
    {
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        await client.CreateAsync(U(Base + "/root/"), new MemoryStream("streamed"u8.ToArray()), "text/plain", cancellationToken: Ct);
        Assert.Equal(
            [$"HEAD {Base}/root/", $"GET {Prm}/root/", $"GET {Storage}", $"GET {Metadata}", $"POST {TokenEndpoint}", $"HEAD {Base}/root/", $"POST {Base}/root/"],
            Trace());
        Recorded post = _server.RequestsTo("POST", Base + "/root/").Single();
        Assert.Equal("Bearer at-1", post.Header("Authorization"));
        Assert.Equal("streamed", post.Text);
    }

    [Fact]
    public async Task AChallengeWithoutAnAuthorizationServerIsUnauthorized()
    {
        _server.On("GET", Base + "/basic", () => Respond.Status(401, ("WWW-Authenticate", "Basic realm=\"x\"")));
        _server.On("GET", Base + "/bearer", () => Respond.Status(401, ("WWW-Authenticate", "Bearer realm=\"x\""), ("Link", $"<{Storage}>; rel=\"{Lws.Rel.Storage}\"")));
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        UnauthorizedException e = await Assert.ThrowsAsync<UnauthorizedException>(() => client.ReadAsync(U(Base + "/basic"), cancellationToken: Ct));
        Assert.True(e.Challenges.Single().IsScheme("basic"));
        await Assert.ThrowsAsync<UnauthorizedException>(() => client.ReadAsync(U(Base + "/bearer"), cancellationToken: Ct));
        Assert.Equal(0, _exchanges);
        Assert.Equal([$"GET {Base}/basic", $"GET {Base}/bearer"], Trace());
    }

    // ------------------------------------------------------------------------------------------------ the checks

    [Fact]
    public async Task TheDiscoveryChecksComeBeforeAnyToken()
    {
        const string decoy = Base + "/root/decoy";
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        async Task<AuthenticationException> RefusedAsync(Func<HttpResponseMessage> challenge)
        {
            _server.On("GET", decoy, challenge);
            return await Assert.ThrowsAsync<AuthenticationException>(() => client.ReadAsync(U(decoy), cancellationToken: Ct));
        }

        // Metadata on another origin, or a 401 without a storage link: nothing is fetched.
        AuthenticationException e = await RefusedAsync(() => Respond.Status(401,
            ("WWW-Authenticate", "Bearer resource_metadata=\"https://evil.example/.well-known/oauth-protected-resource/root/decoy\""),
            ("Link", $"<{Storage}>; rel=\"{Lws.Rel.Storage}\"")));
        Assert.Contains("origin", e.Message, StringComparison.Ordinal);
        await RefusedAsync(() => Respond.Status(401, ("WWW-Authenticate", $"Bearer resource_metadata=\"{MetadataUrl(decoy)}\"")));
        Assert.All(_server.Requests, r => Assert.Equal(decoy, r.Url));

        // Metadata that cannot be read, is not JSON, is invalid, or describes another resource.
        await RefusedAsync(() => Challenge(decoy));
        _server.On("GET", MetadataUrl(decoy), () => Respond.Text(200, "{}", "text/html"));
        await RefusedAsync(() => Challenge(decoy));
        _server.On("GET", MetadataUrl(decoy), () => Respond.Json(200, $"{{\"resource\":\"{decoy}\",\"authorization_servers\":[]}}"));
        await RefusedAsync(() => Challenge(decoy));
        _server.On("GET", MetadataUrl(decoy), () => Respond.Json(200, $"{{\"resource\":\"{decoy}/\",\"authorization_servers\":[\"{As}\"]}}"));
        e = await RefusedAsync(() => Challenge(decoy));
        Assert.Contains("describes", e.Message, StringComparison.Ordinal);

        // A storage whose root is on another origin, one without a root, one that cannot be read.
        DescribeResource(decoy);
        Describe(Base + "/vault/", "https://evil.example/vault/");
        e = await RefusedAsync(() => Challenge(decoy, Base + "/vault/"));
        Assert.Contains("root", e.Message, StringComparison.Ordinal);
        _server.On("GET", Base + "/bare", () => Respond.Json(200, $"{{\"id\":\"{Base}/bare\",\"type\":\"Storage\"}}", "application/lws+cid"));
        await RefusedAsync(() => Challenge(decoy, Base + "/bare"));
        await RefusedAsync(() => Challenge(decoy, Base + "/missing"));

        Assert.Empty(_server.RequestsTo("GET", Metadata));
        Assert.Equal(0, _exchanges);
        Assert.DoesNotContain(_server.Requests, r => r.Uri.Host == "evil.example");
    }

    [Fact]
    public async Task TheFirstSecureAndAcceptedAuthorizationServerIsTheIssuer()
    {
        const string url = Base + "/root/c";
        Protect("GET", url, () => Respond.Text(200, "c"));
        DescribeResource(url, "not a url", "http://insecure.example", "https://filtered.example", As, "https://unused.example");
        Uri? storageSeen = null;
        using TokenExchangeAuthenticator auth = Authenticator(options: new TokenExchangeOptions
        {
            AuthorizationServerFilter = (issuer, storage) =>
            {
                storageSeen = storage;
                return issuer.Host != "filtered.example";
            },
        });
        using LwsClient client = Client(auth);
        Assert.Equal("c", (await client.ReadAsync(U(url), cancellationToken: Ct)).GetText());
        Assert.Equal(Storage, storageSeen?.AbsoluteUri);
        Assert.Single(_server.RequestsTo("POST", TokenEndpoint));
        Assert.DoesNotContain(_server.Requests, r => r.Uri.Host is "insecure.example" or "filtered.example" or "unused.example");
    }

    [Fact]
    public async Task ADecoyChallengeLeavesTheCachedTokenInUse()
    {
        const string decoy = Base + "/root/decoy";
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        await client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct);
        Assert.Equal(1, _exchanges);

        // The storage answers a request that carried the cached token with challenges that must all be refused:
        // metadata on another origin, or for another resource; a storage whose root is elsewhere; an insecure
        // authorization server; a realm (drafts before 19 October 2026) that does not contain the URL, or an insecure
        // as_uri.
        Describe(Base + "/vault/", "https://evil.example/vault/");
        static string PrmJson(string resource, string server = As) => $"{{\"resource\":\"{resource}\",\"authorization_servers\":[\"{server}\"]}}";
        (Func<HttpResponseMessage> Challenge, string Metadata)[] decoys =
        [
            (() => Respond.Status(401, ("WWW-Authenticate", "Bearer resource_metadata=\"https://evil.example/.well-known/oauth-protected-resource/root/decoy\""),
                ("Link", $"<{Storage}>; rel=\"{Lws.Rel.Storage}\"")), PrmJson(decoy)),
            (() => Challenge(decoy), PrmJson(Base + "/root/a")),
            (() => Challenge(decoy, Base + "/vault/"), PrmJson(decoy)),
            (() => Challenge(decoy), PrmJson(decoy, "http://as.evil.example")),
            (() => LegacyChallenge(realm: "https://evil.example/"), "{}"),
            (() => LegacyChallenge(asUri: "http://as.evil.example"), "{}"),
        ];
        foreach ((Func<HttpResponseMessage> challenge, string metadata) in decoys)
        {
            _server.On("GET", decoy, challenge);
            _server.On("GET", MetadataUrl(decoy), () => Respond.Json(200, metadata));
            await Assert.ThrowsAsync<AuthenticationException>(() => client.ReadAsync(U(decoy), cancellationToken: Ct));
            Assert.Equal("Bearer at-1", _server.RequestsTo("GET", decoy).Last().Header("Authorization"));
            int before = _server.Requests.Count;
            await client.ReadAsync(U(Base + "/root/b"), cancellationToken: Ct);
            Assert.Equal("Bearer at-1", _server.Requests[before].Header("Authorization"));
            Assert.Equal(before + 1, _server.Requests.Count);
        }

        using TokenExchangeAuthenticator filtered = Authenticator(options: new TokenExchangeOptions
        {
            AuthorizationServerFilter = (issuer, _) => issuer.Host == "as.example",
        });
        using LwsClient filteredClient = Client(filtered);
        await filteredClient.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct);
        _server.On("GET", decoy, () => Challenge(decoy));
        DescribeResource(decoy, "https://as.attacker.example");
        await Assert.ThrowsAsync<AuthenticationException>(() => filteredClient.ReadAsync(U(decoy), cancellationToken: Ct));
        _server.On("GET", decoy, () => LegacyChallenge(asUri: "https://as.attacker.example"));
        await Assert.ThrowsAsync<AuthenticationException>(() => filteredClient.ReadAsync(U(decoy), cancellationToken: Ct));
        await filteredClient.ReadAsync(U(Base + "/root/b"), cancellationToken: Ct);
        Assert.Equal("Bearer at-2", _server.Requests[^1].Header("Authorization"));
        Assert.DoesNotContain(_server.Requests, r => r.Uri.Host.Contains("attacker", StringComparison.Ordinal) || r.Uri.Host.Contains("evil", StringComparison.Ordinal));
        Assert.Equal(2, _exchanges);
    }

    [Fact]
    public async Task InsecureAuthorizationServersAreRefusedUnlessAllowed()
    {
        const string insecure = "http://as.example";
        Protect("GET", Base + "/root/c", () => Respond.Text(200, "c"));
        DescribeResource(Base + "/root/c", insecure);
        _server.On("GET", insecure + "/.well-known/lws-configuration", () => Respond.Json(200, MetadataJson(insecure, insecure + "/token")));
        _server.On("POST", insecure + "/token", () => Respond.Json(200, "{\"access_token\":\"at-1\",\"token_type\":\"bearer\"}"));
        lock (_validTokens) _validTokens.Add("at-1");
        using (TokenExchangeAuthenticator strict = Authenticator())
        using (LwsClient client = Client(strict))
        {
            AuthenticationException e = await Assert.ThrowsAsync<AuthenticationException>(() => client.ReadAsync(U(Base + "/root/c"), cancellationToken: Ct));
            Assert.Contains("HTTPS", e.Message, StringComparison.Ordinal);
            Assert.Null(e.Status);
            Assert.DoesNotContain(_server.Requests, r => r.Uri.Scheme == "http");
        }
        using (TokenExchangeAuthenticator lax = Authenticator(options: new TokenExchangeOptions { AllowInsecureHttp = true }))
        using (LwsClient client = Client(lax))
        {
            Assert.Equal("c", (await client.ReadAsync(U(Base + "/root/c"), cancellationToken: Ct)).GetText());
        }
        // An https AS whose token endpoint is plain http is refused too.
        _server.On("GET", Metadata, () => Respond.Json(200, MetadataJson(As, "http://as.example/token")));
        using TokenExchangeAuthenticator mixed = Authenticator();
        using LwsClient mixedClient = Client(mixed);
        await Assert.ThrowsAsync<AuthenticationException>(() => mixedClient.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct));
    }

    [Fact]
    public async Task LoopbackAuthorizationServersMayUseHttp()
    {
        const string local = "http://localhost:8787";
        Describe(local + "/", local + "/root/");
        _server.On("GET", local + "/root/x", r => Authorized(r) ? Respond.Text(200, "x") : Challenge(local + "/root/x", local + "/"));
        DescribeResource(local + "/root/x", local);
        _server.On("GET", local + "/.well-known/lws-configuration", () => Respond.Json(200, MetadataJson(local, local + "/oauth/token")));
        _server.On("POST", local + "/oauth/token", () => Respond.Json(200, "{\"access_token\":\"at-local\",\"token_type\":\"Bearer\"}"));
        lock (_validTokens) _validTokens.Add("at-local");
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        Assert.Equal("x", (await client.ReadAsync(U(local + "/root/x"), cancellationToken: Ct)).GetText());
        Assert.Contains("resource=" + Uri.EscapeDataString(local + "/"), _server.RequestsTo("POST", local + "/oauth/token").Single().Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheChallengeOfTheDraftsBefore19OctoberIsFollowed()
    {
        _server.On("GET", Base + "/root/legacy", r => Authorized(r) ? Respond.Text(200, "legacy") : LegacyChallenge(realm: Root));
        _server.On("GET", Base + "/public", () => Respond.Text(200, "p"));
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        Assert.Equal("legacy", (await client.ReadAsync(U(Base + "/root/legacy"), cancellationToken: Ct)).GetText());
        Assert.Equal([$"GET {Base}/root/legacy", $"GET {Metadata}", $"POST {TokenEndpoint}", $"GET {Base}/root/legacy"], Trace());
        Assert.Equal(Root, Form(_server.RequestsTo("POST", TokenEndpoint).Single())["resource"]);
        // The realm alone is the token's scope.
        await client.ReadAsync(U(Base + "/root/b"), cancellationToken: Ct);
        Assert.Equal("Bearer at-1", _server.Requests[^1].Header("Authorization"));
        await client.ReadAsync(U(Base + "/public"), cancellationToken: Ct);
        Assert.Null(_server.Requests[^1].Header("Authorization"));
    }

    [Fact]
    public async Task TheRealmOfTheDraftsBefore19OctoberMustContainTheRequestUrl()
    {
        _server.On("GET", Base + "/root/other", _ => LegacyChallenge(realm: Base + "/other/"));
        _server.On("GET", Base + "/storage_10/x", _ => LegacyChallenge(realm: Base + "/storage_1"));
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        await Assert.ThrowsAsync<AuthenticationException>(() => client.ReadAsync(U(Base + "/root/other"), cancellationToken: Ct));
        await Assert.ThrowsAsync<AuthenticationException>(() => client.ReadAsync(U(Base + "/storage_10/x"), cancellationToken: Ct));
        Assert.Empty(_server.RequestsTo("GET", Metadata));
        Assert.Equal(0, _exchanges);
    }

    [Fact]
    public async Task DiscoveryMetadataAndTokenRequestsNeverFollowRedirects()
    {
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);

        _server.On("GET", Prm + "/root/a", () => Respond.Status(307, ("Location", "https://attacker.example/prm")));
        Assert.Equal(307, (await Assert.ThrowsAsync<AuthenticationException>(() => client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct))).Status);
        DescribeResource(Base + "/root/a");
        _server.On("GET", Storage, () => Respond.Status(302, ("Location", "https://attacker.example/storage")));
        Assert.Equal(302, (await Assert.ThrowsAsync<AuthenticationException>(() => client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct))).Status);
        Describe(Storage, Root);

        _server.On("GET", Metadata, () => Respond.Status(307, ("Location", "https://attacker.example/.well-known/lws-configuration")));
        AuthenticationException md = await Assert.ThrowsAsync<AuthenticationException>(() => client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct));
        Assert.Equal(307, md.Status);
        Assert.Empty(_server.RequestsTo("POST", TokenEndpoint));

        _server.On("GET", Metadata, () => Respond.Json(200, MetadataJson(As)));
        _server.On("POST", TokenEndpoint, () => Respond.Status(308, ("Location", "https://attacker.example/token")));
        AuthenticationException token = await Assert.ThrowsAsync<AuthenticationException>(() => client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct));
        Assert.Equal(308, token.Status);
        Assert.Contains("redirect", token.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Single(_server.RequestsTo("POST", TokenEndpoint));
        Assert.DoesNotContain(_server.Requests, r => r.Uri.Host == "attacker.example");

        // A handler that would follow redirects by itself is refused outright.
        using var following = new SocketsHttpHandler { AllowAutoRedirect = true };
        Assert.Throws<ArgumentException>(() => new TokenExchangeAuthenticator(new OpenIdCredentials("x"), new TokenExchangeOptions { HttpMessageHandler = following }));
        using var inner = new HttpClientHandler();
        using var chained = new PassThrough(inner);
        Assert.Throws<ArgumentException>(() => new TokenExchangeAuthenticator(new OpenIdCredentials("x"), new TokenExchangeOptions { HttpMessageHandler = chained }));
    }

    private sealed class PassThrough(HttpMessageHandler inner) : DelegatingHandler(inner);

    [Fact]
    public async Task AuthorizationServerFailures()
    {
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);

        _server.On("POST", TokenEndpoint, () => Respond.Json(400, "{\"error\":\"invalid_target\",\"error_description\":\"resource is not a known storage\"}"));
        AuthenticationException e = await Assert.ThrowsAsync<AuthenticationException>(() => client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct));
        Assert.Equal("invalid_target", e.Error);
        Assert.Equal("resource is not a known storage", e.ErrorDescription);
        Assert.Equal(400, e.Status);

        _server.On("POST", TokenEndpoint, () => Respond.Json(200, "{\"access_token\":\"x\",\"token_type\":\"DPoP\"}"));
        await Assert.ThrowsAsync<AuthenticationException>(() => client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct));

        _server.On("POST", TokenEndpoint, () => Respond.Text(200, "not json"));
        await Assert.ThrowsAsync<AuthenticationException>(() => client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct));

        using TokenExchangeAuthenticator other = Authenticator();
        using LwsClient otherClient = Client(other);
        _server.On("GET", Metadata, () => Respond.Json(200, MetadataJson("https://not-the-as.example")));
        await Assert.ThrowsAsync<AuthenticationException>(() => otherClient.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct));
        _server.On("GET", Metadata, () => Respond.Status(404));
        Assert.Equal(404, (await Assert.ThrowsAsync<AuthenticationException>(() => otherClient.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct))).Status);
        _server.On("GET", Metadata, () => Respond.Json(200, "{\"issuer\":\"https://as.example\"}"));
        await Assert.ThrowsAsync<AuthenticationException>(() => otherClient.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct));
        _server.On("GET", Metadata, () => Respond.Json(200,
            $"{{\"issuer\":\"{As}/\",\"token_endpoint\":\"{TokenEndpoint}\",\"subject_token_types_supported\":[\"{Lws.TokenType.Saml2}\"]}}"));
        AuthenticationException unsupported = await Assert.ThrowsAsync<AuthenticationException>(() => otherClient.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct));
        Assert.Contains("does not accept", unsupported.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TokensNeverLeaveTheirScopeOnRedirects()
    {
        Protect("GET", Base + "/root/moved", () => Respond.Status(302, ("Location", "https://cdn.example/blob")));
        _server.On("GET", "https://cdn.example/blob", () => Respond.Text(200, "blob"));
        Protect("GET", Base + "/root/renamed", () => Respond.Status(308, ("Location", "/root/a")));
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        Assert.Equal("blob", (await client.ReadAsync(U(Base + "/root/moved"), cancellationToken: Ct)).GetText());
        Assert.Null(_server.RequestsTo("GET", "https://cdn.example/blob").Single().Header("Authorization"));
        Assert.Equal("a", (await client.ReadAsync(U(Base + "/root/renamed"), cancellationToken: Ct)).GetText());
        Assert.Equal("Bearer at-1", _server.Requests[^1].Header("Authorization"));
        Assert.Equal(1, _exchanges);
    }

    [Fact]
    public async Task AnExplicitAuthorizationHeaderSurvivesSameOriginRedirectsOnly()
    {
        using var client = new LwsClient(new LwsClientOptions { HttpMessageHandler = _server });
        _server.On("GET", Base + "/x", () => Respond.Status(301, ("Location", "/y")));
        _server.On("GET", Base + "/y", () => Respond.Status(302, ("Location", "https://other.example/z")));
        _server.On("GET", "https://other.example/z", () => Respond.Text(200, "z"));
        await client.ReadAsync(U(Base + "/x"), new ReadOptions { Headers = new Dictionary<string, string> { ["Authorization"] = "Bearer mine" } }, Ct);
        Assert.Equal(["Bearer mine", "Bearer mine", null], _server.Requests.Select(r => r.Header("Authorization")));
    }

    [Fact]
    public async Task BearerTokenAuthenticatorRestrictsToItsRealm()
    {
        int asked = 0;
        var bearer = new BearerTokenAuthenticator(_ => ValueTask.FromResult<string?>("at-" + Interlocked.Increment(ref asked)), U(Base + "/root/"));
        using LwsClient client = Client(bearer);
        lock (_validTokens) _validTokens.UnionWith(["at-1", "at-2"]);
        _server.On("GET", Base + "/public", () => Respond.Text(200, "p"));
        await client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct);
        await client.ReadAsync(U(Base + "/public"), cancellationToken: Ct);
        Assert.Equal(["Bearer at-1", null], _server.Requests.Select(r => r.Header("Authorization")));
        Assert.Equal(1, asked);
        // A refused bearer token is not retried.
        lock (_validTokens) _validTokens.Clear();
        await Assert.ThrowsAsync<UnauthorizedException>(() => client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct));
        Assert.Equal(0, _exchanges);
        Assert.Equal(Base + "/root/", bearer.Realm?.AbsoluteUri);
    }

    [Fact]
    public async Task SelfSignedCredentialsCacheTokensPerAudience()
    {
        SelfSignedCredentials ed = SelfSignedCredentials.DidKey(SigningKey.GenerateEd25519()).WithTimeProvider(_clock);
        Assert.StartsWith("did:key:z6Mk", ed.Agent, StringComparison.Ordinal);
        Assert.Equal("EdDSA", ed.Algorithm);
        Assert.Equal(DidKey.KeyId(ed.Agent), ed.KeyId);
        var md = AuthorizationServerMetadata.Parse(JsonDocument.Parse(MetadataJson(As)).RootElement, U(Metadata));
        var other = AuthorizationServerMetadata.Parse(JsonDocument.Parse(MetadataJson("https://as2.example", "https://as2.example/t")).RootElement, U(Metadata));
        var context = new CredentialContext(U(As), U(Storage), md);
        string t1 = await ed.GetSubjectTokenAsync(context, Ct);
        Assert.Equal(t1, await ed.GetSubjectTokenAsync(context, Ct));
        string t2 = await ed.GetSubjectTokenAsync(context with { Metadata = other }, Ct);
        Assert.NotEqual(t1, t2);
        Assert.Equal("https://as2.example", Jwt.DecodeClaims(t2).GetProperty("aud")[0].GetString());
        Assert.True(Jwt.Verify(t1, ed.PublicKey));
        Assert.Equal("EdDSA", Jwt.DecodeHeader(t1).GetProperty("alg").GetString());
        _clock.Advance(TimeSpan.FromSeconds(241)); // within 60 s of the 300 s expiry: a new token
        Assert.NotEqual(t1, await ed.GetSubjectTokenAsync(context, Ct));

        SigningKey key = SigningKey.GenerateP256();
        SelfSignedCredentials agent = SelfSignedCredentials.ForAgent(U("https://bot.example/id"), key, "https://bot.example/id#key-1").WithLifetime(TimeSpan.FromSeconds(60));
        string token = agent.CreateToken(As);
        Assert.Equal("https://bot.example/id", Jwt.DecodeClaims(token).GetProperty("sub").GetString());
        Assert.Equal("https://bot.example/id#key-1", Jwt.DecodeHeader(token).GetProperty("kid").GetString());
        JsonElement claims = Jwt.DecodeClaims(token);
        Assert.Equal(60, claims.GetProperty("exp").GetInt64() - claims.GetProperty("iat").GetInt64());
        Assert.False(Jwt.Verify(token, SigningKey.GenerateP256().PublicKey));
        Assert.False(Jwt.Verify(token, ed.PublicKey)); // the header alg must be the key's
    }

    [Fact]
    public void KeyHelpers()
    {
        SigningKey p256 = SigningKey.Generate("ES256");
        SigningKey ed = SigningKey.Generate("EdDSA");
        Assert.Throws<ArgumentException>(() => SigningKey.Generate("RS256"));
        foreach (SigningKey key in new[] { p256, ed })
        {
            SigningKey back = SigningKey.FromJwk(key.ToJwk());
            Assert.Equal(key.PublicKey.ToJwk().ToJsonString(), back.PublicKey.ToJwk().ToJsonString());
            byte[] sig = back.Sign("x"u8);
            Assert.True(key.PublicKey.Verify("x"u8, sig));
            Assert.Equal(key.PublicKey.ToJwk().ToJsonString(), DidKey.ToPublicKey(DidKey.FromPublicKey(key.PublicKey)).ToJwk().ToJsonString());
            Assert.Equal(Jwk.FromSigningKey(key).ToJsonString(), key.ToJwk().ToJsonString());
        }
        Assert.Throws<ArgumentException>(() => SigningKey.FromJwk(Fixtures.Parse("{\"kty\":\"RSA\",\"crv\":\"x\",\"d\":\"AA\"}")));
        Assert.Throws<ArgumentException>(() => VerificationKey.FromJwk(Fixtures.Parse("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AA\",\"y\":\"AA\"}")));
        Assert.Throws<ArgumentException>(() => DidKey.ToPublicKey("did:web:example.org"));
        using var ecdsa = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP384);
        SigningKey p384 = SigningKey.FromECDsa(ecdsa);
        Assert.Equal("ES384", p384.Algorithm);
        Assert.Equal(96, p384.Sign("x"u8).Length);
        Assert.Throws<ArgumentException>(() => DidKey.FromPublicKey(p384.PublicKey));

        var cid = ControlledIdentifierDocument.Create("https://bot.example/id", ed.PublicKey, "key-1");
        Assert.Equal("https://bot.example/id", cid["id"]!.GetValue<string>());
        var method = cid["authentication"]![0]!;
        Assert.Equal("https://bot.example/id#key-1", method["id"]!.GetValue<string>());
        Assert.Equal("JsonWebKey", method["type"]!.GetValue<string>());
        Assert.Equal("EdDSA", method["publicKeyJwk"]!["alg"]!.GetValue<string>());
        Assert.Equal("key-1", method["publicKeyJwk"]!["kid"]!.GetValue<string>());
        Assert.Null(ControlledIdentifierDocument.Create("https://bot.example/id", Fixtures.ToElement(p256.ToJwk()), "did:x#k")["authentication"]![0]!["publicKeyJwk"]!["d"]);
        Assert.Equal(Lws.CidContext, cid["@context"]![0]!.GetValue<string>());
    }
}
