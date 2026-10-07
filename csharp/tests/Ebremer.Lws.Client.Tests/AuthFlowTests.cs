// SPDX-License-Identifier: MIT
using System.Text.Json;
using Ebremer.Lws.Auth;
using Ebremer.Lws.Tests.Support;

namespace Ebremer.Lws.Tests;

/// <summary>
/// The LWS authorization flow (<c>401 → metadata → token exchange → retry</c>) and its security checks, against a
/// fake storage protected by a fake authorization server.
/// </summary>
public sealed class AuthFlowTests : IDisposable
{
    private const string Base = "https://storage.example";
    private const string Realm = Base + "/";
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

    private static HttpResponseMessage Challenge(string asUri = As, string realm = Realm, string error = "invalid_token") =>
        Respond.Status(401, ("WWW-Authenticate", $"Bearer as_uri=\"{asUri}\", realm=\"{realm}\", error=\"{error}\""));

    private bool Authorized(Recorded r)
    {
        if (r.Header("Authorization") is not { } a || !a.StartsWith("Bearer ", StringComparison.Ordinal)) return false;
        lock (_validTokens) return _validTokens.Contains(a[7..]);
    }

    private void Protect(string method, string url, Func<HttpResponseMessage> ok) =>
        _server.On(method, url, r => Authorized(r) ? ok() : Challenge());

    private TokenExchangeAuthenticator Authenticator(ICredentialProvider? credentials = null, TokenExchangeOptions? options = null) =>
        new(credentials ?? new OpenIdCredentials("id-token"), (options ?? new TokenExchangeOptions()) with { HttpMessageHandler = _server, TimeProvider = _clock });

    private LwsClient Client(IAuthenticator authenticator) => new(new LwsClientOptions { HttpMessageHandler = _server, Authenticator = authenticator });

    private IEnumerable<string> Trace() => _server.Requests.Select(r => $"{r.Method} {r.Url}");

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
            [$"GET {Base}/root/a", $"GET {Metadata}", $"POST {TokenEndpoint}", $"GET {Base}/root/a"],
            Trace());
        Recorded exchange = _server.RequestsTo("POST", TokenEndpoint).Single();
        Assert.Equal("application/x-www-form-urlencoded", exchange.Header("Content-Type"));
        Dictionary<string, string> form = exchange.Text.Split('&').Select(p => p.Split('=', 2))
            .ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1].Replace('+', ' ')));
        Assert.Equal(Lws.GrantTypeTokenExchange, form["grant_type"]);
        Assert.Equal(Realm, form["resource"]);
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
    public async Task ProactiveReuseInsideTheRealmOnly()
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
        Assert.Equal("at-1", (await auth.GetAccessTokenAsync(As, Realm, Ct)).Value);
    }

    [Fact]
    public async Task OpenIdAndSamlSubjectTokens()
    {
        using (TokenExchangeAuthenticator oidc = Authenticator(new OpenIdCredentials((ctx, _) =>
               {
                   Assert.Equal(As, ctx.Metadata.Issuer);
                   Assert.Equal(Realm, ctx.Realm.AbsoluteUri);
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
    public async Task PostIsRetriedOnceAfterA401Only()
    {
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        CreateResult created = await client.CreateTextAsync(U(Base + "/root/"), "hello", cancellationToken: Ct);
        Assert.Equal(Base + "/root/new", created.Location.AbsoluteUri);
        Assert.Equal([null, "Bearer at-1"], _server.RequestsTo("POST", Base + "/root/").Select(r => r.Header("Authorization")));
        Assert.All(_server.RequestsTo("POST", Base + "/root/"), r => Assert.Equal("hello", r.Text));

        // A server that keeps refusing: exactly one retry, then UnauthorizedException.
        _server.On("POST", Base + "/root/stubborn/", _ => Challenge());
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
            [$"HEAD {Base}/root/", $"GET {Metadata}", $"POST {TokenEndpoint}", $"HEAD {Base}/root/", $"POST {Base}/root/"],
            Trace());
        Recorded post = _server.RequestsTo("POST", Base + "/root/").Single();
        Assert.Equal("Bearer at-1", post.Header("Authorization"));
        Assert.Equal("streamed", post.Text);
    }

    [Fact]
    public async Task AChallengeWithoutAnAuthorizationServerIsUnauthorized()
    {
        _server.On("GET", Base + "/basic", () => Respond.Status(401, ("WWW-Authenticate", "Basic realm=\"x\"")));
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        UnauthorizedException e = await Assert.ThrowsAsync<UnauthorizedException>(() => client.ReadAsync(U(Base + "/basic"), cancellationToken: Ct));
        Assert.True(e.Challenges.Single().IsScheme("basic"));
        Assert.Equal(0, _exchanges);
    }

    // ------------------------------------------------------------------------------------------------ the checks

    [Fact]
    public async Task TheRealmMustContainTheRequestUrl()
    {
        _server.On("GET", Base + "/root/other", _ => Challenge(realm: Base + "/other/"));
        _server.On("GET", Base + "/storage_10/x", _ => Challenge(realm: Base + "/storage_1"));
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        await Assert.ThrowsAsync<AuthenticationException>(() => client.ReadAsync(U(Base + "/root/other"), cancellationToken: Ct));
        await Assert.ThrowsAsync<AuthenticationException>(() => client.ReadAsync(U(Base + "/storage_10/x"), cancellationToken: Ct));
        Assert.Empty(_server.RequestsTo("GET", Metadata));
        Assert.Equal(0, _exchanges);
    }

    [Fact]
    public async Task ADecoyChallengeLeavesTheCachedTokenInUse()
    {
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        await client.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct);
        Assert.Equal(1, _exchanges);

        // The storage answers a request that carried the cached token with challenges that must all be refused: a
        // realm that does not contain the URL, an insecure authorization server, one the filter rejects.
        string[] decoys =
        [
            $"Bearer as_uri=\"{As}\", realm=\"https://evil.example/\"",
            $"Bearer as_uri=\"http://as.evil.example\", realm=\"{Realm}\"",
        ];
        foreach (string decoy in decoys)
        {
            _server.On("GET", Base + "/root/decoy", () => Respond.Status(401, ("WWW-Authenticate", decoy)));
            await Assert.ThrowsAsync<AuthenticationException>(() => client.ReadAsync(U(Base + "/root/decoy"), cancellationToken: Ct));
            Assert.Equal("Bearer at-1", _server.RequestsTo("GET", Base + "/root/decoy").Last().Header("Authorization"));
            int before = _server.Requests.Count;
            await client.ReadAsync(U(Base + "/root/b"), cancellationToken: Ct);
            Assert.Equal("Bearer at-1", _server.Requests[before].Header("Authorization"));
            Assert.Equal(before + 1, _server.Requests.Count);
        }

        using TokenExchangeAuthenticator filtered = Authenticator(options: new TokenExchangeOptions
        {
            AuthorizationServerFilter = (asUri, _) => asUri.Host == "as.example",
        });
        using LwsClient filteredClient = Client(filtered);
        await filteredClient.ReadAsync(U(Base + "/root/a"), cancellationToken: Ct);
        _server.On("GET", Base + "/root/decoy", () => Challenge(asUri: "https://as.attacker.example"));
        await Assert.ThrowsAsync<AuthenticationException>(() => filteredClient.ReadAsync(U(Base + "/root/decoy"), cancellationToken: Ct));
        await filteredClient.ReadAsync(U(Base + "/root/b"), cancellationToken: Ct);
        Assert.Equal("Bearer at-2", _server.Requests[^1].Header("Authorization"));
        Assert.DoesNotContain(_server.Requests, r => r.Uri.Host.Contains("attacker", StringComparison.Ordinal) || r.Uri.Host.Contains("evil", StringComparison.Ordinal));
        Assert.Equal(2, _exchanges);
    }

    [Fact]
    public async Task InsecureAuthorizationServersAreRefusedUnlessAllowed()
    {
        const string insecure = "http://as.example";
        _server.On("GET", Base + "/root/c", r => Authorized(r) ? Respond.Text(200, "c") : Challenge(asUri: insecure));
        _server.On("GET", insecure + "/.well-known/lws-configuration", () => Respond.Json(200, MetadataJson(insecure, insecure + "/token")));
        _server.On("POST", insecure + "/token", () => Respond.Json(200, "{\"access_token\":\"at-1\",\"token_type\":\"bearer\"}"));
        lock (_validTokens) _validTokens.Add("at-1");
        using (TokenExchangeAuthenticator strict = Authenticator())
        using (LwsClient client = Client(strict))
        {
            AuthenticationException e = await Assert.ThrowsAsync<AuthenticationException>(() => client.ReadAsync(U(Base + "/root/c"), cancellationToken: Ct));
            Assert.Contains("HTTPS", e.Message, StringComparison.Ordinal);
            Assert.Null(e.Status);
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
        _server.On("GET", "http://localhost:8787/root/x", r => Authorized(r) ? Respond.Text(200, "x") : Challenge(local, local + "/"));
        _server.On("GET", local + "/.well-known/lws-configuration", () => Respond.Json(200, MetadataJson(local, local + "/oauth/token")));
        _server.On("POST", local + "/oauth/token", () => Respond.Json(200, "{\"access_token\":\"at-local\",\"token_type\":\"Bearer\"}"));
        lock (_validTokens) _validTokens.Add("at-local");
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);
        Assert.Equal("x", (await client.ReadAsync(U("http://localhost:8787/root/x"), cancellationToken: Ct)).GetText());
        Assert.Contains("resource=" + Uri.EscapeDataString(local + "/"), _server.RequestsTo("POST", local + "/oauth/token").Single().Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MetadataAndTokenRequestsNeverFollowRedirects()
    {
        using TokenExchangeAuthenticator auth = Authenticator();
        using LwsClient client = Client(auth);

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
    public async Task TokensNeverLeaveTheirRealmOnRedirects()
    {
        _server.On("GET", Base + "/root/moved", r => Authorized(r) ? Respond.Status(302, ("Location", "https://cdn.example/blob")) : Challenge());
        _server.On("GET", "https://cdn.example/blob", () => Respond.Text(200, "blob"));
        _server.On("GET", Base + "/root/renamed", r => Authorized(r) ? Respond.Status(308, ("Location", "/root/a")) : Challenge());
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
        var context = new CredentialContext(U(As), U(Realm), md);
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
