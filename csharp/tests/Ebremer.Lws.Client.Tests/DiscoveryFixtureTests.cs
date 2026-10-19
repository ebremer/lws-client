// SPDX-License-Identifier: MIT
using System.Text;
using System.Text.Json;
using Ebremer.Lws.Auth;
using Ebremer.Lws.Tests.Support;

namespace Ebremer.Lws.Tests;

/// <summary>
/// The authorization flow after a <c>401</c> (<c>conformance/fixtures/discovery.json</c>): every case through a
/// <see cref="TokenExchangeAuthenticator"/> with default options, against an in-process fake server that answers as the
/// fixture describes.
/// </summary>
public sealed class DiscoveryFixtureTests
{
    private const string Token = "token-1";

    public static TheoryData<string> Cases() => [.. Fixtures.Load("discovery.json").Arr("cases").Select(c => c.Str("name"))];

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Discovery(string name)
    {
        JsonElement fixture = Fixtures.Load("discovery.json");
        JsonElement c = fixture.Arr("cases").Single(x => x.Str("name") == name);
        // {A} and {B}: two https origins, and the two loopback origins one real server would have.
        await RunAsync(fixture, c, "https://storage.example", "https://other.example");
        await RunAsync(fixture, c, "http://127.0.0.1:8787", "http://localhost:8787");
    }

    private static async Task RunAsync(JsonElement fixture, JsonElement c, string a, string b)
    {
        string Fill(string s) => s.Replace("{A}", a, StringComparison.Ordinal).Replace("{B}", b, StringComparison.Ordinal);

        var server = new FakeServer();
        string request = Fill(c.Str("request"));
        (string, string)[] challenge = [.. c.GetProperty("challenge").EnumerateObject().Select(h => (h.Name, Fill(h.Value.GetString()!)))];
        server.On("GET", request, r => r.Header("Authorization") == "Bearer " + Token ? Respond.Text(200, "ok") : Respond.Status(401, challenge));
        foreach (JsonProperty document in c.GetProperty("documents").EnumerateObject())
        {
            int status = document.Value.GetProperty("status").GetInt32();
            JsonElement headers = document.Value.GetProperty("headers");
            string? contentType = headers.OptStr("content-type");
            (string, string)[] others = [.. headers.EnumerateObject().Where(h => h.Name != "content-type").Select(h => (h.Name, Fill(h.Value.GetString()!)))];
            JsonElement body = document.Value.GetProperty("body");
            byte[]? bytes = body.ValueKind == JsonValueKind.Null ? null : Encoding.UTF8.GetBytes(Fill(body.GetRawText()));
            server.On("GET", Fill(document.Name), () => Respond.Make(status, bytes, contentType, others));
        }
        server.On("POST", a + "/as/token", () => Respond.Json(200, fixture.GetProperty("tokenResponse").GetRawText()));

        using var authenticator = new TokenExchangeAuthenticator(new OpenIdCredentials("id-token"), new TokenExchangeOptions { HttpMessageHandler = server });
        using var client = new LwsClient(new LwsClientOptions { HttpMessageHandler = server, Authenticator = authenticator });
        JsonElement expected = c.GetProperty("expected");
        string outcome = expected.Str("outcome");
        Task<Resource> read = client.ReadAsync(new Uri(request), cancellationToken: Ct);
        switch (outcome)
        {
            case "ok":
                Assert.Equal("ok", (await read).GetText());
                Assert.Equal([null, "Bearer " + Token], server.RequestsTo("GET", request).Select(r => r.Header("Authorization")));
                break;
            case "AuthenticationError":
                await Assert.ThrowsAsync<AuthenticationException>(() => read);
                break;
            case "UnauthorizedError":
                await Assert.ThrowsAsync<UnauthorizedException>(() => read);
                break;
            default:
                Assert.Fail($"Unknown outcome {outcome}");
                break;
        }

        List<Recorded> tokenRequests = [.. server.Requests.Where(r => r.Method == "POST")];
        if (expected.GetProperty("tokenRequest") is { ValueKind: JsonValueKind.Object } tokenRequest)
        {
            Recorded post = Assert.Single(tokenRequests);
            Assert.Equal(new Uri(Fill(tokenRequest.Str("endpoint"))).AbsoluteUri, post.Url);
            Assert.Equal(Fill(tokenRequest.Str("resource")), Form(post)["resource"]);
        }
        else
        {
            Assert.Empty(tokenRequests);
        }
        foreach (string url in expected.Strings("notFetched").Select(u => new Uri(Fill(u)).AbsoluteUri))
        {
            Assert.DoesNotContain(server.Requests, r => r.Url == url);
        }

        if (!expected.TryGetProperty("then", out JsonElement then)) return;
        foreach (JsonElement next in then.EnumerateArray())
        {
            string url = Fill(next.Str("request"));
            server.On("GET", url, () => Respond.Text(200, "ok"));
            int before = server.Requests.Count;
            Assert.Equal("ok", (await client.ReadAsync(new Uri(url), cancellationToken: Ct)).GetText());
            Recorded sent = Assert.Single(server.Requests.Skip(before));
            Assert.Equal(next.GetProperty("sendsToken").GetBoolean() ? "Bearer " + Token : null, sent.Header("Authorization"));
        }
    }

    private static Dictionary<string, string> Form(Recorded post) =>
        post.Text.Split('&').Select(p => p.Split('=', 2))
            .ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1].Replace('+', ' ')));
}
