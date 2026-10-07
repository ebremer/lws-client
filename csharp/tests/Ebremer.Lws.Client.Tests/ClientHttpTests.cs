// SPDX-License-Identifier: MIT
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ebremer.Lws.Access;
using Ebremer.Lws.Http;
using Ebremer.Lws.Notifications;
using Ebremer.Lws.Tests.Support;

namespace Ebremer.Lws.Tests;

/// <summary>Every operation against an in-process fake server: the requests sent and the results parsed.</summary>
public sealed class ClientHttpTests : IDisposable
{
    private const string Base = "https://storage.example";
    private const string Root = Base + "/root/";
    private readonly FakeServer _server = new();
    private readonly LwsClient _client;

    public ClientHttpTests() => _client = new LwsClient(new LwsClientOptions { HttpMessageHandler = _server });

    public void Dispose() => _client.Dispose();

    private static Uri U(string url) => new(url);

    private static string StorageDescriptionJson =>
        Fixtures.Load("responses/storage-description.json").GetProperty("body").GetRawText();

    private static (string, string)[] DataLinks(string url, string parent) =>
    [
        ("Link", $"<{url}.meta>; rel=\"linkset\"; type=\"application/linkset+json\""),
        ("Link", $"<{parent}>; rel=\"up\""),
        ("Link", "<https://www.w3.org/ns/lws#DataResource>; rel=\"type\""),
        ("Link", "</>; rel=\"https://www.w3.org/ns/lws#storage\""),
    ];

    private static string Page(string id, params string[] itemIds) =>
        new JsonObject
        {
            ["@context"] = "https://www.w3.org/ns/lws/v1",
            ["id"] = id,
            ["type"] = "Container",
            ["totalItems"] = 7,
            ["items"] = new JsonArray([.. itemIds.Select(i => (JsonNode)new JsonObject { ["id"] = i, ["type"] = "DataResource", ["format"] = "text/plain" })]),
        }.ToJsonString();

    // ------------------------------------------------------------------------------------------------ discovery

    [Fact]
    public async Task DiscoverStorageFollowsTheStorageLink()
    {
        _server.On("HEAD", Root, () => Respond.Status(200, ("Link", "</>; rel=\"https://www.w3.org/ns/lws#storage\"")));
        _server.On("GET", Base + "/", () => Respond.Json(200, StorageDescriptionJson, "application/lws+cid"));
        StorageDescription s = await _client.DiscoverStorageAsync(U(Root), cancellationToken: Ct);
        Assert.Equal(Base + "/", s.Id.AbsoluteUri);
        Assert.Equal(Root, s.GetStorageRoot().AbsoluteUri);
        Recorded get = _server.RequestsTo("GET", Base + "/").Single();
        Assert.Equal("application/lws+cid, application/ld+json;q=0.9, application/json;q=0.8", get.Header("Accept"));
        Assert.Equal(LwsClient.DefaultUserAgent, get.Header("User-Agent"));
    }

    [Fact]
    public async Task DiscoverStorageFallsBackToGetAndAcceptsAnAnonymous401()
    {
        _server.On("HEAD", Root, () => Respond.Status(405, ("Allow", "GET")));
        _server.On("GET", Root, () => Respond.Status(401, ("WWW-Authenticate", "Bearer realm=\"x\""), ("Link", "</>; rel=\"https://www.w3.org/ns/lws#storage\"")));
        _server.On("GET", Base + "/", () => Respond.Json(200, StorageDescriptionJson, "application/ld+json"));
        StorageDescription s = await _client.DiscoverStorageAsync(U(Root), cancellationToken: Ct);
        Assert.Equal(Base + "/", s.Id.AbsoluteUri);
        Assert.Equal(["HEAD", "GET", "GET"], _server.Requests.Select(r => r.Method));
    }

    [Fact]
    public async Task DiscoverStorageFailures()
    {
        _server.On("HEAD", Root, () => Respond.Status(200));
        await Assert.ThrowsAsync<ProtocolException>(() => _client.DiscoverStorageAsync(U(Root), cancellationToken: Ct));
        _server.On("HEAD", Root, () => Respond.Status(403));
        await Assert.ThrowsAsync<ForbiddenException>(() => _client.DiscoverStorageAsync(U(Root), cancellationToken: Ct));
        _server.On("GET", Base + "/", () => Respond.Text(200, "<html/>", "text/html"));
        await Assert.ThrowsAsync<ProtocolException>(() => _client.GetStorageDescriptionAsync(U(Base + "/"), cancellationToken: Ct));
        _server.On("GET", Base + "/", () => Respond.Json(200, "{\"id\":\"/\",\"type\":\"Thing\"}"));
        await Assert.ThrowsAsync<ProtocolException>(() => _client.GetStorageDescriptionAsync(U(Base + "/"), cancellationToken: Ct));
        _server.On("GET", Base + "/", () => Respond.Json(200, "{not json"));
        await Assert.ThrowsAsync<ProtocolException>(() => _client.GetStorageDescriptionAsync(U(Base + "/"), cancellationToken: Ct));
    }

    // ------------------------------------------------------------------------------------------------ reading

    [Fact]
    public async Task HeadParsesTheMetadata()
    {
        string url = Root + "notes/a.txt";
        _server.On("HEAD", url, () => Respond.Make(200, null, "text/plain; charset=utf-8",
        [
            ("ETag", "W/\"v1\""), ("Last-Modified", "Tue, 06 Oct 2026 12:00:00 GMT"), ("Content-Length", "11"),
            ("Allow", "GET, HEAD, PUT"), ("Allow", "DELETE"), ("Accept-Patch", "application/json-patch+json"),
            .. DataLinks(url, Root + "notes/"),
        ]));
        ResourceMetadata m = await _client.HeadAsync(U(url), cancellationToken: Ct);
        Assert.Equal(url, m.Url.AbsoluteUri);
        Assert.Equal(200, m.Status);
        Assert.Equal("W/\"v1\"", m.ETag);
        Assert.Equal(new DateTimeOffset(2026, 10, 6, 12, 0, 0, TimeSpan.Zero), m.LastModified);
        Assert.Equal("Tue, 06 Oct 2026 12:00:00 GMT", m.LastModifiedRaw);
        Assert.Equal("text/plain; charset=utf-8", m.ContentType);
        Assert.Equal(11, m.ContentLength);
        Assert.Equal(url + ".meta", m.Linkset?.AbsoluteUri);
        Assert.Equal(Root + "notes/", m.Parent?.AbsoluteUri);
        Assert.Equal(Base + "/", m.Storage?.AbsoluteUri);
        Assert.Equal([Lws.Types.DataResource], m.Types);
        Assert.True(m.IsDataResource);
        Assert.False(m.IsContainer);
        Assert.Equal(["GET", "HEAD", "PUT", "DELETE"], m.Allow);
        Assert.Equal(["application/json-patch+json"], m.AcceptPatch);
        Assert.Equal(4, m.Links.Count);
        Assert.Equal("application/linkset+json", m.GetLink("linkset")?.Type);
        Assert.Single(m.GetLinks("up"));
    }

    [Fact]
    public async Task ReadSendsTheOptionsAndDecodesTheCharset()
    {
        string url = Root + "latin1.txt";
        _server.On("GET", url, () => Respond.Make(200, Encoding.Latin1.GetBytes("café"), "text/plain; charset=ISO-8859-1", ("ETag", "\"1\"")));
        Resource r = await _client.ReadAsync(U(url), new ReadOptions
        {
            Accept = "text/plain",
            Range = new RangeHeaderValue(0, 99),
            IfNoneMatch = "\"0\"",
            IfModifiedSince = new DateTimeOffset(2026, 10, 1, 8, 0, 0, TimeSpan.Zero),
            Prefer = "return=minimal",
            Headers = new Dictionary<string, string> { ["X-Trace"] = "abc" },
        }, Ct);
        Assert.Equal("café", r.GetText());
        Assert.False(r.NotModified);
        Assert.Equal("\"1\"", r.ETag);
        Recorded req = _server.Requests.Single();
        Assert.Equal("text/plain", req.Header("Accept"));
        Assert.Equal("bytes=0-99", req.Header("Range"));
        Assert.Equal("\"0\"", req.Header("If-None-Match"));
        Assert.Equal("Thu, 01 Oct 2026 08:00:00 GMT", req.Header("If-Modified-Since"));
        Assert.Equal("return=minimal", req.Header("Prefer"));
        Assert.Equal("abc", req.Header("X-Trace"));
    }

    [Fact]
    public async Task ConditionalAndPartialReads()
    {
        string url = Root + "a.json";
        _server.On("GET", url, r => r.Header("If-None-Match") == "\"7\""
            ? Respond.Status(304, ("ETag", "\"7\""))
            : r.Header("Range") is not null
                ? Respond.Text(206, "{\"a\"", "application/json", ("Content-Range", "bytes 0-3/9"))
                : Respond.Json(200, "{\"a\":[1]}", "application/json", ("ETag", "\"7\"")));
        Resource full = await _client.ReadAsync(U(url), cancellationToken: Ct);
        Assert.Equal(1, full.GetJson().GetProperty("a")[0].GetInt32());
        Assert.Equal([1], full.GetJson<Dictionary<string, int[]>>()!["a"]);
        Resource notModified = await _client.ReadAsync(U(url), new ReadOptions { IfNoneMatch = full.ETag }, Ct);
        Assert.True(notModified.NotModified);
        Assert.Equal(304, notModified.Status);
        Assert.True(notModified.Body.IsEmpty);
        Resource partial = await _client.ReadAsync(U(url), new ReadOptions { Range = new RangeHeaderValue(0, 3) }, Ct);
        Assert.Equal(206, partial.Status);
        Assert.Equal("bytes 0-3/9", partial.ContentRange);
        Assert.Equal("{\"a\"", partial.GetText());
        Assert.Throws<ProtocolException>(() => partial.GetJson());
    }

    [Fact]
    public async Task ReadStreamStreamsAndMapsErrors()
    {
        _server.On("GET", Root + "big.bin", () => Respond.Make(200, [1, 2, 3, 4], "application/octet-stream"));
        _server.On("GET", Root + "missing", () => Respond.Text(404, "nope"));
        _server.On("GET", Root + "same", () => Respond.Status(304));
        await using (ResourceStream s = await _client.ReadStreamAsync(U(Root + "big.bin"), cancellationToken: Ct))
        {
            using var buffer = new MemoryStream();
            await s.Content.CopyToAsync(buffer, Ct);
            Assert.Equal([1, 2, 3, 4], buffer.ToArray());
            Assert.Equal("application/octet-stream", s.Metadata.ContentType);
        }
        NotFoundException e = await Assert.ThrowsAsync<NotFoundException>(() => _client.ReadStreamAsync(U(Root + "missing"), cancellationToken: Ct));
        Assert.Equal("nope", e.Body);
        using ResourceStream same = await _client.ReadStreamAsync(U(Root + "same"), new ReadOptions { IfNoneMatch = "\"1\"" }, Ct);
        Assert.True(same.NotModified);
    }

    [Fact]
    public async Task ReadContainerChecksTheRepresentation()
    {
        _server.On("GET", Root, () => Respond.Json(200, Page("/root/", "/root/a", "b"), "application/lws+json", ("ETag", "\"c1\"")));
        ContainerPage page = await _client.ReadContainerAsync(U(Root), cancellationToken: Ct);
        Assert.Equal(Root, page.Id.AbsoluteUri);
        Assert.Equal([Root + "a", Root + "b"], page.Items.Select(i => i.Id.AbsoluteUri));
        Assert.Equal(7, page.TotalItems);
        Assert.Equal("\"c1\"", page.ETag);
        Assert.Equal("application/lws+json", _server.Requests.Single().Header("Accept"));

        _server.On("GET", Root, () => Respond.Text(200, "<html/>", "text/html"));
        await Assert.ThrowsAsync<ProtocolException>(() => _client.ReadContainerAsync(U(Root), cancellationToken: Ct));
        _server.On("GET", Root, () => Respond.Json(200, "{\"id\":\"/root/\",\"type\":\"DataResource\"}", "application/ld+json"));
        await Assert.ThrowsAsync<ProtocolException>(() => _client.ReadContainerAsync(U(Root), cancellationToken: Ct));
        // A container identified by its rel="type" link and served as application/json is fine.
        _server.On("GET", Root, () => Respond.Json(200, "{\"items\":[]}", "application/json; charset=utf-8",
            ("Link", "<https://www.w3.org/ns/lws#Container>; rel=\"type\"")));
        Assert.True((await _client.ReadContainerAsync(U(Root), cancellationToken: Ct)).IsContainer);
    }

    [Fact]
    public async Task ListContainerFollowsThreePagesLazily()
    {
        _server.On("GET", Root, () => Respond.Json(200, Page("/root/", "a", "b"), "application/lws+json", ("Link", "</root/?page=2>; rel=\"next\"")));
        _server.On("GET", Root + "?page=2", () => Respond.Json(200, Page("/root/", "c", "d"), "application/lws+json", ("Link", "<?page=3>; rel=\"next\"")));
        _server.On("GET", Root + "?page=3", () => Respond.Json(200, Page("/root/", "e"), "application/lws+json", ("Link", "</root/>; rel=\"first\"")));
        IAsyncEnumerable<ContainedResource> all = _client.ListContainerAsync(U(Root), cancellationToken: Ct);
        Assert.Empty(_server.Requests);
        var ids = new List<string>();
        await foreach (ContainedResource item in all) ids.Add(item.Id.AbsoluteUri);
        Assert.Equal(["a", "b", "c", "d", "e"], ids.Select(i => i[Root.Length..]));
        Assert.Equal([Root, Root + "?page=2", Root + "?page=3"], _server.Requests.Select(r => r.Url));

        // Pulling only two items reads only the first page.
        int before = _server.Requests.Count;
        await foreach (ContainedResource item in _client.ListContainerAsync(U(Root), cancellationToken: Ct).Take(2)) Assert.NotNull(item);
        Assert.Equal(before + 1, _server.Requests.Count);
    }

    [Fact]
    public async Task ListContainerStopsOnALoop()
    {
        _server.On("GET", Root, () => Respond.Json(200, Page("/root/", "a"), "application/lws+json", ("Link", "</root/?page=2>; rel=\"next\"")));
        _server.On("GET", Root + "?page=2", () => Respond.Json(200, Page("/root/", "b"), "application/lws+json", ("Link", "</root/>; rel=\"next\"")));
        Assert.Equal(2, await _client.ListContainerAsync(U(Root), cancellationToken: Ct).CountAsync(Ct));
    }

    // ------------------------------------------------------------------------------------------------ creating

    [Fact]
    public async Task CreateSendsSlugTypesAndLinks()
    {
        _server.On("POST", Root, () => Respond.Status(201, ("Location", "/root/caf%C3%A9.txt"), ("ETag", "\"1\""),
            ("Link", "</root/caf%C3%A9.txt.meta>; rel=\"linkset\"")));
        CreateResult r = await _client.CreateTextAsync(U(Root), "Hello, LWS!", options: new CreateOptions
        {
            Slug = "café 100%.txt",
            Types = ["https://schema.org/Note"],
            Links = [new Link(U("https://example.org/shape"), "describedby")],
        }, cancellationToken: Ct);
        Assert.Equal(Root + "caf%C3%A9.txt", r.Location.AbsoluteUri);
        Assert.Equal("\"1\"", r.ETag);
        Assert.Equal(Root + "caf%C3%A9.txt.meta", r.Linkset?.AbsoluteUri);
        Recorded req = _server.Requests.Single();
        Assert.Equal("text/plain", req.Header("Content-Type"));
        Assert.Equal("Hello, LWS!", req.Text);
        Assert.Equal("caf%C3%A9 100%25.txt", req.Header("Slug"));
        Assert.Equal(["<https://schema.org/Note>; rel=\"type\"", "<https://example.org/shape>; rel=\"describedby\""], LinkValues(req));
    }

    private static IEnumerable<string> LinkValues(Recorded req) =>
        req.HeaderValues("Link").SelectMany(v => LinkHeader.Parse(v, null)).Select(l => l.ToHeaderValue());

    [Fact]
    public async Task CreateJsonAndBinary()
    {
        _server.On("POST", Root, () => Respond.Status(201, ("Location", Root + "x")));
        await _client.CreateJsonAsync(U(Root), new { name = "Alice", age = 30 }, cancellationToken: Ct);
        Assert.Equal("application/json", _server.Requests[^1].Header("Content-Type"));
        Assert.Equal("{\"name\":\"Alice\",\"age\":30}", _server.Requests[^1].Text);
        await _client.CreateJsonAsync(U(Root), new JsonObject { ["done"] = false }, cancellationToken: Ct);
        Assert.Equal("{\"done\":false}", _server.Requests[^1].Text);
        await _client.CreateAsync(U(Root), new byte[] { 0, 1, 250 }, "application/octet-stream", cancellationToken: Ct);
        Assert.Equal([0, 1, 250], _server.Requests[^1].Body);
        await _client.CreateAsync(U(Root), new MemoryStream([9, 8]), "application/octet-stream", cancellationToken: Ct);
        Assert.Equal([9, 8], _server.Requests[^1].Body);
    }

    [Fact]
    public async Task CreateContainerAndMissingLocation()
    {
        _server.On("POST", Root, () => Respond.Status(201, ("Location", "notes/")));
        CreateResult r = await _client.CreateContainerAsync(U(Root), new CreateOptions { Slug = "notes" }, Ct);
        Assert.Equal(Root + "notes/", r.Location.AbsoluteUri);
        Recorded req = _server.Requests.Single();
        Assert.Equal(["<https://www.w3.org/ns/lws#Container>; rel=\"type\""], LinkValues(req));
        Assert.Equal("0", req.Header("Content-Length"));
        Assert.Empty(req.Body);
        _server.On("POST", Root, () => Respond.Status(201));
        await Assert.ThrowsAsync<ProtocolException>(() => _client.CreateContainerAsync(U(Root), cancellationToken: Ct));
    }

    // ------------------------------------------------------------------------------------------------ updating

    [Fact]
    public async Task UpdateIsConditional()
    {
        string url = Root + "a.txt";
        _server.On("PUT", url, r => r.Header("If-Match") == "\"1\"" ? Respond.Status(204, ("ETag", "\"2\"")) : Respond.Json(412, "{\"title\":\"stale\"}", "application/problem+json"));
        UpdateResult ok = await _client.UpdateAsync(U(url), "Hello again"u8.ToArray(), "text/plain", new UpdateOptions { IfMatch = "\"1\"" }, Ct);
        Assert.Equal(204, ok.Status);
        Assert.Equal("\"2\"", ok.ETag);
        PreconditionFailedException e = await Assert.ThrowsAsync<PreconditionFailedException>(() =>
            _client.UpdateAsync(U(url), "x"u8.ToArray(), "text/plain", new UpdateOptions { IfMatch = "\"0\"" }, Ct));
        Assert.Equal(412, e.Status);
        Assert.Equal("stale", e.Problem?.Title);
        Assert.Equal("PUT", e.Method);
        Assert.Equal(url, e.Uri.AbsoluteUri);
    }

    [Fact]
    public async Task UpdateWithLinksetAndIfNoneMatch()
    {
        string url = Root + "b.txt";
        _server.On("PUT", url, () => Respond.Status(201));
        await _client.UpdateAsync(U(url), new MemoryStream("data"u8.ToArray()), "text/plain", new UpdateOptions
        {
            IfNoneMatch = "*",
            SetLinkset = true,
            Links = [new Link(U("https://example.org/l"), "license")],
        }, Ct);
        Recorded req = _server.Requests.Single();
        Assert.Equal("*", req.Header("If-None-Match"));
        Assert.Equal("set-linkset", req.Header("Prefer"));
        Assert.Equal(["<https://example.org/l>; rel=\"license\""], LinkValues(req));
        Assert.Equal("data", req.Text);
    }

    [Fact]
    public async Task PatchSendsJsonPatchOrARawFormat()
    {
        string url = Root + "p.json";
        _server.On("PATCH", url, r => r.Header("Content-Type") == "application/json-patch+json"
            ? Respond.Status(204, ("ETag", "\"3\""))
            : Respond.Status(415, ("Accept-Patch", "application/json-patch+json, application/merge-patch+json")));
        UpdateResult r = await _client.PatchAsync(U(url), new JsonPatch().Replace("/age", 31).Add("/city", "Boston"), new UpdateOptions { IfMatch = "\"2\"" }, Ct);
        Assert.Equal("\"3\"", r.ETag);
        Recorded req = _server.Requests.Single();
        Assert.Equal("[{\"op\":\"replace\",\"path\":\"/age\",\"value\":31},{\"op\":\"add\",\"path\":\"/city\",\"value\":\"Boston\"}]", req.Text);
        Assert.Equal("\"2\"", req.Header("If-Match"));
        UnsupportedMediaTypeException e = await Assert.ThrowsAsync<UnsupportedMediaTypeException>(() =>
            _client.PatchAsync(U(url), "INSERT DATA {}"u8.ToArray(), "application/sparql-update", cancellationToken: Ct));
        Assert.Equal(["application/json-patch+json", "application/merge-patch+json"], e.AcceptPatch);
        Assert.Equal("application/sparql-update", _server.Requests[^1].Header("Content-Type"));
    }

    [Fact]
    public async Task DeleteRecursiveAndConflict()
    {
        _server.On("DELETE", Root + "c/", r => r.Header("Depth") == "infinity"
            ? Respond.Status(204)
            : Respond.Json(409, Fixtures.Load("responses/problem-details.json").GetProperty("body").GetRawText(), "application/problem+json"));
        ConflictException e = await Assert.ThrowsAsync<ConflictException>(() => _client.DeleteAsync(U(Root + "c/"), cancellationToken: Ct));
        Assert.Equal("Container not empty", e.Problem?.Title);
        await _client.DeleteAsync(U(Root + "c/"), new DeleteOptions { Recursive = true, IfMatch = "\"9\"" }, Ct);
        Assert.Equal("\"9\"", _server.Requests[^1].Header("If-Match"));
    }

    // ------------------------------------------------------------------------------------------------ linksets

    [Fact]
    public async Task LinksetOperations()
    {
        string url = Root + "p.json";
        JsonElement fixture = Fixtures.Load("responses/linkset.json");
        _server.On("HEAD", url, () => Respond.Status(200, ("Link", "<p.json.meta>; rel=\"linkset\"")));
        _server.On("HEAD", Root + "bare", () => Respond.Status(200));
        _server.On("GET", url + ".meta", () => Respond.Json(200, fixture.GetProperty("body").GetRawText(), "application/linkset+json",
            ("ETag", "\"ls-7\""), ("Allow", "GET, HEAD, PATCH"), ("Accept-Patch", "application/json-patch+json")));
        _server.On("PUT", url + ".meta", () => Respond.Status(405, ("Allow", "GET, HEAD, PATCH")));
        _server.On("PATCH", url + ".meta", () => Respond.Status(204));

        Assert.Equal(url + ".meta", (await _client.LinksetUrlAsync(U(url), cancellationToken: Ct)).AbsoluteUri);
        await Assert.ThrowsAsync<ProtocolException>(() => _client.LinksetUrlAsync(U(Root + "bare"), cancellationToken: Ct));
        LinksetDocument doc = await _client.ReadLinksetAsync(U(url), cancellationToken: Ct);
        Assert.Equal(url + ".meta", doc.Url.AbsoluteUri);
        Assert.Equal("\"ls-7\"", doc.ETag);
        Assert.False(doc.SupportsPut);
        Assert.Equal("application/linkset+json, application/json;q=0.5", _server.RequestsTo("GET", url + ".meta").Single().Header("Accept"));

        MethodNotAllowedException e = await Assert.ThrowsAsync<MethodNotAllowedException>(() =>
            _client.UpdateLinksetAsync(doc.Url, doc.Linkset.Add(doc.Linkset.Contexts[0].Anchor, "license", "https://example.org/l2"),
                new UpdateOptions { IfMatch = doc.ETag }, Ct));
        Assert.Equal(["GET", "HEAD", "PATCH"], e.Allow);
        Recorded put = _server.RequestsTo("PUT", url + ".meta").Single();
        Assert.Equal("application/linkset+json", put.Header("Content-Type"));
        Assert.Equal(2, Linkset.Parse(put.Text).GetTargets("license").Count);

        string pointer = JsonPointer.Of("linkset", "0", "https://example.org/rel/reviewer", "-");
        await _client.PatchLinksetAsync(doc.Url, new JsonPatch().Add(pointer, new JsonObject { ["href"] = "https://id.example/dan" }),
            new UpdateOptions { IfMatch = doc.ETag }, Ct);
        Recorded patch = _server.RequestsTo("PATCH", url + ".meta").Single();
        Assert.Equal("application/json-patch+json", patch.Header("Content-Type"));
        Assert.Contains("/linkset/0/https:~1~1example.org~1rel~1reviewer/-", patch.Text, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------------------------------------ notifications

    [Fact]
    public async Task SubscriptionLifecycle()
    {
        string service = Base + "/notifications/";
        JsonElement fixture = Fixtures.Load("responses/subscription.json");
        JsonElement response = fixture.GetProperty("response");
        _server.On("POST", service, () => Respond.Json(200, response.GetProperty("body").GetRawText(), "application/lws+json",
            ("Location", response.GetProperty("headers").Str("location"))));
        JsonElement input = fixture.GetProperty("input");
        var request = new WebhookSubscriptionRequest(U(input.Str("inbox")), input.Strings("topics").Select(U),
            DateTimeOffset.Parse(input.Str("expires"), System.Globalization.CultureInfo.InvariantCulture));
        Subscription s = await _client.SubscribeAsync(U(service), request, cancellationToken: Ct);
        Assert.Equal("https://notification.example/subscriptions/9e8d7c6b5a4f", s.Url.AbsoluteUri);
        Assert.Equal("WebhookSubscription", s.Type);
        Recorded post = _server.Requests.Single();
        Assert.Equal("application/lws+json", post.Header("Content-Type"));
        Assert.True(Fixtures.JsonEquals(fixture.GetProperty("expectedRequestBody"), Fixtures.Parse(post.Text)));

        // A response without a body falls back to Location.
        _server.On("POST", service, () => Respond.Status(201, ("Location", "s/2")));
        Subscription bare = await _client.SubscribeAsync(U(service), request, cancellationToken: Ct);
        Assert.Equal(service + "s/2", bare.Url.AbsoluteUri);
        _server.On("POST", service, () => Respond.Status(201));
        await Assert.ThrowsAsync<ProtocolException>(() => _client.SubscribeAsync(U(service), request, cancellationToken: Ct));

        // Through the storage description: the service must offer webhooks.
        StorageDescription sd = StorageDescription.Parse(Fixtures.Parse(
            "{\"id\":\"https://storage.example/\",\"type\":\"Storage\",\"service\":[{\"type\":\"NotificationService\",\"serviceEndpoint\":\"/n/\",\"subscriptionType\":[\"StreamingSubscription\"]}]}"), null);
        await Assert.ThrowsAsync<ProtocolException>(() => _client.SubscribeAsync(sd.NotificationService!, request, cancellationToken: Ct));

        _server.On("GET", service, () => Respond.Json(200, Page("/notifications/", "s/1", "s/2"), "application/lws+json"));
        Assert.Equal([service + "s/1", service + "s/2"], await _client.ListSubscriptionsAsync(U(service), cancellationToken: Ct).Select(i => i.Id.AbsoluteUri).ToListAsync(Ct));
        _server.On("GET", service + "s/2", () => Respond.Json(200, "{\"type\":\"WebhookSubscription\",\"expires\":\"2026-11-01T00:00:00Z\"}", "application/lws+json"));
        Subscription got = await _client.GetSubscriptionAsync(U(service + "s/2"), cancellationToken: Ct);
        Assert.Equal(service + "s/2", got.Url.AbsoluteUri);
        Assert.Equal("2026-11-01T00:00:00Z", got.ExpiresRaw);
        _server.On("DELETE", service + "s/2", () => Respond.Status(204));
        await _client.UnsubscribeAsync(U(service + "s/2"), cancellationToken: Ct);
        Assert.Equal("DELETE", _server.Requests[^1].Method);
    }

    // ------------------------------------------------------------------------------------------------ access

    [Fact]
    public async Task AccessRequestsAndGrants()
    {
        JsonElement fixture = Fixtures.Load("responses/access.json");
        string requests = Base + "/access/requests/";
        string grants = Base + "/access/grants/";
        _server.On("POST", requests, () => Respond.Status(201, ("Location", "r1")));
        _server.On("GET", requests + "r1", () => Respond.Json(200, fixture.GetProperty("request").GetRawText(), "application/lws+json"));
        _server.On("GET", requests, () => Respond.Json(200, Page("/access/requests/", "r1"), "application/lws+json"));
        _server.On("DELETE", requests + "r1", () => Respond.Status(204));
        _server.On("POST", grants, () => Respond.Status(201, ("Location", grants + "g1")));
        _server.On("GET", grants + "g1", () => Respond.Json(200, fixture.GetProperty("grant").GetRawText(), "application/lws+json"));
        _server.On("GET", grants, () => Respond.Json(200, Page("/access/grants/", "g1"), "application/lws+json"));
        _server.On("DELETE", grants + "g1", () => Respond.Status(204));

        AccessRequest request = AccessRequest.Parse(fixture.GetProperty("request"));
        Uri r1 = await _client.RequestAccessAsync(U(requests), request, cancellationToken: Ct);
        Assert.Equal(requests + "r1", r1.AbsoluteUri);
        Recorded post = _server.Requests[^1];
        Assert.Equal("application/lws+json", post.Header("Content-Type"));
        Assert.True(Fixtures.JsonEquals(fixture.GetProperty("request"), Fixtures.Parse(post.Text)));
        AccessRequest got = await _client.GetAccessRequestAsync(r1, cancellationToken: Ct);
        Assert.Equal(request.Access[0].Assignee, got.Access[0].Assignee);
        Assert.Equal([requests + "r1"], await _client.ListAccessRequestsAsync(U(requests), cancellationToken: Ct).Select(i => i.Id.AbsoluteUri).ToListAsync(Ct));

        Uri g1 = await _client.GrantAccessAsync(U(grants), AccessGrant.Approving(got), cancellationToken: Ct);
        Assert.Equal(grants + "g1", g1.AbsoluteUri);
        Assert.Equal("AccessGrant", Fixtures.Parse(_server.Requests[^1].Text).GetProperty("type")[0].GetString());
        AccessGrant grant = await _client.GetAccessGrantAsync(g1, cancellationToken: Ct);
        Assert.Equal(["read"], grant.Access[0].Actions);
        Assert.Single(await _client.ListAccessGrantsAsync(U(grants), cancellationToken: Ct).ToListAsync(Ct));
        await _client.RevokeAccessGrantAsync(g1, cancellationToken: Ct);
        await _client.CancelAccessRequestAsync(r1, cancellationToken: Ct);
        Assert.Equal(["DELETE", "DELETE"], _server.Requests.TakeLast(2).Select(r => r.Method));

        _server.On("GET", grants + "g1", () => Respond.Json(200, "{\"type\":\"Other\"}", "application/lws+json"));
        await Assert.ThrowsAsync<ProtocolException>(() => _client.GetAccessGrantAsync(g1, cancellationToken: Ct));
    }

    // ------------------------------------------------------------------------------------------------ type index and search

    [Fact]
    public async Task TypeIndexPages()
    {
        string index = Base + "/types/index";
        _server.On("GET", index, () => Respond.Json(200, "{\"type\":\"TypeIndex\",\"totalItems\":3,\"items\":[{\"id\":\"https://schema.org/Person\"}]}", "application/lws+json",
            ("Link", "<?page=2>; rel=\"next\"")));
        _server.On("GET", index + "?page=2", () => Respond.Json(200, "{\"type\":\"TypeIndex\",\"items\":[\"https://schema.org/Event\"]}", "application/lws+json",
            ("Link", "<?page=3>; rel=\"next\"")));
        _server.On("GET", index + "?page=3", () => Respond.Json(200, "{\"type\":\"TypeIndex\",\"items\":[{\"id\":\"https://schema.org/Note\"}]}", "application/lws+json"));
        TypeIndexPage first = await _client.ReadTypeIndexAsync(U(index), cancellationToken: Ct);
        Assert.Equal(3, first.TotalItems);
        Assert.Equal(index + "?page=2", first.Next?.AbsoluteUri);
        Assert.Equal(["https://schema.org/Person", "https://schema.org/Event", "https://schema.org/Note"],
            await _client.ListTypesAsync(U(index), cancellationToken: Ct).ToListAsync(Ct));
        Assert.All(_server.Requests, r => Assert.Equal("application/lws+json", r.Header("Accept")));
    }

    [Fact]
    public async Task SearchUsesQueryThenGetsTheNextPages()
    {
        string search = Base + "/types/search";
        _server.On("QUERY", search, () => Respond.Json(200,
            "{\"type\":\"ContainerPage\",\"totalItems\":3,\"items\":[{\"id\":\"/data/1\",\"type\":[\"DataResource\",\"https://schema.org/Person\"]}]}",
            "application/lws+json", ("Link", "</types/search?cursor=b>; rel=\"next\"")));
        _server.On("GET", search + "?cursor=b", () => Respond.Json(200, "{\"type\":\"ContainerPage\",\"items\":[{\"id\":\"/data/2\"}]}", "application/lws+json",
            ("Link", "</types/search?cursor=c>; rel=\"next\"")));
        _server.On("GET", search + "?cursor=c", () => Respond.Json(200, "{\"type\":\"ContainerPage\",\"items\":[{\"id\":\"/data/3\"}]}", "application/lws+json"));
        _server.On("OPTIONS", search, () => Respond.Status(204, ("Allow", "OPTIONS, QUERY"), ("Accept-Query", "application/lws-query+json, \"application/jsonpath\"")));

        TypeQuery query = new TypeQuery().AllOf("https://schema.org/Person");
        ContainerPage page = await _client.SearchTypesAsync(U(search), query, cancellationToken: Ct);
        Assert.Equal(search, page.Id.AbsoluteUri);
        Assert.Equal(Base + "/data/1", page.Items.Single().Id.AbsoluteUri);
        Recorded q = _server.Requests.Single();
        Assert.Equal("QUERY", q.Method);
        Assert.Equal("application/lws-query+json", q.Header("Content-Type"));
        Assert.Equal("application/lws+json", q.Header("Accept"));
        Assert.Equal("{\"type\":[\"https://schema.org/Person\"]}", q.Text);

        List<string> all = await _client.SearchAllAsync(U(search), query, cancellationToken: Ct).Select(i => i.Id.AbsoluteUri).ToListAsync(Ct);
        Assert.Equal([Base + "/data/1", Base + "/data/2", Base + "/data/3"], all);
        Assert.Equal(["QUERY", "QUERY", "GET", "GET"], _server.Requests.Select(r => r.Method));

        Assert.Equal(["application/lws-query+json", "application/jsonpath"], await _client.AcceptedQueryFormatsAsync(U(search), cancellationToken: Ct));
    }

    // ------------------------------------------------------------------------------------------------ errors and transport

    public static TheoryData<int, Type> StatusMappings() => new()
    {
        { 400, typeof(BadRequestException) }, { 401, typeof(UnauthorizedException) }, { 403, typeof(ForbiddenException) },
        { 404, typeof(NotFoundException) }, { 405, typeof(MethodNotAllowedException) }, { 406, typeof(NotAcceptableException) },
        { 409, typeof(ConflictException) }, { 410, typeof(GoneException) }, { 412, typeof(PreconditionFailedException) },
        { 415, typeof(UnsupportedMediaTypeException) }, { 422, typeof(UnprocessableContentException) },
        { 501, typeof(HttpNotImplementedException) }, { 507, typeof(InsufficientStorageException) },
        { 418, typeof(HttpException) }, { 500, typeof(HttpException) }, { 503, typeof(HttpException) },
    };

    [Theory]
    [MemberData(nameof(StatusMappings))]
    public async Task ErrorStatusesMapToExceptions(int status, Type expected)
    {
        _server.On("GET", Root + "x", () => Respond.Text(status, new string('e', 5000)));
        HttpException e = await Assert.ThrowsAnyAsync<HttpException>(() => _client.ReadAsync(U(Root + "x"), cancellationToken: Ct));
        Assert.IsType(expected, e);
        Assert.Equal(status, e.Status);
        Assert.Equal(HttpException.MaxBodyLength, e.Body.Length);
        Assert.Equal("GET", e.Method);
        Assert.IsAssignableFrom<LwsException>(e);
    }

    [Fact]
    public async Task UnauthorizedCarriesTheChallenges()
    {
        _server.On("GET", Root, () => Respond.Status(401, ("WWW-Authenticate", "Bearer as_uri=\"https://as.example\", realm=\"https://storage.example/\"")));
        UnauthorizedException e = await Assert.ThrowsAsync<UnauthorizedException>(() => _client.ReadAsync(U(Root), cancellationToken: Ct));
        Assert.Equal("https://as.example", e.Challenges.Single().AsUri);
        _server.On("QUERY", Base + "/s", () => Respond.Status(415, ("Accept-Query", "application/lws-query+json")));
        UnsupportedMediaTypeException u = await Assert.ThrowsAsync<UnsupportedMediaTypeException>(() => _client.SearchTypesAsync(U(Base + "/s"), TypeQuery.Empty, cancellationToken: Ct));
        Assert.Equal(["application/lws-query+json"], u.AcceptQuery);
    }

    [Fact]
    public async Task TransportFailuresTimeoutsAndCancellation()
    {
        _server.BeforeRespond = async (r, token) =>
        {
            if (r.Uri.AbsolutePath == "/down") throw new HttpRequestException("connection refused");
            if (r.Uri.AbsolutePath == "/slow") await Task.Delay(TimeSpan.FromSeconds(10), token);
        };
        LwsTransportException down = await Assert.ThrowsAsync<LwsTransportException>(() => _client.ReadAsync(U(Base + "/down"), cancellationToken: Ct));
        Assert.IsType<HttpRequestException>(down.InnerException);
        LwsTransportException slow = await Assert.ThrowsAsync<LwsTransportException>(() =>
            _client.ReadAsync(U(Base + "/slow"), new ReadOptions { Timeout = TimeSpan.FromMilliseconds(100) }, Ct));
        Assert.IsType<TimeoutException>(slow.InnerException);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => _client.ReadAsync(U(Base + "/slow"), cancellationToken: cts.Token));
    }

    [Fact]
    public async Task ArgumentsMustBeAbsoluteHttpUrls()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => _client.ReadAsync(new Uri("/root/", UriKind.Relative), cancellationToken: Ct));
        await Assert.ThrowsAsync<ArgumentException>(() => _client.ReadAsync(new Uri("/root/", UriKind.RelativeOrAbsolute), cancellationToken: Ct));
        await Assert.ThrowsAsync<ArgumentException>(() => _client.HeadAsync(new Uri("ftp://storage.example/"), cancellationToken: Ct));
        Assert.Throws<ArgumentException>(() => _client.ListContainerAsync(new Uri("file:///tmp/"), cancellationToken: Ct));
        await Assert.ThrowsAsync<ArgumentNullException>(() => _client.ReadAsync(null!, cancellationToken: Ct));
        Assert.Empty(_server.Requests);
    }

    [Fact]
    public async Task DefaultHeadersUserAgentAndPerCallHeaders()
    {
        using var client = new LwsClient(new LwsClientOptions
        {
            HttpMessageHandler = _server,
            UserAgent = "custom/1",
            DefaultHeaders = new Dictionary<string, string> { ["X-Default"] = "d", ["X-Both"] = "default" },
        });
        _server.On("HEAD", Root, () => Respond.Status(200));
        await client.HeadAsync(U(Root), new RequestOptions { Headers = new Dictionary<string, string> { ["X-Both"] = "call" } }, Ct);
        Recorded r = _server.Requests.Single();
        Assert.Equal("custom/1", r.Header("User-Agent"));
        Assert.Equal("d", r.Header("X-Default"));
        Assert.Equal(["call"], r.HeaderValues("X-Both"));
        using var anonymous = new LwsClient(new LwsClientOptions { HttpMessageHandler = _server, UserAgent = null });
        await anonymous.HeadAsync(U(Root), cancellationToken: Ct);
        Assert.Null(_server.Requests[^1].Header("User-Agent"));
    }

    [Fact]
    public async Task RedirectsAreFollowedByTheClient()
    {
        _server.On("GET", Root + "old", () => Respond.Status(301, ("Location", "/root/new")));
        _server.On("GET", Root + "new", () => Respond.Text(200, "moved"));
        Resource r = await _client.ReadAsync(U(Root + "old"), cancellationToken: Ct);
        Assert.Equal("moved", r.GetText());
        Assert.Equal(Root + "new", r.Url.AbsoluteUri);

        // 303 turns a QUERY into a GET of the result; 307 keeps a POST and its body; 302 does not redirect a POST.
        _server.On("QUERY", Base + "/q", () => Respond.Status(303, ("Location", "/q/result")));
        _server.On("GET", Base + "/q/result", () => Respond.Json(200, "{\"type\":\"ContainerPage\",\"items\":[]}", "application/lws+json"));
        Assert.Empty((await _client.SearchTypesAsync(U(Base + "/q"), TypeQuery.Empty, cancellationToken: Ct)).Items);
        Assert.Null(_server.RequestsTo("GET", Base + "/q/result").Single().Header("Content-Type"));

        _server.On("POST", Root + "c1/", () => Respond.Status(307, ("Location", "/root/c2/")));
        _server.On("POST", Root + "c2/", () => Respond.Status(201, ("Location", "/root/c2/x")));
        CreateResult created = await _client.CreateTextAsync(U(Root + "c1/"), "body", cancellationToken: Ct);
        Assert.Equal(Root + "c2/x", created.Location.AbsoluteUri);
        Assert.Equal("body", _server.RequestsTo("POST", Root + "c2/").Single().Text);

        _server.On("POST", Root + "c3/", () => Respond.Status(302, ("Location", "/root/c2/")));
        HttpException e = await Assert.ThrowsAsync<HttpException>(() => _client.CreateTextAsync(U(Root + "c3/"), "body", cancellationToken: Ct));
        Assert.Equal(302, e.Status);
        Assert.Single(_server.RequestsTo("POST", Root + "c2/"));
    }

    [Fact]
    public async Task RedirectLoopsAreBounded()
    {
        _server.On("GET", Root + "loop", r => Respond.Status(302, ("Location", "/root/loop")));
        await Assert.ThrowsAsync<ProtocolException>(() => _client.ReadAsync(U(Root + "loop"), cancellationToken: Ct));
        Assert.Equal(11, _server.Requests.Count);
    }

    [Fact]
    public async Task PostIsNeverRetried()
    {
        _server.On("POST", Root, () => Respond.Status(503));
        await Assert.ThrowsAsync<HttpException>(() => _client.CreateTextAsync(U(Root), "once", cancellationToken: Ct));
        _server.BeforeRespond = (r, _) => r.Method == "POST" && r.Uri.AbsolutePath == "/root/broken/" ? throw new HttpRequestException("reset") : Task.CompletedTask;
        await Assert.ThrowsAsync<LwsTransportException>(() => _client.CreateTextAsync(U(Root + "broken/"), "once", cancellationToken: Ct));
        Assert.Equal(2, _server.Requests.Count(r => r.Method == "POST"));
    }

    [Fact]
    public async Task RequestAsyncSendsAnything()
    {
        _server.On("PROPFIND", Root, () => Respond.Text(207, "<multistatus/>", "application/xml"));
        Resource r = await _client.RequestAsync(new HttpMethod("PROPFIND"), U(Root), "<x/>"u8.ToArray(), "application/xml", cancellationToken: Ct);
        Assert.Equal(207, r.Status);
        Assert.Equal("application/xml", _server.Requests.Single().Header("Content-Type"));
    }

    [Fact]
    public async Task WithAuthenticatorSharesTheConnection()
    {
        using LwsClient bearer = _client.WithAuthenticator(new Auth.BearerTokenAuthenticator("t0k", U(Base + "/")));
        _server.On("HEAD", Root, () => Respond.Status(200));
        _server.On("HEAD", "https://other.example/", () => Respond.Status(200));
        await bearer.HeadAsync(U(Root), cancellationToken: Ct);
        await bearer.HeadAsync(U("https://other.example/"), cancellationToken: Ct);
        await _client.HeadAsync(U(Root), cancellationToken: Ct);
        Assert.Equal(["Bearer t0k", null, null], _server.Requests.Select(r => r.Header("Authorization")));
    }
}
