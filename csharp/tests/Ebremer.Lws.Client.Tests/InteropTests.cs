// SPDX-License-Identifier: MIT
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ebremer.Lws.Access;
using Ebremer.Lws.Auth;
using Ebremer.Lws.Notifications;

namespace Ebremer.Lws.Tests;

/// <summary>
/// The cross-language interop scenario (<c>conformance/scenario.md</c>) against the mock server of
/// <c>testing/mock-server</c>. Skipped unless <c>LWS_TEST_SERVER</c> is set to its base URL.
/// </summary>
public sealed class InteropTests
{
    private const string Person = "https://schema.org/Person";

    [Fact]
    public async Task Scenario()
    {
        string? server = Environment.GetEnvironmentVariable("LWS_TEST_SERVER");
        Assert.SkipUnless(!string.IsNullOrEmpty(server), "LWS_TEST_SERVER is not set");
        string baseUrl = server!.TrimEnd('/');
        var root = new Uri(baseUrl + "/root/");
        var storageId = new Uri(baseUrl + "/");

        // 1. Authenticate + discover.
        SelfSignedCredentials credentials = SelfSignedCredentials.DidKey(SigningKey.GenerateP256());
        using var authenticator = new TokenExchangeAuthenticator(credentials);
        using var client = new LwsClient(new LwsClientOptions { Authenticator = authenticator });
        StorageDescription storage = await client.DiscoverStorageAsync(root, cancellationToken: Ct);
        Assert.Equal(root, storage.GetStorageRoot());
        Assert.NotNull(storage.NotificationService);
        Assert.NotNull(storage.AccessRequestService);
        Assert.NotNull(storage.AccessGrantService);
        Assert.NotNull(storage.TypeIndexService);
        Assert.NotNull(storage.TypeSearchService);

        // 2. Create a container.
        string slug = $"interop-csharp-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        Uri c = (await client.CreateContainerAsync(root, new CreateOptions { Slug = slug }, Ct)).Location;
        Assert.StartsWith(root.AbsoluteUri, c.AbsoluteUri, StringComparison.Ordinal);

        // 3. Create text.
        Uri h = (await client.CreateAsync(c, "Hello, LWS!"u8.ToArray(), "text/plain", new CreateOptions { Slug = "hello.txt" }, Ct)).Location;

        // 4. Read.
        Resource hello = await client.ReadAsync(h, cancellationToken: Ct);
        Assert.Equal("Hello, LWS!", hello.GetText());
        string etag = Assert.IsType<string>(hello.ETag);
        Assert.True(hello.Metadata.IsDataResource);
        Assert.Equal(c, hello.Metadata.Parent);
        Assert.NotNull(hello.Metadata.Linkset);
        Assert.Equal(storageId, hello.Metadata.Storage);

        // 5. Conditional read.
        Assert.True((await client.ReadAsync(h, new ReadOptions { IfNoneMatch = etag }, Ct)).NotModified);

        // 6. Update with If-Match; a stale ETag is a precondition failure.
        await client.UpdateAsync(h, "Hello again"u8.ToArray(), "text/plain", new UpdateOptions { IfMatch = etag }, Ct);
        await Assert.ThrowsAsync<PreconditionFailedException>(() =>
            client.UpdateAsync(h, "stale"u8.ToArray(), "text/plain", new UpdateOptions { IfMatch = etag }, Ct));
        Assert.Equal("Hello again", (await client.ReadAsync(h, cancellationToken: Ct)).GetText());

        // 7. Create JSON with an extra type, and patch it.
        Uri p = (await client.CreateJsonAsync(c, new JsonObject { ["name"] = "Alice", ["age"] = 30 },
            new CreateOptions { Slug = "profile.json", Types = [Person] }, Ct)).Location;
        await client.PatchAsync(p, new JsonPatch().Replace("/age", 31).Add("/city", "Boston"), cancellationToken: Ct);
        JsonElement profile = (await client.ReadAsync(p, cancellationToken: Ct)).GetJson();
        Assert.Equal("Alice", profile.GetProperty("name").GetString());
        Assert.Equal(31, profile.GetProperty("age").GetInt32());
        Assert.Equal("Boston", profile.GetProperty("city").GetString());

        // 8. Linkset.
        LinksetDocument linkset = await client.ReadLinksetAsync(p, cancellationToken: Ct);
        await client.PatchLinksetAsync(linkset.Url,
            new JsonPatch().Add(JsonPointer.Of("linkset", "0", "describedby"), new JsonArray(new JsonObject { ["href"] = "https://example.org/shapes/person" })),
            new UpdateOptions { IfMatch = linkset.ETag }, Ct);
        LinksetDocument after = await client.ReadLinksetAsync(p, cancellationToken: Ct);
        Assert.Contains(after.Linkset.GetTargets("describedby"), t => t.Href == "https://example.org/shapes/person");

        // 9. Pagination: 8 members.
        for (int i = 0; i < 6; i++)
        {
            await client.CreateTextAsync(c, $"item {i}", options: new CreateOptions { Slug = $"item-{i}.txt" }, cancellationToken: Ct);
        }
        ContainerPage first = await client.ReadContainerAsync(c, cancellationToken: Ct);
        Assert.Equal(8, first.TotalItems);
        Assert.NotNull(first.Next);
        List<Uri> members = await client.ListContainerAsync(c, cancellationToken: Ct).Select(i => i.Id).ToListAsync(Ct);
        Assert.Equal(8, members.Count);
        Assert.Contains(h, members);
        Assert.Contains(p, members);

        // 10. Type index and search.
        Assert.Contains(Person, await client.ListTypesAsync(storage.TypeIndexService!.ServiceEndpoint, cancellationToken: Ct).ToListAsync(Ct));
        Uri search = storage.TypeSearchService!.ServiceEndpoint;
        Assert.Contains(p, await client.SearchAllAsync(search, new TypeQuery().AllOf(Person), cancellationToken: Ct).Select(i => i.Id).ToListAsync(Ct));
        Assert.Contains(Lws.MediaType.LwsQueryJson, await client.AcceptedQueryFormatsAsync(search, cancellationToken: Ct));

        // 11. Notifications: a signed delivery to a local inbox, verified.
        await using (var inbox = await Inbox.StartAsync(client, storageId))
        {
            Subscription subscription = await client.SubscribeAsync(storage.NotificationService!, new WebhookSubscriptionRequest(inbox.Url, [c]), cancellationToken: Ct);
            await client.UpdateAsync(h, "Hello, notifications"u8.ToArray(), "text/plain", cancellationToken: Ct);
            VerifiedNotification verified = await inbox.WaitAsync(v => v.Notification.Activities.Any(a => a.IsUpdate && a.Object.Id == h), TimeSpan.FromSeconds(5));
            Assert.Equal(storageId, verified.Storage);
            Assert.Contains(subscription.Url, await client.ListSubscriptionsAsync(storage.NotificationService!.ServiceEndpoint, cancellationToken: Ct).Select(i => i.Id).ToListAsync(Ct));
            await client.UnsubscribeAsync(subscription.Url, cancellationToken: Ct);
        }

        // 12. Access requests and grants.
        var policy = new AccessPolicy([Lws.Actions.Read], credentials.Agent, AccessTarget.StorageResources(c),
            [Constraint.Purpose(new Uri("https://purpose.example/interop"))]);
        Uri request = await client.RequestAccessAsync(storage.AccessRequestService!.ServiceEndpoint, new AccessRequest(storage.Id, [policy]), cancellationToken: Ct);
        AccessRequest gotRequest = await client.GetAccessRequestAsync(request, cancellationToken: Ct);
        Assert.Equal(credentials.Agent, gotRequest.Access[0].Assignee);
        Assert.Equal([c.AbsoluteUri], gotRequest.Access[0].Target!.Values);
        Assert.Contains(request, await client.ListAccessRequestsAsync(storage.AccessRequestService.ServiceEndpoint, cancellationToken: Ct).Select(i => i.Id).ToListAsync(Ct));
        Uri grant = await client.GrantAccessAsync(storage.AccessGrantService!.ServiceEndpoint, new AccessGrant(storage.Id, [policy]), cancellationToken: Ct);
        Assert.Equal([Lws.Actions.Read], (await client.GetAccessGrantAsync(grant, cancellationToken: Ct)).Access[0].Actions);
        await client.RevokeAccessGrantAsync(grant, cancellationToken: Ct);
        await client.CancelAccessRequestAsync(request, cancellationToken: Ct);
        await Assert.ThrowsAsync<NotFoundException>(() => client.GetAccessRequestAsync(request, cancellationToken: Ct));

        // 13. Delete.
        await Assert.ThrowsAsync<ConflictException>(() => client.DeleteAsync(c, cancellationToken: Ct));
        await client.DeleteAsync(c, new DeleteOptions { Recursive = true }, Ct);
        await Assert.ThrowsAsync<NotFoundException>(() => client.ReadAsync(h, cancellationToken: Ct));
    }

    /// <summary>A local webhook inbox that verifies every delivery with <see cref="WebhookVerifier"/>.</summary>
    private sealed class Inbox : IAsyncDisposable
    {
        private readonly HttpListener _listener;
        private readonly WebhookVerifier _verifier;
        private readonly ConcurrentQueue<VerifiedNotification> _verified = new();
        private readonly SemaphoreSlim _arrived = new(0);
        private readonly Task _loop;

        private Inbox(HttpListener listener, WebhookVerifier verifier, Uri url)
        {
            _listener = listener;
            _verifier = verifier;
            Url = url;
            _loop = Task.Run(LoopAsync);
        }

        public Uri Url { get; }

        public static Task<Inbox> StartAsync(LwsClient client, Uri storage)
        {
            int port;
            using (var probe = new TcpListener(IPAddress.Loopback, 0))
            {
                probe.Start();
                port = ((IPEndPoint)probe.LocalEndpoint).Port;
            }
            var listener = new HttpListener();
            listener.Prefixes.Add($"http://127.0.0.1:{port}/");
            listener.Start();
            var verifier = new WebhookVerifier(new WebhookVerifierOptions { Client = client, TrustedStorages = [storage] });
            return Task.FromResult(new Inbox(listener, verifier, new Uri($"http://127.0.0.1:{port}/inbox")));
        }

        private async Task LoopAsync()
        {
            while (_listener.IsListening)
            {
                HttpListenerContext context;
                try
                {
                    context = await _listener.GetContextAsync();
                }
                catch (Exception e) when (e is HttpListenerException or ObjectDisposedException or InvalidOperationException)
                {
                    return;
                }
                try
                {
                    _verified.Enqueue(await _verifier.VerifyAsync(context.Request, Url));
                    context.Response.StatusCode = 202;
                }
                catch (SignatureVerificationException)
                {
                    context.Response.StatusCode = 400;
                }
                context.Response.Close();
                _arrived.Release();
            }
        }

        public async Task<VerifiedNotification> WaitAsync(Func<VerifiedNotification, bool> predicate, TimeSpan timeout)
        {
            DateTimeOffset deadline = DateTimeOffset.UtcNow + timeout;
            while (true)
            {
                VerifiedNotification? found = _verified.FirstOrDefault(predicate);
                if (found is not null) return found;
                TimeSpan left = deadline - DateTimeOffset.UtcNow;
                if (left <= TimeSpan.Zero || !await _arrived.WaitAsync(left)) Assert.Fail("No verified notification arrived in time");
            }
        }

        public async ValueTask DisposeAsync()
        {
            _listener.Stop();
            _listener.Close();
            await _loop.ConfigureAwait(false);
            _verifier.Dispose();
            _arrived.Dispose();
        }
    }
}
