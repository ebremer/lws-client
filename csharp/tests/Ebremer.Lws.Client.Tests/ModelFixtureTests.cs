// SPDX-License-Identifier: MIT
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ebremer.Lws.Access;
using Ebremer.Lws.Auth;
using Ebremer.Lws.Http;
using Ebremer.Lws.Internal;
using Ebremer.Lws.Notifications;
using Ebremer.Lws.Tests.Support;

namespace Ebremer.Lws.Tests;

/// <summary>The shared response fixtures (<c>conformance/fixtures/responses</c>) and the models they parse into.</summary>
public sealed class ModelFixtureTests
{
    private static HeaderMap HeadersOf(JsonElement headers) => HeaderMap.From(headers.EnumerateObject().SelectMany(p =>
        p.Value.ValueKind == JsonValueKind.Array
            ? p.Value.EnumerateArray().Select(v => new KeyValuePair<string, string>(p.Name, v.GetString()!))
            : [new KeyValuePair<string, string>(p.Name, p.Value.GetString()!)]));

    [Fact]
    public void ContainerPageFixture()
    {
        JsonElement f = Fixtures.Load("responses/container-page.json");
        var metadata = new ResourceMetadata(new Uri(f.Str("url")), f.GetProperty("status").GetInt32(), HeadersOf(f.GetProperty("headers")));
        ContainerPage page = ContainerPage.Parse(f.GetProperty("body"), metadata);
        JsonElement e = f.GetProperty("expected");
        Assert.Equal(e.Str("id"), page.Id.AbsoluteUri);
        Assert.True(page.IsContainer);
        Assert.Equal(e.GetProperty("totalItems").GetInt64(), page.TotalItems);
        Assert.Equal(e.Str("etag"), page.ETag);
        Assert.Equal(e.Str("linkset"), page.Metadata.Linkset?.AbsoluteUri);
        Assert.Equal(e.Str("parent"), page.Metadata.Parent?.AbsoluteUri);
        Assert.Equal(e.Str("storage"), page.Metadata.Storage?.AbsoluteUri);
        Assert.Equal(e.Str("first"), page.First?.AbsoluteUri);
        Assert.Equal(e.Str("next"), page.Next?.AbsoluteUri);
        Assert.Null(page.Prev);
        Assert.Equal(e.Str("last"), page.Last?.AbsoluteUri);
        Assert.True(page.Metadata.IsContainer);
        var items = e.Arr("items").ToList();
        Assert.Equal(items.Count, page.Items.Count);
        for (int i = 0; i < items.Count; i++)
        {
            JsonElement x = items[i];
            ContainedResource item = page.Items[i];
            Assert.Equal(x.Str("id"), item.Id.AbsoluteUri);
            Assert.Equal(x.GetProperty("isContainer").GetBoolean(), item.IsContainer);
            Assert.Equal(x.GetProperty("isDataResource").GetBoolean(), item.IsDataResource);
            Assert.Equal(x.OptStr("format"), item.Format);
            Assert.Equal(x.GetProperty("size").ValueKind == JsonValueKind.Null ? null : x.GetProperty("size").GetInt64(), item.Size);
            Assert.Equal(x.Strings("types"), item.Types);
            if (x.OptStr("modified") is { } modified) Assert.Equal(DateTimeOffset.Parse(modified, System.Globalization.CultureInfo.InvariantCulture), item.Modified);
            else Assert.Null(item.Modified);
            if (x.OptStr("modifiedRaw") is { } raw) Assert.Equal(raw, item.ModifiedRaw);
            if (x.OptStr("hasType") is { } t) Assert.True(item.HasType(t));
        }
    }

    [Fact]
    public void ContainerPageWithoutIdUsesThePageUrl()
    {
        var metadata = new ResourceMetadata(new Uri("https://example.org/types/search?cursor=1"), 200, HeaderMap.Empty);
        ContainerPage page = ContainerPage.Parse(Fixtures.Parse("{\"type\":\"ContainerPage\",\"items\":[]}"), metadata);
        Assert.Equal("https://example.org/types/search?cursor=1", page.Id.AbsoluteUri);
        Assert.False(page.IsContainer);
        Assert.Throws<ProtocolException>(() => ContainerPage.Parse(Fixtures.Parse("{\"items\":{}}"), metadata));
        Assert.Throws<ProtocolException>(() => ContainerPage.Parse(Fixtures.Parse("{\"items\":[{\"type\":\"x\"}]}"), metadata));
        Assert.Throws<ProtocolException>(() => ContainerPage.Parse(Fixtures.Parse("[]"), metadata));
    }

    [Fact]
    public void StorageDescriptionFixture()
    {
        JsonElement f = Fixtures.Load("responses/storage-description.json");
        StorageDescription s = StorageDescription.Parse(f.GetProperty("body"), new Uri(f.Str("url")));
        JsonElement e = f.GetProperty("expected");
        Assert.Equal(e.Str("id"), s.Id.AbsoluteUri);
        Assert.Equal(e.Strings("types"), s.Types);
        Assert.Equal(e.Str("storageRoot"), s.GetStorageRoot().AbsoluteUri);
        Assert.Equal(e.Str("notificationService"), s.NotificationService!.ServiceEndpoint.AbsoluteUri);
        Assert.Equal(e.Strings("notificationSubscriptionTypes"), s.NotificationService.SubscriptionTypes);
        Assert.Equal(e.Str("typeIndexService"), s.TypeIndexService!.ServiceEndpoint.AbsoluteUri);
        Assert.Equal(e.Str("typeSearchService"), s.TypeSearchService!.ServiceEndpoint.AbsoluteUri);
        Assert.Equal(e.Str("accessRequestService"), s.AccessRequestService!.ServiceEndpoint.AbsoluteUri);
        Assert.Equal(e.Str("accessGrantService"), s.AccessGrantService!.ServiceEndpoint.AbsoluteUri);
        Assert.Equal(e.GetProperty("serviceCount").GetInt32(), s.Services.Count);
        Assert.Equal(e.Strings("capabilityTypes"), s.Capabilities.SelectMany(c => c.Types));
        JsonElement custom = e.GetProperty("customService");
        Service sharing = s.GetService(custom.Str("type"))!;
        Assert.Equal(custom.Str("id"), sharing.Id!.AbsoluteUri);
        Assert.Equal(custom.Str("serviceEndpoint"), sharing.ServiceEndpoint.AbsoluteUri);
        Assert.Equal([Lws.AccessProfile], s.AccessGrantService.ConformsTo);
        Assert.NotNull(s.GetCapability("https://feature.example/PatchSupport")?.GetProperty("format"));
        Assert.Single(s.GetServices(Lws.ServiceType.StorageRoot));

        JsonElement invalid = f.GetProperty("invalid");
        Assert.Throws<ProtocolException>(() => StorageDescription.Parse(invalid.GetProperty("notStorage"), new Uri(f.Str("url"))));
        StorageDescription noRoot = StorageDescription.Parse(invalid.GetProperty("noRoot"), new Uri(f.Str("url")));
        Assert.Throws<ProtocolException>(() => noRoot.GetStorageRoot());
    }

    [Fact]
    public void WebhookStorageDescriptionKeys()
    {
        StorageDescription s = StorageDescription.Parse(Fixtures.Load("webhook/storage-description.json"), new Uri("https://storage.example/"));
        Assert.Equal(3, s.VerificationMethods.Count);
        VerificationMethod p256 = s.FindVerificationMethod("https://storage.example/#key-p256")!;
        VerificationMethod ed = s.FindVerificationMethod("https://storage.example/#key-ed25519")!;
        Assert.Equal("#key-ed25519", ed.Id);
        Assert.Same(ed, s.FindVerificationMethod("key-ed25519"));
        Assert.Same(ed, s.FindVerificationMethod("#key-ed25519"));
        Assert.True(s.IsAuthenticationMethod(p256));
        Assert.True(s.IsAuthenticationMethod(ed));
        Assert.False(s.IsAuthenticationMethod(s.FindVerificationMethod("#key-unlisted")!));
        Assert.Null(s.FindVerificationMethod("#nope"));
        Assert.Equal("JsonWebKey", p256.Type);
        Assert.Equal("https://storage.example/", p256.Controller);
        Assert.Equal("EC", p256.PublicKeyJwk!.Value.Str("kty"));
    }

    [Fact]
    public void LinksetFixture()
    {
        JsonElement f = Fixtures.Load("responses/linkset.json");
        var metadata = new ResourceMetadata(new Uri(f.Str("url")), 200, HeadersOf(f.GetProperty("headers")));
        Linkset ls = Linkset.Parse(f.GetProperty("body"));
        var doc = new LinksetDocument(metadata.Url, ls, metadata);
        JsonElement e = f.GetProperty("expected");
        Assert.Equal(e.Str("url"), doc.Url.AbsoluteUri);
        Assert.Equal(e.Str("etag"), doc.ETag);
        Assert.Equal(e.Strings("allow"), doc.Allow);
        Assert.Equal(e.Strings("acceptPatch"), doc.AcceptPatch);
        Assert.True(doc.SupportsPut);
        Assert.Equal(e.GetProperty("contexts").GetInt32(), ls.Contexts.Count);
        Assert.Equal(e.Str("anchor"), ls.Contexts[0].Anchor);
        Assert.Equal(e.GetProperty("linkCount").GetInt32(), ls.GetLinks().Count);
        foreach (JsonProperty t in e.GetProperty("targets").EnumerateObject())
        {
            Assert.Equal(t.Value.EnumerateArray().Select(x => x.GetString()), ls.GetTargets(t.Name).Select(x => x.Href));
            Assert.Equal(t.Value.EnumerateArray().Select(x => x.GetString()), ls.GetTargets(e.Str("anchor"), t.Name).Select(x => x.Href));
        }
        JsonElement add = e.GetProperty("afterAdd");
        JsonElement op = add.GetProperty("operation");
        Linkset added = ls.Add(op.Str("anchor"), op.Str("rel"), op.Str("href"));
        Assert.Equal(add.Strings("licenseTargets"), added.GetTargets("license").Select(x => x.Href));
        Assert.Single(ls.GetTargets("license"));
        Assert.True(Fixtures.JsonEquals(f.GetProperty("body"), ls.ToJson().ToElement()), "round trip");
        Assert.True(Fixtures.JsonEquals(f.GetProperty("body"), Linkset.Parse(ls.ToString()).ToJson().ToElement()));

        Link describedBy = ls.GetLinks().First(l => l.Rel == "describedby");
        Assert.Equal("https://storage.example/schemas/personal-info.json", describedBy.Href.AbsoluteUri);
        Assert.Equal("application/schema+json", describedBy.Type);
        Assert.Equal(e.Str("anchor"), describedBy.Anchor);
        Assert.Equal("Bob", ls.GetTargets("https://example.org/rel/reviewer")[0].GetAttribute("title"));

        Linkset removed = ls.Remove(e.Str("anchor"), "https://example.org/rel/reviewer", "https://id.example/bob");
        Assert.Equal(["https://id.example/carol"], removed.GetTargets("https://example.org/rel/reviewer").Select(x => x.Href));
        Assert.Empty(ls.Remove(e.Str("anchor"), "license").GetTargets("license"));
        Linkset fresh = Linkset.Empty.Add("https://a.example/x", "describedby", "https://a.example/shape",
            new Dictionary<string, JsonNode?> { ["type"] = "text/turtle" });
        Assert.Equal("{\"linkset\":[{\"anchor\":\"https://a.example/x\",\"describedby\":[{\"href\":\"https://a.example/shape\",\"type\":\"text/turtle\"}]}]}", fresh.ToString());
        Assert.Throws<ProtocolException>(() => Linkset.Parse(Fixtures.Parse("{\"linkset\":\"not a list\"}")));
        Assert.Throws<ProtocolException>(() => Linkset.Parse(Fixtures.Parse("{\"linkset\":[1]}")));
    }

    [Fact]
    public void NotificationFixture()
    {
        JsonElement f = Fixtures.Load("responses/notification.json");
        Notification single = Notification.Parse(f.GetProperty("single"));
        AssertNotification(f.GetProperty("singleExpected"), single);
        Notification batch = Notification.Parse(Encoding.UTF8.GetBytes(f.GetProperty("batch").GetRawText()));
        AssertNotification(f.GetProperty("batchExpected"), batch);
        Assert.Throws<ProtocolException>(() => Notification.Parse(f.GetProperty("invalid")));
        Assert.Throws<ProtocolException>(() => Notification.Parse("{\"type\":\"Notification\",\"storage\":\"https://s.example/\"}"));
        Assert.Throws<ProtocolException>(() => Notification.Parse("not json"));
    }

    private static void AssertNotification(JsonElement expected, Notification n)
    {
        Assert.Equal(expected.Str("storage"), n.Storage.AbsoluteUri);
        var activities = expected.Arr("activities").ToList();
        Assert.Equal(activities.Count, n.Activities.Count);
        for (int i = 0; i < activities.Count; i++)
        {
            JsonElement x = activities[i];
            Activity a = n.Activities[i];
            Assert.Equal(x.Str("id"), a.Id);
            Assert.Equal(x.Strings("types"), a.Types);
            Assert.Equal(x.Str("objectId"), a.Object.Id.AbsoluteUri);
            if (x.TryGetProperty("objectTypes", out _)) Assert.Equal(x.Strings("objectTypes"), a.Object.Types);
            if (x.OptStr("origin") is { } origin) Assert.Equal(origin, a.Origin?.AbsoluteUri);
            if (x.OptStr("actor") is { } actor) Assert.Equal(actor, a.Actor?.AbsoluteUri);
            if (x.OptStr("target") is { } target) Assert.Equal(target, a.Target?.AbsoluteUri);
            if (x.OptStr("published") is { } published)
            {
                Assert.Equal(published, a.PublishedRaw);
                Assert.Equal(DateTimeOffset.Parse(published, System.Globalization.CultureInfo.InvariantCulture), a.Published);
            }
            if (x.TryGetProperty("isCreate", out _)) Assert.True(a.IsCreate);
            if (x.TryGetProperty("isUpdate", out _)) Assert.True(a.IsUpdate);
            if (x.TryGetProperty("isDelete", out _)) Assert.True(a.IsDelete);
            Assert.True(a.Object.IsDataResource);
        }
    }

    [Fact]
    public void SubscriptionFixture()
    {
        JsonElement f = Fixtures.Load("responses/subscription.json");
        JsonElement input = f.GetProperty("input");
        var request = new WebhookSubscriptionRequest(new Uri(input.Str("inbox")), input.Strings("topics").Select(t => new Uri(t)),
            DateTimeOffset.Parse(input.Str("expires"), System.Globalization.CultureInfo.InvariantCulture));
        Assert.True(Fixtures.JsonEquals(f.GetProperty("expectedRequestBody"), request.ToJson().ToElement()), request.ToJson().ToJsonString());
        JsonElement response = f.GetProperty("response");
        Subscription s = Subscription.Parse(response.GetProperty("body"), new Uri("https://notification.example/"), null);
        JsonElement e = f.GetProperty("expected");
        Assert.Equal(e.Str("type"), s.Type);
        Assert.Equal(e.Str("subscription"), s.Url.AbsoluteUri);
        Assert.Equal(e.Str("expires"), s.ExpiresRaw);
        Assert.Equal(DateTimeOffset.Parse(e.Str("expires"), System.Globalization.CultureInfo.InvariantCulture), s.Expires);
        Assert.Throws<ArgumentException>(() => new WebhookSubscriptionRequest(new Uri("https://r.example/"), []));
        Subscription fallback = Subscription.Parse(Fixtures.Parse("{\"type\":\"WebhookSubscription\"}"), null, new Uri("https://n.example/s/1"));
        Assert.Equal("https://n.example/s/1", fallback.Url.AbsoluteUri);
        Assert.Throws<ProtocolException>(() => Subscription.Parse(Fixtures.Parse("{}"), null, null));
    }

    [Fact]
    public void TypeIndexAndSearchFixtures()
    {
        JsonElement f = Fixtures.Load("responses/type-index.json");
        JsonElement index = f.GetProperty("typeIndex");
        var md = new ResourceMetadata(new Uri(index.Str("url")), 200, HeadersOf(index.GetProperty("headers")));
        TypeIndexPage page = TypeIndexPage.Parse(index.GetProperty("body"), md);
        JsonElement ie = index.GetProperty("expected");
        Assert.Equal(ie.GetProperty("totalItems").GetInt64(), page.TotalItems);
        Assert.Equal(ie.Strings("types"), page.Types);
        Assert.Equal(ie.Str("next"), page.Next?.AbsoluteUri);
        Assert.Equal("https://example.org/types/index?page=1", page.First?.AbsoluteUri);
        Assert.Equal("https://example.org/types/index?page=4", page.Last?.AbsoluteUri);

        JsonElement search = f.GetProperty("search");
        var smd = new ResourceMetadata(new Uri(search.Str("url")), 200, HeadersOf(search.GetProperty("headers")));
        ContainerPage results = ContainerPage.Parse(search.GetProperty("body"), smd);
        JsonElement se = search.GetProperty("expected");
        Assert.Equal(se.GetProperty("totalItems").GetInt64(), results.TotalItems);
        Assert.Equal(se.Strings("ids"), results.Items.Select(i => i.Id.AbsoluteUri));
        Assert.Equal(se.Str("next"), results.Next?.AbsoluteUri);
        Assert.Equal(search.Str("url"), results.Id.AbsoluteUri);
        Assert.True(results.HasType("ContainerPage"));
        Assert.True(results.Items[0].HasType("https://schema.org/Person"));
    }

    [Fact]
    public void AccessFixture()
    {
        JsonElement f = Fixtures.Load("responses/access.json");
        AccessRequest request = AccessRequest.Parse(f.GetProperty("request"));
        Assert.Equal("https://storage.example/", request.Storage.AbsoluteUri);
        Assert.Equal("https://id.example/agent/inbox/", request.Inbox?.AbsoluteUri);
        AccessPolicy policy = Assert.Single(request.Access);
        Assert.Equal(["read", "create"], policy.Actions);
        Assert.Equal("https://id.example/agent", policy.Assignee);
        Assert.Equal("StorageResource", policy.Target!.Type);
        Assert.Equal(["https://storage.example/root/projects/"], policy.Target.Values);
        Assert.Equal(2, policy.Constraints.Count);
        Assert.Equal("purpose", policy.Constraints[0].LeftOperand);
        Assert.Equal("lteq", policy.Constraints[1].Operator);
        Assert.True(Fixtures.JsonEquals(f.GetProperty("request"), request.Raw!.Value));
        Assert.True(Fixtures.JsonEquals(f.GetProperty("request"), request.ToJson().ToElement()));

        AccessGrant grant = AccessGrant.Parse(f.GetProperty("grant"));
        Assert.Equal(["image/jpeg", "image/png"], grant.Access[0].Constraints[0].RightOperand.EnumerateArray().Select(x => x.GetString()));
        Assert.True(Fixtures.JsonEquals(f.GetProperty("grant"), grant.ToJson().ToElement()));
        Assert.Throws<ProtocolException>(() => AccessGrant.Parse(f.GetProperty("request")));
        Assert.Throws<ProtocolException>(() => AccessRequest.Parse(f.GetProperty("grant")));

        // The builder expectation: the same request built from parts.
        var built = new AccessRequest(new Uri("https://storage.example/"),
            [new AccessPolicy(["read", "create"], "https://id.example/agent", AccessTarget.StorageResources(new Uri("https://storage.example/root/projects/")),
                [Constraint.Purpose(new Uri("https://purpose.example/collaboration")), Constraint.NotAfter(DateTimeOffset.Parse("2026-06-09T10:00:00Z", System.Globalization.CultureInfo.InvariantCulture))])],
            new Uri("https://id.example/agent/inbox/"));
        Assert.True(Fixtures.JsonEquals(f.GetProperty("request"), built.ToJson().ToElement()), built.ToJson().ToJsonString());
        Assert.Null(built.Raw);

        AccessGrant approving = AccessGrant.Approving(built);
        Assert.Equal(["AccessGrant"], approving.Types);
        Assert.Equal(built.Access, approving.Access);

        // Builders validate the required fields.
        Assert.Throws<ArgumentException>(() => new AccessPolicy([], "https://id.example/agent"));
        Assert.Throws<ArgumentException>(() => new AccessPolicy(["read"], "agent"));
        Assert.Throws<ArgumentException>(() => new AccessRequest(new Uri("https://s.example/"), []));
        Assert.Throws<ArgumentNullException>(() => new AccessGrant(null!, [policy]));
        Assert.Throws<ArgumentException>(() => new AccessTarget("Container", []));
        Assert.Throws<ProtocolException>(() => AccessRequest.Parse(Fixtures.Parse("{\"type\":\"AccessRequest\",\"storage\":\"https://s.example/\",\"access\":[]}")));
        Assert.Throws<ProtocolException>(() => AccessRequest.Parse(Fixtures.Parse("{\"type\":\"AccessRequest\",\"access\":[{}]}")));
    }

    [Fact]
    public void ConstraintFactories()
    {
        string Json(Constraint c) => $"{c.LeftOperand} {c.Operator} {c.RightOperand.GetRawText()}";
        Assert.Equal("purpose eq \"https://p.example/x\"", Json(Constraint.Purpose(new Uri("https://p.example/x"))));
        Assert.Equal("purpose isAnyOf [\"https://p.example/a\",\"https://p.example/b\"]",
            Json(Constraint.PurposeAnyOf([new Uri("https://p.example/a"), new Uri("https://p.example/b")])));
        Assert.Equal("client eq \"https://app.example/id\"", Json(Constraint.Client(new Uri("https://app.example/id"))));
        Assert.Equal("format eq \"image/png\"", Json(Constraint.Format("image/png")));
        Assert.Equal("format isAnyOf [\"image/png\",\"image/jpeg\"]", Json(Constraint.FormatAnyOf(["image/png", "image/jpeg"])));
        Assert.Equal("type eq \"https://schema.org/Person\"", Json(Constraint.Type(new Uri("https://schema.org/Person"))));
        Assert.Equal("type isAnyOf [\"https://schema.org/Person\"]", Json(Constraint.TypeAnyOf([new Uri("https://schema.org/Person")])));
        Assert.Equal("dateTime gteq \"2026-01-02T03:04:05Z\"", Json(Constraint.NotBefore(new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero))));
        Assert.Equal("dateTime lteq \"2026-01-02T03:04:05.5Z\"", Json(Constraint.NotAfter(new DateTimeOffset(2026, 1, 2, 4, 4, 5, 500, TimeSpan.FromHours(1)))));
        Assert.Equal("StorageResource", AccessTarget.StorageResources(new Uri("https://s.example/a")).Type);
        Assert.Equal("Container", AccessTarget.Containers(new Uri("https://s.example/a/")).Type);
        Assert.Equal("DataResource", AccessTarget.DataResources(new Uri("https://s.example/a")).Type);
    }

    [Fact]
    public void OAuthFixture()
    {
        JsonElement f = Fixtures.Load("responses/oauth.json");
        AuthorizationServerMetadata md = AuthorizationServerMetadata.Parse(f.GetProperty("metadata"), new Uri("https://authorization.example/.well-known/lws-configuration"));
        Assert.Equal("https://authorization.example", md.Issuer);
        Assert.Equal("https://authorization.example/token", md.TokenEndpoint.AbsoluteUri);
        Assert.Equal("https://authorization.example/jwks", md.JwksUri?.AbsoluteUri);
        Assert.True(md.SupportsSubjectTokenType(Lws.TokenType.Jwt));
        Assert.True(md.SupportsSubjectTokenType(Lws.TokenType.IdToken));
        Assert.False(md.SupportsSubjectTokenType(Lws.TokenType.Saml2));
        Assert.Equal([Lws.GrantTypeTokenExchange], md.GrantTypesSupported);
        Assert.Equal(["did:web", "did:key", "https"], md.SubjectIdentifierTypesSupported);

        foreach (JsonElement c in f.Arr("metadataUrls"))
        {
            Assert.Equal(c.Str("url"), AuthorizationServerMetadata.MetadataUrl(new Uri(c.Str("issuer"))).AbsoluteUri);
        }

        var now = DateTimeOffset.FromUnixTimeSeconds(1_735_000_000);
        AccessToken t = AccessToken.FromTokenResponse(f.GetProperty("tokenResponse").GetProperty("body"), now);
        Assert.Equal(now.AddSeconds(f.GetProperty("tokenResponse").GetProperty("expectedExpiresIn").GetInt32()), t.ExpiresAt);
        AccessToken noExpiry = AccessToken.FromTokenResponse(f.GetProperty("tokenResponseNoExpiry").GetProperty("body"), now);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(f.GetProperty("tokenResponseNoExpiry").GetProperty("expectedExp").GetInt64()), noExpiry.ExpiresAt);
        AccessToken opaque = AccessToken.FromTokenResponse(Fixtures.Parse("{\"access_token\":\"opaque\",\"token_type\":\"Bearer\"}"), now);
        Assert.Equal(now + AccessToken.DefaultLifetime, opaque.ExpiresAt);
        Assert.Throws<AuthenticationException>(() => AccessToken.FromTokenResponse(Fixtures.Parse("{\"access_token\":\"x\",\"token_type\":\"DPoP\"}"), now));
        Assert.Throws<AuthenticationException>(() => AccessToken.FromTokenResponse(Fixtures.Parse("{\"token_type\":\"Bearer\"}"), now));
        Assert.True(t.IsValid(now, TimeSpan.FromSeconds(30)));
        Assert.False(t.IsValid(now.AddSeconds(3580), TimeSpan.FromSeconds(30)));

        foreach (JsonElement c in f.Arr("realmChecks"))
        {
            Assert.Equal(c.GetProperty("contained").GetBoolean(), Uris.Contains(new Uri(c.Str("realm")), new Uri(c.Str("url"))));
        }
    }

    [Fact]
    public void EveryFixtureFileIsCovered()
    {
        string[] covered =
        [
            "did-key.json", "json-patch.json", "jwt.json", "link-headers.json", "structured-fields.json", "type-queries.json",
            "www-authenticate.json", "keys/ed25519.json", "keys/p256.json", "keys/p256-unlisted.json",
            "responses/access.json", "responses/container-page.json", "responses/linkset.json", "responses/notification.json",
            "responses/oauth.json", "responses/problem-details.json", "responses/storage-description.json", "responses/subscription.json",
            "responses/type-index.json", "webhook/index.json", "webhook/storage-description.json",
            .. Fixtures.Load("webhook/index.json").Strings("vectors").Select(v => "webhook/" + v),
        ];
        Assert.Equal(covered.Order(StringComparer.Ordinal), Fixtures.All());
        Assert.Equal(13, Fixtures.Load("webhook/index.json").Strings("vectors").Count);
    }
}
