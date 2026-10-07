// SPDX-License-Identifier: MIT
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ebremer.Lws.Auth;
using Ebremer.Lws.Http;
using Ebremer.Lws.Notifications;
using Ebremer.Lws.Tests.Support;

namespace Ebremer.Lws.Tests;

/// <summary>The shared cryptographic fixtures: did:key, JWT credentials, test keys and the RFC 9421 webhook vectors.</summary>
public sealed class CryptoFixtureTests
{
    public static TheoryData<string> DidKeyVectors() => [.. Fixtures.Load("did-key.json").Arr("vectors").Select(v => v.Str("name"))];

    [Theory]
    [MemberData(nameof(DidKeyVectors))]
    public void DidKeyDerivation(string name)
    {
        JsonElement v = Fixtures.Load("did-key.json").Arr("vectors").Single(x => x.Str("name") == name);
        VerificationKey key = VerificationKey.FromJwk(v.GetProperty("publicJwk"));
        Assert.Equal(v.Str("did"), DidKey.FromPublicKey(key));
        Assert.Equal(v.Str("kid"), DidKey.KeyId(key));
        Assert.Equal(v.Str("kid"), DidKey.KeyId(v.Str("did")));
        Assert.Equal(v.Str("did"), DidKey.FromJwk(v.GetProperty("publicJwk")));
        VerificationKey decoded = DidKey.ToPublicKey(v.Str("kid"));
        Assert.True(Fixtures.JsonEquals(Fixtures.ToElement(key.ToJwk()), Fixtures.ToElement(decoded.ToJwk())));
    }

    public static TheoryData<string> JwtVectors() => [.. Fixtures.Load("jwt.json").Arr("vectors").Select(v => v.Str("name"))];

    [Theory]
    [MemberData(nameof(JwtVectors))]
    public void JwtCredentialsVerify(string name)
    {
        JsonElement v = Fixtures.Load("jwt.json").Arr("vectors").Single(x => x.Str("name") == name);
        VerificationKey key = VerificationKey.FromJwk(v.GetProperty("publicJwk"));
        string jwt = v.Str("jwt");
        Assert.True(Jwt.Verify(jwt, key));
        Assert.True(Fixtures.JsonEquals(v.GetProperty("header"), Jwt.DecodeHeader(jwt)));
        Assert.True(Fixtures.JsonEquals(v.GetProperty("claims"), Jwt.DecodeClaims(jwt)));
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(v.GetProperty("claims").GetProperty("exp").GetInt64()), Jwt.Expiration(jwt));
        string tampered = jwt[..^4] + (jwt[^4] == 'A' ? "B" : "A") + jwt[^3..];
        Assert.False(Jwt.Verify(tampered, key));
        // The kid in the header is the did:key of the key, so the signing key is implied by the token.
        Assert.Equal(v.GetProperty("header").Str("kid"), DidKey.KeyId(key));
    }

    public static TheoryData<string> TestKeys() => ["keys/p256.json", "keys/ed25519.json", "keys/p256-unlisted.json"];

    [Theory]
    [MemberData(nameof(TestKeys))]
    public void TestKeysImportAndSign(string file)
    {
        JsonElement f = Fixtures.Load(file);
        SigningKey key = SigningKey.FromJwk(f.GetProperty("privateJwk"));
        Assert.True(Fixtures.JsonEquals(f.GetProperty("publicJwk"), Fixtures.ToElement(key.PublicKey.ToJwk())));
        Assert.True(Fixtures.JsonEquals(f.GetProperty("privateJwk"), Fixtures.ToElement(key.ToJwk())));
        byte[] data = Encoding.UTF8.GetBytes("signature input");
        byte[] signature = key.Sign(data);
        Assert.Equal(64, signature.Length);
        VerificationKey pub = VerificationKey.FromJwk(f.GetProperty("publicJwk"));
        Assert.True(pub.Verify(data, signature));
        Assert.False(pub.Verify(Encoding.UTF8.GetBytes("other input"), signature));
        Assert.Throws<ArgumentException>(() => SigningKey.FromJwk(f.GetProperty("publicJwk")));
    }

    public static TheoryData<string> WebhookVectors() => [.. Fixtures.Load("webhook/index.json").Strings("vectors")];

    [Theory]
    [MemberData(nameof(WebhookVectors))]
    public async Task WebhookVector(string file)
    {
        JsonElement v = Fixtures.Load("webhook/" + file);
        StorageDescription description = StorageDescription.Parse(Fixtures.Load("webhook/storage-description.json"), new Uri("https://storage.example/"));
        var clock = new FakeClock(DateTimeOffset.FromUnixTimeSeconds(v.GetProperty("now").GetInt64()));
        int fetches = 0;
        using var verifier = new WebhookVerifier(new WebhookVerifierOptions
        {
            StorageDescriptionResolver = (uri, _) =>
            {
                fetches++;
                Assert.Equal("https://storage.example/", uri.AbsoluteUri);
                return Task.FromResult(description);
            },
            TimeProvider = clock,
        });
        HeaderMap headers = HeaderMap.From(v.GetProperty("headers").EnumerateObject().Select(p => new KeyValuePair<string, string>(p.Name, p.Value.GetString()!)));
        byte[] body = Encoding.UTF8.GetBytes(v.Str("body"));
        JsonElement expected = v.GetProperty("expected");

        if (v.TryGetProperty("signatureBase", out JsonElement signatureBase))
        {
            var covered = (SfInnerList)StructuredFields.ParseDictionary(headers.GetFirst("signature-input")!)["sig1"];
            Assert.Equal(signatureBase.GetString(), WebhookVerifier.SignatureBase(v.Str("method"), new Uri(v.Str("url")), headers, covered));
        }

        if (!expected.GetProperty("valid").GetBoolean())
        {
            await Assert.ThrowsAsync<SignatureVerificationException>(() => verifier.VerifyAsync(v.Str("method"), new Uri(v.Str("url")), headers, body, Ct));
            return;
        }
        VerifiedNotification verified = await verifier.VerifyAsync(v.Str("method"), new Uri(v.Str("url")), headers, body, Ct);
        Assert.Equal(expected.Str("keyid"), verified.KeyId);
        Assert.Equal("https://storage.example/", verified.Storage.AbsoluteUri);
        JsonElement n = expected.GetProperty("notification");
        Assert.Equal(n.Str("storage"), verified.Notification.Storage.AbsoluteUri);
        var activities = n.Arr("activities").ToList();
        Assert.Equal(activities.Count, verified.Notification.Activities.Count);
        for (int i = 0; i < activities.Count; i++)
        {
            Activity a = verified.Notification.Activities[i];
            Assert.Equal(activities[i].Strings("types"), a.Types);
            Assert.Equal(activities[i].Str("objectId"), a.Object.Id.AbsoluteUri);
            Assert.Equal(activities[i].OptStr("target"), a.Target?.AbsoluteUri);
        }
        Assert.Equal(1, fetches);

        // The description is cached: a second delivery does not fetch it again.
        await verifier.VerifyAsync(v.Str("method"), new Uri(v.Str("url")), headers, body, Ct);
        Assert.Equal(1, fetches);
    }

    [Fact]
    public async Task WebhookTrustedStoragesAreEnforcedEvenWhenEmpty()
    {
        JsonElement v = Fixtures.Load("webhook/p256-valid.json");
        StorageDescription description = StorageDescription.Parse(Fixtures.Load("webhook/storage-description.json"), new Uri("https://storage.example/"));
        HeaderMap headers = HeaderMap.From(v.GetProperty("headers").EnumerateObject().Select(p => new KeyValuePair<string, string>(p.Name, p.Value.GetString()!)));
        byte[] body = Encoding.UTF8.GetBytes(v.Str("body"));
        var clock = new FakeClock(DateTimeOffset.FromUnixTimeSeconds(v.GetProperty("now").GetInt64()));
        WebhookVerifier Make(IReadOnlyCollection<Uri>? trusted) => new(new WebhookVerifierOptions
        {
            StorageDescriptionResolver = (_, _) => Task.FromResult(description),
            TimeProvider = clock,
            TrustedStorages = trusted,
        });

        using (WebhookVerifier empty = Make([]))
        {
            await Assert.ThrowsAsync<SignatureVerificationException>(() => empty.VerifyAsync("POST", new Uri(v.Str("url")), headers, body, Ct));
        }
        using (WebhookVerifier other = Make([new Uri("https://other.example/")]))
        {
            await Assert.ThrowsAsync<SignatureVerificationException>(() => other.VerifyAsync("POST", new Uri(v.Str("url")), headers, body, Ct));
        }
        // Compared as URLs: case and the default port do not matter.
        using (WebhookVerifier same = Make([new Uri("HTTPS://Storage.Example:443/")]))
        {
            VerifiedNotification ok = await same.VerifyAsync("POST", new Uri(v.Str("url")), headers, body, Ct);
            Assert.Equal("https://storage.example/", ok.Storage.AbsoluteUri);
        }
        using (WebhookVerifier none = Make(null))
        {
            await none.VerifyAsync("POST", new Uri(v.Str("url")), headers, body, Ct);
        }
    }

    [Fact]
    public async Task WebhookKeyRotationRefetchesOnce()
    {
        JsonElement v = Fixtures.Load("webhook/p256-valid.json");
        JsonElement current = Fixtures.Load("webhook/storage-description.json");
        // A stale description whose key-p256 is the unlisted key (as if the storage rotated keys since).
        var stale = (JsonObject)JsonNode.Parse(current.GetRawText())!;
        stale["verificationMethod"]![0]!["publicKeyJwk"] = JsonNode.Parse(Fixtures.Load("keys/p256-unlisted.json").GetProperty("publicJwk").GetRawText());
        var descriptions = new Queue<StorageDescription>([
            StorageDescription.Parse(stale.ToElement(), new Uri("https://storage.example/")),
            StorageDescription.Parse(current, new Uri("https://storage.example/")),
        ]);
        var clock = new FakeClock(DateTimeOffset.FromUnixTimeSeconds(v.GetProperty("now").GetInt64()));
        HeaderMap headers = HeaderMap.From(v.GetProperty("headers").EnumerateObject().Select(p => new KeyValuePair<string, string>(p.Name, p.Value.GetString()!)));
        byte[] body = Encoding.UTF8.GetBytes(v.Str("body"));
        int fetches = 0;
        using var verifier = new WebhookVerifier(new WebhookVerifierOptions
        {
            StorageDescriptionResolver = (_, _) =>
            {
                fetches++;
                return Task.FromResult(descriptions.Count > 1 ? descriptions.Dequeue() : descriptions.Peek());
            },
            TimeProvider = clock,
        });
        // First fetch is stale and not cached yet: the failure is final.
        await Assert.ThrowsAsync<SignatureVerificationException>(() => verifier.VerifyAsync("POST", new Uri(v.Str("url")), headers, body, Ct));
        Assert.Equal(1, fetches);
        // Now the stale description is cached; verification fails with it, refetches once, and succeeds.
        descriptions = new Queue<StorageDescription>([StorageDescription.Parse(current, new Uri("https://storage.example/"))]);
        await verifier.VerifyAsync("POST", new Uri(v.Str("url")), headers, body, Ct);
        Assert.Equal(2, fetches);
    }
}
