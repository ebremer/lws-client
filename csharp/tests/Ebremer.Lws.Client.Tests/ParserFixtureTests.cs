// SPDX-License-Identifier: MIT
using System.Text.Json;
using Ebremer.Lws.Http;
using Ebremer.Lws.Tests.Support;

namespace Ebremer.Lws.Tests;

/// <summary>The shared parser fixtures: Link, WWW-Authenticate, structured fields, JSON Patch / Pointer, type queries.</summary>
public sealed class ParserFixtureTests
{
    public static TheoryData<string> LinkCases() => [.. Fixtures.Load("link-headers.json").Arr("cases").Select(c => c.Str("name"))];

    [Theory]
    [MemberData(nameof(LinkCases))]
    public void LinkHeaders(string name)
    {
        JsonElement c = Fixtures.Load("link-headers.json").Arr("cases").Single(x => x.Str("name") == name);
        IReadOnlyList<Link> links = LinkHeader.Parse(c.Strings("headers"), new Uri(c.Str("base")));
        var expected = c.Arr("expected").ToList();
        Assert.Equal(expected.Count, links.Count);
        for (int i = 0; i < expected.Count; i++)
        {
            Assert.Equal(expected[i].Str("href"), links[i].Href.AbsoluteUri);
            Assert.Equal(expected[i].Str("rel"), links[i].Rel);
            var parameters = expected[i].GetProperty("params").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString());
            Assert.Equal(parameters, links[i].Parameters.ToDictionary(p => p.Key, p => (string?)p.Value));
        }
    }

    [Fact]
    public void LinkFormatEscapesAndRoundTrips()
    {
        var link = new Link(new Uri("https://example.org/c"), "related").WithParameter("title", "say \"hi\" \\ bye").WithParameter("crossorigin", "");
        string formatted = LinkHeader.Format(link);
        Assert.Equal("<https://example.org/c>; rel=\"related\"; title=\"say \\\"hi\\\" \\\\ bye\"; crossorigin", formatted);
        Link back = Assert.Single(LinkHeader.Parse(formatted, null));
        Assert.Equal(link, back);
        Assert.Equal("<https://www.w3.org/ns/lws#Container>; rel=\"type\"", Link.ForType(Lws.Types.Container).ToHeaderValue());
        Assert.Equal("<a>; rel=\"up\", <b>; rel=\"next\"", LinkHeader.Format([new Link("a", "up"), new Link("b", "next")]));
    }

    public static TheoryData<string> ChallengeCases() => [.. Fixtures.Load("www-authenticate.json").Arr("cases").Select(c => c.Str("name"))];

    [Theory]
    [MemberData(nameof(ChallengeCases))]
    public void WwwAuthenticateChallenges(string name)
    {
        JsonElement c = Fixtures.Load("www-authenticate.json").Arr("cases").Single(x => x.Str("name") == name);
        IReadOnlyList<AuthChallenge> challenges = WwwAuthenticate.Parse(c.Strings("headers"));
        var expected = c.Arr("expected").ToList();
        Assert.Equal(expected.Count, challenges.Count);
        for (int i = 0; i < expected.Count; i++)
        {
            Assert.True(challenges[i].IsScheme(expected[i].Str("scheme")));
            Assert.Equal(expected[i].OptStr("token68"), challenges[i].Token68);
            var parameters = expected[i].GetProperty("params").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString());
            Assert.Equal(parameters, challenges[i].Parameters.ToDictionary(p => p.Key, p => (string?)p.Value));
        }
    }

    [Fact]
    public void ChallengeAccessors()
    {
        AuthChallenge c = WwwAuthenticate.Parse("Bearer as_uri=\"https://as.example\", realm=\"https://s.example/\", error=\"invalid_token\", error_description=\"expired\"").Single();
        Assert.Equal("https://as.example", c.AsUri);
        Assert.Equal("https://s.example/", c.Realm);
        Assert.Equal("invalid_token", c.Error);
        Assert.Equal("expired", c.ErrorDescription);
        Assert.Empty(WwwAuthenticate.Parse((string?)null));
        Assert.Empty(WwwAuthenticate.Parse(""));
    }

    public static TheoryData<string> StructuredFieldCases() => [.. Fixtures.Load("structured-fields.json").Arr("cases").Select(c => c.Str("name"))];

    [Theory]
    [MemberData(nameof(StructuredFieldCases))]
    public void StructuredFieldDictionaries(string name)
    {
        JsonElement c = Fixtures.Load("structured-fields.json").Arr("cases").Single(x => x.Str("name") == name);
        if (c.TryGetProperty("error", out JsonElement err) && err.GetBoolean())
        {
            Assert.Throws<StructuredFieldFormatException>(() => StructuredFields.ParseDictionary(c.Str("input")));
            return;
        }
        IReadOnlyDictionary<string, SfMember> dict = StructuredFields.ParseDictionary(c.Str("input"));
        var expected = c.GetProperty("expected").EnumerateObject().ToList();
        Assert.Equal(expected.Select(e => e.Name), dict.Keys);
        foreach (JsonProperty e in expected)
        {
            SfMember member = dict[e.Name];
            if (e.Value.TryGetProperty("innerList", out JsonElement items))
            {
                SfInnerList list = Assert.IsType<SfInnerList>(member);
                var expectedItems = items.EnumerateArray().ToList();
                Assert.Equal(expectedItems.Count, list.Items.Count);
                for (int i = 0; i < expectedItems.Count; i++)
                {
                    AssertBareItem(expectedItems[i].GetProperty("item"), list.Items[i].Value);
                    AssertParameters(expectedItems[i].GetProperty("params"), list.Items[i].Parameters);
                }
            }
            else
            {
                SfItem item = Assert.IsType<SfItem>(member);
                AssertBareItem(e.Value.GetProperty("item"), item.Value);
            }
            AssertParameters(e.Value.GetProperty("params"), member.Parameters);
        }
        if (c.TryGetProperty("serialized", out JsonElement serialized))
        {
            foreach (JsonProperty s in serialized.EnumerateObject()) Assert.Equal(s.Value.GetString(), StructuredFields.Serialize(dict[s.Name]));
        }
    }

    private static void AssertParameters(JsonElement expected, IReadOnlyDictionary<string, object> actual)
    {
        var e = expected.EnumerateObject().ToList();
        Assert.Equal(e.Select(p => p.Name), actual.Keys);
        foreach (JsonProperty p in e) AssertBareItem(p.Value, actual[p.Name]);
    }

    private static void AssertBareItem(JsonElement expected, object actual)
    {
        JsonProperty typed = expected.EnumerateObject().Single();
        switch (typed.Name)
        {
            case "string":
                Assert.Equal(typed.Value.GetString(), Assert.IsType<string>(actual));
                break;
            case "token":
                Assert.Equal(typed.Value.GetString(), Assert.IsType<SfToken>(actual).Value);
                break;
            case "integer":
                Assert.Equal(typed.Value.GetInt64(), Assert.IsType<long>(actual));
                break;
            case "decimal":
                Assert.Equal(typed.Value.GetDecimal(), Assert.IsType<decimal>(actual));
                break;
            case "boolean":
                Assert.Equal(typed.Value.GetBoolean(), Assert.IsType<bool>(actual));
                break;
            case "bytes":
                Assert.Equal(Convert.FromBase64String(typed.Value.GetString()!), Assert.IsType<SfByteSequence>(actual).ToArray());
                break;
            default:
                Assert.Fail("unknown typed value " + typed.Name);
                break;
        }
    }

    [Fact]
    public void StructuredFieldSerialization()
    {
        IReadOnlyDictionary<string, SfMember> d = StructuredFields.ParseDictionary("a=?1, b=?0, c, d=tok/en, e=42, f=-3.5, g=\"str \\\"q\\\"\";p=1;q, h=:AAEC:");
        Assert.Equal("a, b=?0, c, d=tok/en, e=42, f=-3.5, g=\"str \\\"q\\\"\";p=1;q, h=:AAEC:", StructuredFields.SerializeDictionary(d));
        Assert.Equal("1.0", StructuredFields.SerializeBareItem(1m));
        Assert.Equal("0.124", StructuredFields.SerializeBareItem(0.1235m));
        Assert.Equal("@1700000000", StructuredFields.SerializeBareItem(new SfDate(1700000000)));
        Assert.Equal("%\"f%c3%bc%25\"", StructuredFields.SerializeBareItem(new SfDisplayString("fü%")));
        Assert.Equal(new SfDisplayString("fü%"), StructuredFields.ParseItem("%\"f%c3%bc%25\"").Value);
        Assert.Equal(new SfDate(1700000000), StructuredFields.ParseItem("@1700000000").Value);
        Assert.Equal(2, StructuredFields.ParseList("a, (b c);x=1").Count);
        Assert.Throws<StructuredFieldFormatException>(() => StructuredFields.ParseItem("1.2345"));
        Assert.Throws<StructuredFieldFormatException>(() => StructuredFields.ParseItem("1234567890123456"));
        Assert.Throws<StructuredFieldFormatException>(() => StructuredFields.ParseDictionary("a=:not base64!:"));
        Assert.Throws<ArgumentException>(() => StructuredFields.SerializeBareItem("ünicode"));
    }

    [Fact]
    public void JsonPointerEscapes()
    {
        JsonElement f = Fixtures.Load("json-patch.json");
        foreach (JsonElement c in f.Arr("pointerEscapes"))
        {
            Assert.Equal(c.Str("escaped"), JsonPointer.Escape(c.Str("segment")));
            Assert.Equal(c.Str("segment"), JsonPointer.Unescape(c.Str("escaped")));
        }
        foreach (JsonElement c in f.Arr("pointers"))
        {
            Assert.Equal(c.Str("pointer"), JsonPointer.Of(c.Strings("segments")));
            Assert.Equal(c.Strings("segments"), JsonPointer.Parse(c.Str("pointer")));
        }
        Assert.Throws<ArgumentException>(() => JsonPointer.Parse("no-slash"));
    }

    [Fact]
    public void JsonPatchSerialization()
    {
        JsonElement f = Fixtures.Load("json-patch.json");
        var ops = f.GetProperty("patch").Arr("operations").ToList();
        JsonPatch patch = new JsonPatch()
            .Add(ops[0].Str("path"), System.Text.Json.Nodes.JsonNode.Parse(ops[0].GetProperty("value").GetRawText()))
            .Remove(ops[1].Str("path"))
            .Replace(ops[2].Str("path"), ops[2].GetProperty("value").GetString())
            .Move(ops[3].Str("from"), ops[3].Str("path"))
            .Copy(ops[4].Str("from"), ops[4].Str("path"))
            .Test(ops[5].Str("path"), ops[5].GetProperty("value").GetInt32());
        Assert.True(Fixtures.JsonEquals(f.GetProperty("patch").GetProperty("operations"), Fixtures.Parse(patch.ToString())));
        Assert.Equal(6, patch.Operations.Count);
        Assert.Equal("[{\"op\":\"add\",\"path\":\"/n\",\"value\":null}]", new JsonPatch().Add("/n", null).ToString());
        Assert.Equal("application/json-patch+json", JsonPatch.MediaType);
    }

    public static TheoryData<string> TypeQueryCases() => [.. Fixtures.Load("type-queries.json").Arr("cases").Select(c => c.Str("name"))];

    [Theory]
    [MemberData(nameof(TypeQueryCases))]
    public void TypeQueries(string name)
    {
        JsonElement c = Fixtures.Load("type-queries.json").Arr("cases").Single(x => x.Str("name") == name);
        TypeQuery Build()
        {
            var q = new TypeQuery();
            foreach (JsonElement step in c.Arr("steps"))
            {
                string key = step.Str("key");
                q = step.TryGetProperty("allOf", out _) ? q.Relation(key).AllOf(step.Strings("allOf")) : q.Relation(key).AnyOf(step.Strings("anyOf"));
            }
            return q;
        }
        if (c.TryGetProperty("error", out JsonElement err) && err.GetBoolean())
        {
            Assert.Throws<ArgumentException>(Build);
            return;
        }
        TypeQuery query = Build();
        Assert.True(Fixtures.JsonEquals(c.GetProperty("json"), Fixtures.Parse(query.ToString())), query.ToString());
        TypeQuery rebuilt = TypeQuery.FromJson(c.GetProperty("json"));
        Assert.Equal(query.ToString(), rebuilt.ToString());
    }

    [Fact]
    public void TypeQueryHelpers()
    {
        Assert.Equal("{\"type\":[\"https://schema.org/Person\"]}", new TypeQuery().AllOf("https://schema.org/Person").ToString());
        Assert.Equal("{\"type\":[[\"https://a.example/A\",\"https://b.example/B\"]]}", TypeQuery.Empty.AnyOf("https://a.example/A", "https://b.example/B").ToString());
        Assert.Equal("{}", TypeQuery.Empty.ToString());
        Assert.Equal("{\"type\":[\"https://a.example/A\"]}", TypeQuery.Empty.AllOf("https://a.example/A").AllOf("https://a.example/A").ToString());
        Assert.Throws<ArgumentException>(() => TypeQuery.Empty.Relation("@id"));
        Assert.Throws<ArgumentException>(() => TypeQuery.FromJson(Fixtures.Parse("{\"type\":[42]}")));
        Assert.Throws<ArgumentException>(() => TypeQuery.FromJson(Fixtures.Parse("{\"type\":\"x\"}")));
        Assert.False(TypeQuery.IsAbsoluteIri("Person"));
        Assert.True(TypeQuery.IsAbsoluteIri("urn:x:y"));
    }

    [Fact]
    public void ProblemDetailsFixture()
    {
        JsonElement f = Fixtures.Load("responses/problem-details.json");
        byte[] body = System.Text.Encoding.UTF8.GetBytes(f.GetProperty("body").GetRawText());
        HeaderMap headers = HeaderMap.From(f.GetProperty("headers").EnumerateObject().Select(p => new KeyValuePair<string, string>(p.Name, p.Value.GetString()!)));
        HttpException e = HttpException.Create("DELETE", new Uri("https://storage.example/alice/notes/"), f.GetProperty("status").GetInt32(), headers, body);
        JsonElement expected = f.GetProperty("expected");
        Assert.IsType<ConflictException>(e);
        Assert.Equal(409, e.Status);
        Assert.NotNull(e.Problem);
        Assert.Equal(expected.Str("type"), e.Problem!.Type);
        Assert.Equal(expected.Str("title"), e.Problem.Title);
        Assert.Equal(expected.Str("detail"), e.Problem.Detail);
        Assert.Equal(expected.Str("instance"), e.Problem.Instance);
        Assert.Equal(409, e.Problem.Status);
        Assert.Equal(3, e.Problem.Extensions["itemCount"].GetInt32());
        Assert.Contains("Container not empty", e.Message, StringComparison.Ordinal);
        Assert.True(Fixtures.JsonEquals(f.GetProperty("body"), e.Problem.Raw));
    }

    [Fact]
    public void ProblemDetailsDetection()
    {
        Assert.Null(ProblemDetails.Parse("text/plain", "{\"title\":\"x\"}"u8));
        Assert.Null(ProblemDetails.Parse("application/json", "{\"other\":1}"u8));
        Assert.NotNull(ProblemDetails.Parse("application/json", "{\"title\":\"x\"}"u8));
        Assert.NotNull(ProblemDetails.Parse("application/problem+json; charset=utf-8", "{}"u8));
        Assert.Null(ProblemDetails.Parse("application/problem+json", "not json"u8));
        Assert.Null(ProblemDetails.Parse("application/problem+json", []));
    }
}
