// SPDX-License-Identifier: MIT
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using Ebremer.Lws;
using Ebremer.Lws.Access;
using Ebremer.Lws.Auth;
using Ebremer.Lws.Http;
using Ebremer.Lws.Notifications;

namespace Ebremer.Lws.Driver.Adapter;

/// <summary>
/// The operations of <c>driver/PROTOCOL.md</c>, run with lws-client for C#. The adapter is a thin wrapper: it calls
/// the library's operations with the library's options and reports the library's results and errors, without
/// retrying or fixing anything up.
/// </summary>
internal sealed class Adapter : IDisposable
{
    public const string Protocol = "lws-driver/1";
    public const string Language = "csharp";
    public const string Library = "lws-client-csharp/" + LwsClient.Version;

    private readonly Dictionary<string, Func<JsonObject, Task<JsonObject>>> _operations;

    /// <summary>The client every operation uses; <c>configure</c> replaces it.</summary>
    private LwsClient _client = new();

    private IDisposable? _authenticator;

    public Adapter()
    {
        _operations = new Dictionary<string, Func<JsonObject, Task<JsonObject>>>(StringComparer.Ordinal)
        {
            ["configure"] = a => Task.FromResult(Configure(a)),
            ["discover_storage"] = async a => Results.Storage(await _client.DiscoverStorageAsync(Args.RequiredUrl(a, "url"))),
            ["get_storage_description"] = async a => Results.Storage(await _client.GetStorageDescriptionAsync(Args.RequiredUrl(a, "url"))),
            ["head"] = async a => Results.Metadata(await _client.HeadAsync(Args.RequiredUrl(a, "url"))),
            ["read"] = ReadAsync,
            ["read_container"] = async a => Results.Page(await _client.ReadContainerAsync(Args.RequiredUrl(a, "url"))),
            ["list_container"] = a => ItemsAsync(_client.ListContainerAsync(Args.RequiredUrl(a, "url")), Args.Limit(a)),
            ["create"] = CreateAsync,
            ["create_container"] = CreateContainerAsync,
            ["update"] = UpdateAsync,
            ["patch"] = async a => Results.Update(await _client.PatchAsync(Args.RequiredUrl(a, "url"), Args.Patch(Args.Get(a, "patch")), IfMatch(a))),
            ["delete"] = DeleteAsync,
            ["linkset_url"] = async a => new JsonObject { ["linkset"] = Results.Text(await _client.LinksetUrlAsync(Args.RequiredUrl(a, "url"))) },
            ["read_linkset"] = async a => Results.Linkset(await _client.ReadLinksetAsync(Args.RequiredUrl(a, "url"))),
            ["update_linkset"] = UpdateLinksetAsync,
            ["patch_linkset"] = async a =>
            {
                Uri linksetUrl = Args.RequiredUrl(a, "linksetUrl");
                return Results.Update(await _client.PatchLinksetAsync(linksetUrl, Args.Patch(Args.Get(a, "patch")), IfMatch(a)));
            },
            ["subscribe"] = SubscribeAsync,
            ["list_subscriptions"] = a => ItemsAsync(_client.ListSubscriptionsAsync(Args.RequiredUrl(a, "serviceUrl")), Args.Limit(a)),
            ["get_subscription"] = async a => Results.Subscription(await _client.GetSubscriptionAsync(Args.RequiredUrl(a, "url"))),
            ["unsubscribe"] = async a =>
            {
                await _client.UnsubscribeAsync(Args.RequiredUrl(a, "url"));
                return [];
            },
            ["verify_notification"] = VerifyNotificationAsync,
            ["request_access"] = async a =>
            {
                Uri service = Args.RequiredUrl(a, "serviceUrl");
                AccessRequest request = Args.Document(() => AccessRequest.Parse(Args.Element(Args.RequiredObject(a, "request"))), "request");
                return new JsonObject { ["location"] = Results.Text(await _client.RequestAccessAsync(service, request)) };
            },
            ["get_access_request"] = async a => Document(await _client.GetAccessRequestAsync(Args.RequiredUrl(a, "url"))),
            ["list_access_requests"] = a => ItemsAsync(_client.ListAccessRequestsAsync(Args.RequiredUrl(a, "serviceUrl")), Args.Limit(a)),
            ["cancel_access_request"] = async a =>
            {
                await _client.CancelAccessRequestAsync(Args.RequiredUrl(a, "url"));
                return [];
            },
            ["grant_access"] = async a =>
            {
                Uri service = Args.RequiredUrl(a, "serviceUrl");
                AccessGrant grant = Args.Document(() => AccessGrant.Parse(Args.Element(Args.RequiredObject(a, "grant"))), "grant");
                return new JsonObject { ["location"] = Results.Text(await _client.GrantAccessAsync(service, grant)) };
            },
            ["get_access_grant"] = async a => Document(await _client.GetAccessGrantAsync(Args.RequiredUrl(a, "url"))),
            ["list_access_grants"] = a => ItemsAsync(_client.ListAccessGrantsAsync(Args.RequiredUrl(a, "serviceUrl")), Args.Limit(a)),
            ["revoke_access_grant"] = async a =>
            {
                await _client.RevokeAccessGrantAsync(Args.RequiredUrl(a, "url"));
                return [];
            },
            ["read_type_index"] = async a => Results.TypeIndex(await _client.ReadTypeIndexAsync(Args.RequiredUrl(a, "url"))),
            ["list_types"] = async a =>
            {
                (List<string> types, bool truncated) = await TakeAsync(_client.ListTypesAsync(Args.RequiredUrl(a, "serviceUrl")), Args.Limit(a));
                return new JsonObject { ["types"] = Results.Strings(types), ["truncated"] = truncated };
            },
            ["search_types"] = async a =>
            {
                Uri service = Args.RequiredUrl(a, "serviceUrl");
                return Results.Page(await _client.SearchTypesAsync(service, Args.Query(Args.RequiredObject(a, "query"))));
            },
            ["search_all"] = a =>
            {
                Uri service = Args.RequiredUrl(a, "serviceUrl");
                TypeQuery query = Args.Query(Args.RequiredObject(a, "query"));
                return ItemsAsync(_client.SearchAllAsync(service, query), Args.Limit(a));
            },
            ["accepted_query_formats"] = async a =>
                new JsonObject { ["formats"] = Results.Strings(await _client.AcceptedQueryFormatsAsync(Args.RequiredUrl(a, "serviceUrl"))) },
            ["shutdown"] = _ => Task.FromResult(new JsonObject()),
        };
    }

    /// <summary>The operations, in the protocol's order.</summary>
    public IEnumerable<string> Operations => _operations.Keys;

    public bool TryGet(string op, out Func<JsonObject, Task<JsonObject>> operation) => _operations.TryGetValue(op, out operation!);

    public void Dispose()
    {
        _client.Dispose();
        _authenticator?.Dispose();
    }

    // ---------------------------------------------------------------------------------------------------- configure

    private JsonObject Configure(JsonObject args)
    {
        JsonNode? authArg = Args.Get(args, "auth");
        if (authArg is not null and not JsonObject) throw AdapterException.Invalid("argument 'auth' must be an object");
        JsonObject auth = authArg as JsonObject ?? new JsonObject { ["type"] = "none" };
        bool? allowInsecureHttp = Args.OptionalBoolean(args, "allowInsecureHttp");
        string? userAgent = Args.OptionalString(args, "userAgent");
        long? timeoutSeconds;
        try
        {
            timeoutSeconds = Args.OptionalNonNegativeInteger(args, "timeoutSeconds");
        }
        catch (AdapterException)
        {
            timeoutSeconds = 0;
        }
        if (timeoutSeconds == 0) throw AdapterException.Invalid("argument 'timeoutSeconds' must be a positive integer");
        Dictionary<string, string>? headers = null;
        if (Args.OptionalObject(args, "headers") is { } h)
        {
            headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (KeyValuePair<string, JsonNode?> header in h)
            {
                headers[header.Key] = header.Value is JsonValue v && v.GetValueKind() == System.Text.Json.JsonValueKind.String
                    ? v.GetValue<string>()
                    : throw AdapterException.Invalid($"header '{header.Key}' must be a string");
            }
        }

        var result = new JsonObject { ["library"] = Library };
        TimeSpan? timeout = timeoutSeconds is { } s ? TimeSpan.FromSeconds(s) : null;
        TokenExchangeAuthenticator TokenExchange(ICredentialProvider credentials) => new(credentials, new TokenExchangeOptions
        {
            AllowInsecureHttp = allowInsecureHttp ?? false,
            UserAgent = userAgent ?? LwsClient.DefaultUserAgent,
            Timeout = timeout ?? TimeSpan.FromSeconds(30),
        });

        IAuthenticator? authenticator;
        string type = Args.RequiredString(auth, "type");
        switch (type)
        {
            case "none":
                authenticator = null;
                break;
            case "bearer":
                {
                    string token = Args.RequiredString(auth, "token");
                    authenticator = new BearerTokenAuthenticator(token, Args.OptionalUrl(auth, "realm"));
                    break;
                }
            case "openid":
                authenticator = TokenExchange(new OpenIdCredentials(Args.RequiredString(auth, "idToken")));
                break;
            case "selfSigned":
                {
                    string agent = Args.Iri(Args.RequiredString(auth, "agent"), "agent");
                    JsonObject jwk = Args.RequiredObject(auth, "privateJwk");
                    string kid = Args.OptionalString(auth, "kid")
                        ?? (Args.Get(jwk, "kid") is JsonValue k && k.GetValueKind() == System.Text.Json.JsonValueKind.String ? k.GetValue<string>() : null)
                        ?? throw AdapterException.Invalid("selfSigned needs 'kid', or a 'kid' in the private JWK");
                    SigningKey key;
                    try
                    {
                        key = SigningKey.FromJwk(jwk);
                    }
                    catch (ArgumentException e)
                    {
                        throw AdapterException.Invalid($"argument 'privateJwk' is not a usable private key: {e.Message}");
                    }
                    authenticator = TokenExchange(SelfSignedCredentials.ForAgent(agent, key, kid));
                    result["agent"] = agent;
                    result["kid"] = kid;
                    break;
                }
            case "didKey":
                {
                    string algorithm = Args.OptionalString(auth, "algorithm") ?? "ES256";
                    SigningKey key = algorithm switch
                    {
                        "ES256" => SigningKey.GenerateP256(),
                        "EdDSA" => SigningKey.GenerateEd25519(),
                        _ => throw AdapterException.Invalid($"unknown algorithm '{algorithm}'"),
                    };
                    SelfSignedCredentials credentials = SelfSignedCredentials.DidKey(key);
                    authenticator = TokenExchange(credentials);
                    result["agent"] = credentials.Agent;
                    result["kid"] = credentials.KeyId;
                    break;
                }
            default:
                throw AdapterException.Invalid($"unknown auth type '{type}'");
        }

        var options = new LwsClientOptions
        {
            Authenticator = authenticator,
            UserAgent = userAgent ?? LwsClient.DefaultUserAgent,
            DefaultHeaders = headers,
        };
        if (timeout is { } t) options = options with { Timeout = t };
        _client.Dispose();
        _authenticator?.Dispose();
        _client = new LwsClient(options);
        _authenticator = authenticator as IDisposable;
        return result;
    }

    // ---------------------------------------------------------------------------------------------------- resources

    private async Task<JsonObject> ReadAsync(JsonObject args)
    {
        Uri url = Args.RequiredUrl(args, "url");
        long? start = Args.OptionalNonNegativeInteger(args, "rangeStart");
        long? end = Args.OptionalNonNegativeInteger(args, "rangeEnd");
        if (start is null && end is not null) throw AdapterException.Invalid("rangeEnd needs rangeStart");
        RangeHeaderValue? range;
        try
        {
            range = start is null ? null : new RangeHeaderValue(start, end);
        }
        catch (ArgumentOutOfRangeException)
        {
            throw AdapterException.Invalid("rangeEnd must not be before rangeStart");
        }
        var options = new ReadOptions
        {
            Accept = Args.OptionalString(args, "accept"),
            Range = range,
            IfNoneMatch = Args.OptionalString(args, "ifNoneMatch"),
            Prefer = Args.OptionalString(args, "prefer"),
        };
        Resource resource = await _client.ReadAsync(url, options);
        var result = new JsonObject
        {
            ["metadata"] = Results.Metadata(resource.Metadata),
            ["notModified"] = resource.NotModified,
        };
        Results.Put(result, "contentRange", resource.ContentRange);
        result["body"] = Results.Body(resource);
        return result;
    }

    private async Task<JsonObject> CreateAsync(JsonObject args)
    {
        Uri container = Args.RequiredUrl(args, "container");
        BodyArg body = Args.Body(Args.Get(args, "body"), Args.OptionalString(args, "contentType"));
        List<string>? types = Args.OptionalArray(args, "types") is { } t ? Args.Strings(t, "types") : null;
        List<Link>? links = null;
        if (Args.OptionalArray(args, "links") is { } l)
        {
            links = [];
            foreach (JsonNode? link in l)
            {
                if (link is not JsonObject o) throw AdapterException.Invalid("argument 'links' must be a list of {href, rel} objects");
                string href = Args.RequiredString(o, "href");
                string rel = Args.RequiredString(o, "rel");
                try
                {
                    links.Add(new Link(href, rel));
                }
                catch (UriFormatException)
                {
                    throw AdapterException.Invalid($"argument 'links' has an invalid href: {href}");
                }
            }
        }
        var options = new CreateOptions { Slug = Args.OptionalString(args, "slug"), Types = types, Links = links };
        return Results.Created(await _client.CreateAsync(container, body.Bytes, body.ContentType, options));
    }

    private async Task<JsonObject> CreateContainerAsync(JsonObject args)
    {
        Uri parent = Args.RequiredUrl(args, "parent");
        return Results.Created(await _client.CreateContainerAsync(parent, new CreateOptions { Slug = Args.OptionalString(args, "slug") }));
    }

    private async Task<JsonObject> UpdateAsync(JsonObject args)
    {
        Uri url = Args.RequiredUrl(args, "url");
        if (Args.Get(args, "body") is null) throw AdapterException.Invalid("missing argument 'body'");
        BodyArg body = Args.Body(Args.Get(args, "body"), Args.OptionalString(args, "contentType"));
        var options = new UpdateOptions { IfMatch = Args.OptionalString(args, "ifMatch"), IfNoneMatch = Args.OptionalString(args, "ifNoneMatch") };
        return Results.Update(await _client.UpdateAsync(url, body.Bytes, body.ContentType, options));
    }

    private async Task<JsonObject> DeleteAsync(JsonObject args)
    {
        Uri url = Args.RequiredUrl(args, "url");
        var options = new DeleteOptions { IfMatch = Args.OptionalString(args, "ifMatch"), Recursive = Args.OptionalBoolean(args, "recursive") ?? false };
        await _client.DeleteAsync(url, options);
        return [];
    }

    /// <summary>Update options carrying only the optional <c>ifMatch</c>.</summary>
    private static UpdateOptions IfMatch(JsonObject args) => new() { IfMatch = Args.OptionalString(args, "ifMatch") };

    private async Task<JsonObject> UpdateLinksetAsync(JsonObject args)
    {
        Uri linksetUrl = Args.RequiredUrl(args, "linksetUrl");
        Linkset linkset = Args.Document(() => Linkset.Parse(Args.Element(Args.RequiredObject(args, "linkset"))), "linkset");
        return Results.Update(await _client.UpdateLinksetAsync(linksetUrl, linkset, IfMatch(args)));
    }

    // ---------------------------------------------------------------------------------------------------- notifications

    private async Task<JsonObject> SubscribeAsync(JsonObject args)
    {
        Uri service = Args.RequiredUrl(args, "serviceUrl");
        List<Uri> topics = Args.Urls(Args.RequiredArray(args, "topics"), "topics");
        Uri inbox = Args.RequiredUrl(args, "inbox");
        DateTimeOffset? expires = Args.OptionalString(args, "expires") is { } e ? Args.DateTime(e, "expires") : null;
        WebhookSubscriptionRequest request;
        try
        {
            request = new WebhookSubscriptionRequest(inbox, topics, expires);
        }
        catch (ArgumentException ex)
        {
            throw AdapterException.Invalid(ex.Message);
        }
        return Results.Subscription(await _client.SubscribeAsync(service, request));
    }

    private async Task<JsonObject> VerifyNotificationAsync(JsonObject args)
    {
        string method = Args.RequiredString(args, "method");
        Uri url = Args.RequiredUrl(args, "url");
        var fields = new List<KeyValuePair<string, string[]>>();
        foreach (KeyValuePair<string, JsonNode?> h in Args.RequiredObject(args, "headers"))
        {
            string[] values = h.Value switch
            {
                JsonValue v when v.GetValueKind() == System.Text.Json.JsonValueKind.String => [v.GetValue<string>()],
                JsonArray a => [.. Args.Strings(a, "headers." + h.Key)],
                _ => throw AdapterException.Invalid($"header '{h.Key}' must be a list of values"),
            };
            fields.Add(new(h.Key, values));
        }
        byte[] body = Args.Base64(Args.RequiredString(args, "bodyBase64"), "bodyBase64");
        List<Uri>? trusted = Args.OptionalArray(args, "trustedStorages") is { } t ? Args.Urls(t, "trustedStorages") : null;
        using var verifier = new WebhookVerifier(new WebhookVerifierOptions { Client = _client, TrustedStorages = trusted });
        return Results.Verified(await verifier.VerifyAsync(method, url, HeaderMap.From(fields), body));
    }

    // ---------------------------------------------------------------------------------------------------- access

    /// <summary>The document as the library received it (its <c>Raw</c>), else as the library serializes it.</summary>
    private static JsonObject Document(AccessDocument doc) =>
        new() { ["document"] = doc.Raw is { } raw ? Results.Raw(raw) : doc.ToJson() };

    // ---------------------------------------------------------------------------------------------------- lazy sequences

    private static async Task<JsonObject> ItemsAsync(IAsyncEnumerable<ContainedResource> sequence, long limit)
    {
        (List<ContainedResource> items, bool truncated) = await TakeAsync(sequence, limit);
        return new JsonObject { ["items"] = new JsonArray([.. items.Select(i => (JsonNode)Results.Item(i))]), ["truncated"] = truncated };
    }

    /// <summary>
    /// Pulls at most <paramref name="limit"/> + 1 elements from a lazy sequence, returns the first
    /// <paramref name="limit"/>, and says whether there was one more.
    /// </summary>
    private static async Task<(List<T> Items, bool Truncated)> TakeAsync<T>(IAsyncEnumerable<T> sequence, long limit)
    {
        var items = new List<T>();
        await foreach (T item in sequence)
        {
            if (items.Count == limit) return (items, true);
            items.Add(item);
        }
        return (items, false);
    }
}
