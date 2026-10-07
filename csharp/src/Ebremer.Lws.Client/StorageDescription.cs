// SPDX-License-Identifier: MIT
using System.Text.Json;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws;

/// <summary>
/// A storage description: a W3C Controlled Identifier document describing a storage, its services (storage root,
/// notifications, access requests and grants, type index and search, …), capabilities and verification methods.
/// </summary>
public sealed class StorageDescription
{
    private StorageDescription(Uri id, IReadOnlyList<string> types, IReadOnlyList<Service> services,
        IReadOnlyList<Capability> capabilities, IReadOnlyList<VerificationMethod> verificationMethods,
        IReadOnlyList<JsonElement> authentication, JsonElement raw)
    {
        Id = id;
        Types = types;
        Services = services;
        Capabilities = capabilities;
        VerificationMethods = verificationMethods;
        Authentication = authentication;
        Raw = raw;
    }

    /// <summary>The canonical storage URL.</summary>
    public Uri Id { get; }

    /// <summary>The raw <c>type</c> values (they include <c>Storage</c>).</summary>
    public IReadOnlyList<string> Types { get; }

    /// <summary>The advertised services.</summary>
    public IReadOnlyList<Service> Services { get; }

    /// <summary>The advertised capabilities.</summary>
    public IReadOnlyList<Capability> Capabilities { get; }

    /// <summary>The verification methods (e.g. the webhook signing keys).</summary>
    public IReadOnlyList<VerificationMethod> VerificationMethods { get; }

    /// <summary>The <c>authentication</c> relationship entries (strings or embedded objects).</summary>
    public IReadOnlyList<JsonElement> Authentication { get; }

    /// <summary>The JSON document.</summary>
    public JsonElement Raw { get; }

    /// <summary>The notification service, if advertised.</summary>
    public Service? NotificationService => GetService(Lws.ServiceType.Notification);

    /// <summary>The access request service, if advertised.</summary>
    public Service? AccessRequestService => GetService(Lws.ServiceType.AccessRequest);

    /// <summary>The access grant service, if advertised.</summary>
    public Service? AccessGrantService => GetService(Lws.ServiceType.AccessGrant);

    /// <summary>The type index service, if advertised.</summary>
    public Service? TypeIndexService => GetService(Lws.ServiceType.TypeIndex);

    /// <summary>The type search service, if advertised.</summary>
    public Service? TypeSearchService => GetService(Lws.ServiceType.TypeSearch);

    /// <summary>The storage root container URL.</summary>
    /// <returns>The storage root.</returns>
    /// <exception cref="ProtocolException">The description has no <c>StorageRoot</c> service.</exception>
    public Uri GetStorageRoot() =>
        GetService(Lws.ServiceType.StorageRoot)?.ServiceEndpoint
        ?? throw new ProtocolException($"Storage description {Uris.ToText(Id)} has no StorageRoot service");

    /// <summary>The first service of the given type, or null.</summary>
    /// <param name="type">The service type.</param>
    /// <returns>The service.</returns>
    public Service? GetService(string type) => Services.FirstOrDefault(s => s.HasType(type));

    /// <summary>All services of the given type.</summary>
    /// <param name="type">The service type.</param>
    /// <returns>The services.</returns>
    public IReadOnlyList<Service> GetServices(string type) => Services.Where(s => s.HasType(type)).ToList().AsReadOnly();

    /// <summary>The first capability of the given type, or null.</summary>
    /// <param name="type">The capability type.</param>
    /// <returns>The capability.</returns>
    public Capability? GetCapability(string type) => Capabilities.FirstOrDefault(c => c.HasType(type));

    /// <summary>
    /// Finds a verification method by full id, by fragment (<c>#key</c> or <c>key</c>), or by an id that resolves
    /// against the storage id to the requested one.
    /// </summary>
    /// <param name="idOrFragment">The id or fragment.</param>
    /// <returns>The method, or null.</returns>
    public VerificationMethod? FindVerificationMethod(string idOrFragment)
    {
        ArgumentNullException.ThrowIfNull(idOrFragment);
        return VerificationMethods.FirstOrDefault(v => v.Id is not null && (v.Id == idOrFragment || SameId(v.Id, idOrFragment)));
    }

    /// <summary>Whether a verification method is referenced from the <c>authentication</c> relationship.</summary>
    /// <param name="method">The method.</param>
    /// <returns>Whether it is an authentication method.</returns>
    public bool IsAuthenticationMethod(VerificationMethod method)
    {
        ArgumentNullException.ThrowIfNull(method);
        if (method.Id is null) return false;
        foreach (JsonElement a in Authentication)
        {
            string? reference = a.ValueKind == JsonValueKind.String ? a.GetString() : LwsJson.GetString(a, "id");
            if (reference is not null && (reference == method.Id || SameId(reference, method.Id))) return true;
        }
        return false;
    }

    private bool SameId(string a, string b)
    {
        Uri? ra = ResolveRef(a);
        Uri? rb = ResolveRef(b);
        return ra is not null && rb is not null && ra.AbsoluteUri == rb.AbsoluteUri;
    }

    private Uri? ResolveRef(string reference)
    {
        string r = reference;
        if (!r.Contains(':', StringComparison.Ordinal) && !r.StartsWith('#') && !r.StartsWith('/')) r = "#" + r;
        return Uris.Resolve(Id, r);
    }

    /// <summary>Parses a storage description; relative URLs are resolved against <paramref name="baseUri"/>.</summary>
    /// <param name="json">The document.</param>
    /// <param name="baseUri">The URL it was retrieved from.</param>
    /// <returns>The description.</returns>
    /// <exception cref="ProtocolException">The document is not a storage description.</exception>
    public static StorageDescription Parse(JsonElement json, Uri? baseUri)
    {
        LwsJson.RequireObject(json, "Storage description");
        string idText = LwsJson.GetString(json, "id") ?? throw new ProtocolException("Storage description has no id");
        Uri id = Uris.Resolve(baseUri, idText) ?? throw new ProtocolException($"Storage description id is not a URL: {idText}");
        IReadOnlyList<string> types = LwsJson.StringOrArray(LwsJson.Get(json, "type"));
        if (!Lws.HasType(types, Lws.Types.Storage))
        {
            throw new ProtocolException($"Document type [{string.Join(", ", types)}] does not include Storage");
        }
        var services = new List<Service>();
        if (LwsJson.Get(json, "service") is { ValueKind: JsonValueKind.Array } svc)
        {
            foreach (JsonElement s in svc.EnumerateArray())
            {
                if (s.ValueKind != JsonValueKind.Object) continue;
                Uri? endpoint = LwsJson.GetUri(s, "serviceEndpoint", id);
                if (endpoint is null) continue;
                services.Add(new Service(LwsJson.GetUri(s, "id", id), LwsJson.StringOrArray(LwsJson.Get(s, "type")), endpoint, s.Clone()));
            }
        }
        var capabilities = new List<Capability>();
        if (LwsJson.Get(json, "capability") is { ValueKind: JsonValueKind.Array } cap)
        {
            foreach (JsonElement c in cap.EnumerateArray())
            {
                if (c.ValueKind == JsonValueKind.Object)
                {
                    capabilities.Add(new Capability(LwsJson.GetUri(c, "id", id), LwsJson.StringOrArray(LwsJson.Get(c, "type")), c.Clone()));
                }
            }
        }
        var methods = new List<VerificationMethod>();
        if (LwsJson.Get(json, "verificationMethod") is { ValueKind: JsonValueKind.Array } vm)
        {
            foreach (JsonElement v in vm.EnumerateArray())
            {
                if (v.ValueKind == JsonValueKind.Object) methods.Add(VerificationMethod.Parse(v));
            }
        }
        var authentication = new List<JsonElement>();
        switch (LwsJson.Get(json, "authentication"))
        {
            case { ValueKind: JsonValueKind.Array } an:
                foreach (JsonElement a in an.EnumerateArray()) authentication.Add(a.Clone());
                break;
            case { ValueKind: JsonValueKind.String or JsonValueKind.Object } single:
                authentication.Add(single.Clone());
                break;
        }
        return new StorageDescription(id, types, services.AsReadOnly(), capabilities.AsReadOnly(), methods.AsReadOnly(),
            authentication.AsReadOnly(), json.Clone());
    }

    /// <inheritdoc/>
    public override string ToString() => $"StorageDescription {Uris.ToText(Id)}";
}

/// <summary>A service of a storage description.</summary>
public sealed class Service
{
    internal Service(Uri? id, IReadOnlyList<string> types, Uri serviceEndpoint, JsonElement raw)
    {
        Id = id;
        Types = types;
        ServiceEndpoint = serviceEndpoint;
        Raw = raw;
    }

    /// <summary>The optional service id.</summary>
    public Uri? Id { get; }

    /// <summary>The raw type values.</summary>
    public IReadOnlyList<string> Types { get; }

    /// <summary>The absolute endpoint URL.</summary>
    public Uri ServiceEndpoint { get; }

    /// <summary>The JSON object (for extra members such as <c>subscriptionType</c> or <c>conformsTo</c>).</summary>
    public JsonElement Raw { get; }

    /// <summary>The <c>subscriptionType</c> values of a notification service.</summary>
    public IReadOnlyList<string> SubscriptionTypes => LwsJson.StringOrArray(LwsJson.Get(Raw, "subscriptionType"));

    /// <summary>The <c>conformsTo</c> values (access profiles).</summary>
    public IReadOnlyList<string> ConformsTo => LwsJson.StringOrArray(LwsJson.Get(Raw, "conformsTo"));

    /// <summary>Whether the service declares <paramref name="type"/>.</summary>
    /// <param name="type">A type.</param>
    /// <returns>Whether it is declared.</returns>
    public bool HasType(string type) => Lws.HasType(Types, type);

    /// <summary>An extra member of the service object, or null.</summary>
    /// <param name="name">The member name.</param>
    /// <returns>The value.</returns>
    public JsonElement? GetProperty(string name) => LwsJson.Get(Raw, name);

    /// <inheritdoc/>
    public override string ToString() => $"{string.Join(",", Types)} {Uris.ToText(ServiceEndpoint)}";
}

/// <summary>A capability of a storage description.</summary>
public sealed class Capability
{
    internal Capability(Uri? id, IReadOnlyList<string> types, JsonElement raw)
    {
        Id = id;
        Types = types;
        Raw = raw;
    }

    /// <summary>The optional capability id.</summary>
    public Uri? Id { get; }

    /// <summary>The raw type values.</summary>
    public IReadOnlyList<string> Types { get; }

    /// <summary>The JSON object.</summary>
    public JsonElement Raw { get; }

    /// <summary>Whether the capability declares <paramref name="type"/>.</summary>
    /// <param name="type">A type.</param>
    /// <returns>Whether it is declared.</returns>
    public bool HasType(string type) => Lws.HasType(Types, type);

    /// <summary>An extra member of the capability object, or null.</summary>
    /// <param name="name">The member name.</param>
    /// <returns>The value.</returns>
    public JsonElement? GetProperty(string name) => LwsJson.Get(Raw, name);
}

/// <summary>A verification method of a controlled identifier document.</summary>
public sealed class VerificationMethod
{
    private VerificationMethod(string? id, string? type, string? controller, JsonElement? publicKeyJwk, JsonElement raw)
    {
        Id = id;
        Type = type;
        Controller = controller;
        PublicKeyJwk = publicKeyJwk;
        Raw = raw;
    }

    /// <summary>The id as written (it may be relative, e.g. <c>#key-1</c>).</summary>
    public string? Id { get; }

    /// <summary>The method type (e.g. <c>JsonWebKey</c>).</summary>
    public string? Type { get; }

    /// <summary>The controller.</summary>
    public string? Controller { get; }

    /// <summary>The public key as a JWK, or null.</summary>
    public JsonElement? PublicKeyJwk { get; }

    /// <summary>The JSON object.</summary>
    public JsonElement Raw { get; }

    internal static VerificationMethod Parse(JsonElement o) =>
        new(LwsJson.GetString(o, "id"), LwsJson.GetString(o, "type"), LwsJson.GetString(o, "controller"),
            LwsJson.Get(o, "publicKeyJwk") is { ValueKind: JsonValueKind.Object } jwk ? jwk.Clone() : null, o.Clone());
}
