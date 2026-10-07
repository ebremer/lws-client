// SPDX-License-Identifier: MIT
using System.Text.Json;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws;

/// <summary>
/// One page of a container listing, or of type search results (whose <c>type</c> is <c>ContainerPage</c>).
/// <see cref="Id"/>, <see cref="Types"/> and <see cref="TotalItems"/> describe the whole listing, <see cref="Items"/>
/// only this page; follow <see cref="Next"/> for more.
/// </summary>
public sealed class ContainerPage
{
    private ContainerPage(Uri id, IReadOnlyList<string> types, long? totalItems, IReadOnlyList<ContainedResource> items,
        ResourceMetadata metadata, JsonElement raw)
    {
        Id = id;
        Types = types;
        TotalItems = totalItems;
        Items = items;
        Metadata = metadata;
        Raw = raw;
    }

    /// <summary>The absolute container URL; the page URL when the body has no <c>id</c> (e.g. search results).</summary>
    public Uri Id { get; }

    /// <summary>The raw <c>type</c> values of the listing.</summary>
    public IReadOnlyList<string> Types { get; }

    /// <summary>The (possibly approximate) number of members across all pages.</summary>
    public long? TotalItems { get; }

    /// <summary>The members on this page.</summary>
    public IReadOnlyList<ContainedResource> Items { get; }

    /// <summary>The first page.</summary>
    public Uri? First => Metadata.GetLink(Lws.Rel.First)?.Href;

    /// <summary>The next page.</summary>
    public Uri? Next => Metadata.GetLink(Lws.Rel.Next)?.Href;

    /// <summary>The previous page.</summary>
    public Uri? Prev => Metadata.GetLink(Lws.Rel.Prev)?.Href;

    /// <summary>The last page.</summary>
    public Uri? Last => Metadata.GetLink(Lws.Rel.Last)?.Href;

    /// <summary>The response metadata (entity tag, links, …).</summary>
    public ResourceMetadata Metadata { get; }

    /// <summary>The JSON document.</summary>
    public JsonElement Raw { get; }

    /// <summary>The entity tag of this page.</summary>
    public string? ETag => Metadata.ETag;

    /// <summary>Whether the listing is a container (by its body <c>type</c> or its <c>rel="type"</c> links).</summary>
    public bool IsContainer => HasType(Lws.Types.Container) || Metadata.IsContainer;

    /// <summary>Whether the listing declares <paramref name="type"/>.</summary>
    /// <param name="type">A type.</param>
    /// <returns>Whether it is declared.</returns>
    public bool HasType(string type) => Lws.HasType(Types, type);

    /// <summary>Parses a container representation; relative ids are resolved against the page URL.</summary>
    /// <param name="body">The JSON body.</param>
    /// <param name="metadata">The response metadata.</param>
    /// <returns>The page.</returns>
    /// <exception cref="ProtocolException">The body is not a container representation.</exception>
    public static ContainerPage Parse(JsonElement body, ResourceMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        LwsJson.RequireObject(body, "Container representation");
        Uri baseUri = metadata.Url;
        string? idText = LwsJson.GetString(body, "id");
        Uri id = idText is null ? baseUri : Uris.Resolve(baseUri, idText) ?? throw new ProtocolException($"Invalid container id: {idText}");
        var items = new List<ContainedResource>();
        JsonElement? itemsNode = LwsJson.Get(body, "items");
        if (itemsNode is { ValueKind: JsonValueKind.Array } array)
        {
            foreach (JsonElement n in array.EnumerateArray()) items.Add(ContainedResource.Parse(n, baseUri));
        }
        else if (itemsNode is { ValueKind: not JsonValueKind.Null })
        {
            throw new ProtocolException("Container 'items' is not an array");
        }
        return new ContainerPage(id, LwsJson.StringOrArray(LwsJson.Get(body, "type")), LwsJson.GetLong(body, "totalItems"),
            items.AsReadOnly(), metadata, body.Clone());
    }

    /// <inheritdoc/>
    public override string ToString() => $"ContainerPage {Uris.ToText(Id)} ({Items.Count} items)";
}

/// <summary>One member of a container listing (or of type search results).</summary>
public sealed class ContainedResource
{
    private ContainedResource(Uri id, IReadOnlyList<string> types, string? format, long? size, string? modifiedRaw, JsonElement raw)
    {
        Id = id;
        Types = types;
        Format = format;
        Size = size;
        ModifiedRaw = modifiedRaw;
        Modified = LwsJson.ParseDateTime(modifiedRaw);
        Raw = raw;
    }

    /// <summary>The absolute URL of the member.</summary>
    public Uri Id { get; }

    /// <summary>The raw type values, as received.</summary>
    public IReadOnlyList<string> Types { get; }

    /// <summary>The media type (required for data resources).</summary>
    public string? Format { get; }

    /// <summary>The size in bytes.</summary>
    public long? Size { get; }

    /// <summary>The last modification time, when parseable (an unparseable date never fails the listing).</summary>
    public DateTimeOffset? Modified { get; }

    /// <summary>The <c>modified</c> value as sent.</summary>
    public string? ModifiedRaw { get; }

    /// <summary>The JSON object.</summary>
    public JsonElement Raw { get; }

    /// <summary>Whether the member is a container.</summary>
    public bool IsContainer => HasType(Lws.Types.Container);

    /// <summary>Whether the member is a data resource.</summary>
    public bool IsDataResource => HasType(Lws.Types.DataResource);

    /// <summary>Whether the member declares <paramref name="type"/> (short terms match their full IRIs).</summary>
    /// <param name="type">A type.</param>
    /// <returns>Whether it is declared.</returns>
    public bool HasType(string type) => Lws.HasType(Types, type);

    /// <summary>Parses a contained resource description, resolving its id against <paramref name="baseUri"/>.</summary>
    /// <param name="json">The JSON object.</param>
    /// <param name="baseUri">The page URL.</param>
    /// <returns>The member.</returns>
    /// <exception cref="ProtocolException">The description has no valid id.</exception>
    public static ContainedResource Parse(JsonElement json, Uri? baseUri)
    {
        LwsJson.RequireObject(json, "Contained resource description");
        string idText = LwsJson.GetString(json, "id") ?? throw new ProtocolException("Contained resource description without id");
        Uri id = Uris.Resolve(baseUri, idText) ?? throw new ProtocolException($"Invalid contained resource id: {idText}");
        return new ContainedResource(id, LwsJson.StringOrArray(LwsJson.Get(json, "type")), LwsJson.GetString(json, "format"),
            LwsJson.GetLong(json, "size"), LwsJson.GetString(json, "modified"), json.Clone());
    }

    /// <inheritdoc/>
    public override string ToString() => Uris.ToText(Id);
}
