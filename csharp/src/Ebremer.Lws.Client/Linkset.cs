// SPDX-License-Identifier: MIT
using System.Collections.ObjectModel;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ebremer.Lws.Http;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws;

/// <summary>
/// An immutable linkset document (<c>application/linkset+json</c>, RFC 9264) holding a resource's metadata links.
/// Mutators return modified copies; unknown members are preserved on round trip.
/// </summary>
public sealed class Linkset
{
    /// <summary>Creates a linkset.</summary>
    /// <param name="contexts">The link context objects.</param>
    public Linkset(IEnumerable<LinkContext> contexts) =>
        Contexts = (contexts ?? throw new ArgumentNullException(nameof(contexts))).ToList().AsReadOnly();

    /// <summary>An empty linkset.</summary>
    public static Linkset Empty { get; } = new([]);

    /// <summary>The link context objects.</summary>
    public IReadOnlyList<LinkContext> Contexts { get; }

    /// <summary>Parses an <c>application/linkset+json</c> document.</summary>
    /// <param name="json">The document.</param>
    /// <returns>The linkset.</returns>
    /// <exception cref="ProtocolException">The document is not a linkset.</exception>
    public static Linkset Parse(JsonElement json)
    {
        LwsJson.RequireObject(json, "Linkset");
        if (LwsJson.Get(json, "linkset") is not { ValueKind: JsonValueKind.Array } ls)
        {
            throw new ProtocolException("Linkset document has no 'linkset' array");
        }
        var contexts = new List<LinkContext>();
        foreach (JsonElement c in ls.EnumerateArray())
        {
            if (c.ValueKind != JsonValueKind.Object) throw new ProtocolException("Linkset context is not an object");
            contexts.Add(LinkContext.Parse(c));
        }
        return new Linkset(contexts);
    }

    /// <summary>Parses an <c>application/linkset+json</c> document from text.</summary>
    /// <param name="json">The document.</param>
    /// <returns>The linkset.</returns>
    /// <exception cref="ProtocolException">The document is not a linkset.</exception>
    public static Linkset Parse(string json) => Parse(LwsJson.Parse(json, "Linkset"));

    /// <summary>The <c>application/linkset+json</c> serialization (a new, mutable document).</summary>
    /// <returns>The document.</returns>
    public JsonObject ToJson()
    {
        var a = new JsonArray();
        foreach (LinkContext c in Contexts) a.Add(c.ToJson());
        return new JsonObject { ["linkset"] = a };
    }

    /// <summary>Every link, flattened; targets are resolved against their anchor.</summary>
    /// <returns>The links.</returns>
    public IReadOnlyList<Link> GetLinks()
    {
        var output = new List<Link>();
        foreach (LinkContext c in Contexts)
        {
            Uri? anchor = c.Anchor is null ? null : Uris.Resolve(null, c.Anchor);
            foreach (KeyValuePair<string, IReadOnlyList<LinkTarget>> rel in c.Relations)
            {
                foreach (LinkTarget t in rel.Value)
                {
                    Uri? href = Uris.Resolve(anchor, t.Href);
                    if (href is null) continue;
                    var parameters = new OrderedDictionary<string, string>(StringComparer.Ordinal);
                    if (c.Anchor is not null) parameters["anchor"] = c.Anchor;
                    foreach (KeyValuePair<string, JsonElement> attr in t.Attributes)
                    {
                        if (attr.Value.ValueKind == JsonValueKind.String) parameters[attr.Key] = attr.Value.GetString()!;
                    }
                    output.Add(new Link(href, rel.Key, parameters));
                }
            }
        }
        return output.AsReadOnly();
    }

    /// <summary>The targets of <paramref name="rel"/> across all contexts.</summary>
    /// <param name="rel">The relation type.</param>
    /// <returns>The targets.</returns>
    public IReadOnlyList<LinkTarget> GetTargets(string rel) => Contexts.SelectMany(c => c.GetTargets(rel)).ToList().AsReadOnly();

    /// <summary>The targets of <paramref name="rel"/> for one anchor.</summary>
    /// <param name="anchor">The anchor.</param>
    /// <param name="rel">The relation type.</param>
    /// <returns>The targets.</returns>
    public IReadOnlyList<LinkTarget> GetTargets(string? anchor, string rel) => GetContext(anchor)?.GetTargets(rel) ?? [];

    /// <summary>The context object for <paramref name="anchor"/>, or null.</summary>
    /// <param name="anchor">The anchor (null for a context without one).</param>
    /// <returns>The context.</returns>
    public LinkContext? GetContext(string? anchor) => Contexts.FirstOrDefault(c => c.Anchor == anchor);

    /// <summary>Returns a copy with a link added (creating the context for <paramref name="anchor"/> if needed).</summary>
    /// <param name="anchor">The link context.</param>
    /// <param name="rel">The relation type.</param>
    /// <param name="href">The target.</param>
    /// <param name="attributes">Target attributes (<c>type</c>, <c>title</c>, …).</param>
    /// <returns>The new linkset.</returns>
    public Linkset Add(string? anchor, string rel, string href, IReadOnlyDictionary<string, JsonNode?>? attributes = null)
    {
        ArgumentNullException.ThrowIfNull(rel);
        ArgumentNullException.ThrowIfNull(href);
        var attrs = new OrderedDictionary<string, JsonElement>(StringComparer.Ordinal);
        if (attributes is not null)
        {
            foreach (KeyValuePair<string, JsonNode?> kv in attributes) attrs[kv.Key] = LwsJson.ToElement(kv.Value);
        }
        var target = new LinkTarget(href, attrs);
        var output = Contexts.ToList();
        for (int i = 0; i < output.Count; i++)
        {
            if (output[i].Anchor == anchor)
            {
                output[i] = output[i].With(rel, target);
                return new Linkset(output);
            }
        }
        output.Add(new LinkContext(anchor, new Dictionary<string, IReadOnlyList<LinkTarget>> { [rel] = [target] }));
        return new Linkset(output);
    }

    /// <summary>
    /// Returns a copy without the links of <paramref name="rel"/> for <paramref name="anchor"/>; with
    /// <paramref name="href"/> only that target is removed. Relations left empty are dropped.
    /// </summary>
    /// <param name="anchor">The link context.</param>
    /// <param name="rel">The relation type.</param>
    /// <param name="href">The target to remove, or null for all.</param>
    /// <returns>The new linkset.</returns>
    public Linkset Remove(string? anchor, string rel, string? href = null) =>
        new(Contexts.Select(c => c.Anchor == anchor ? c.Without(rel, href) : c));

    /// <inheritdoc/>
    public override string ToString() => ToJson().ToJsonString(LwsJson.Options);
}

/// <summary>One link context object of a linkset.</summary>
public sealed class LinkContext
{
    /// <summary>Creates a link context.</summary>
    /// <param name="anchor">The context URI as written (null when the object has none).</param>
    /// <param name="relations">Relation type → targets, in document order.</param>
    /// <param name="extra">Members other than the anchor and relations (preserved on round trip).</param>
    public LinkContext(string? anchor, IEnumerable<KeyValuePair<string, IReadOnlyList<LinkTarget>>> relations,
        IEnumerable<KeyValuePair<string, JsonElement>>? extra = null)
    {
        Anchor = anchor;
        var rels = new OrderedDictionary<string, IReadOnlyList<LinkTarget>>(StringComparer.Ordinal);
        foreach (KeyValuePair<string, IReadOnlyList<LinkTarget>> kv in relations ?? throw new ArgumentNullException(nameof(relations)))
        {
            rels[kv.Key] = kv.Value.ToList().AsReadOnly();
        }
        Relations = new ReadOnlyDictionary<string, IReadOnlyList<LinkTarget>>(rels);
        var ext = new OrderedDictionary<string, JsonElement>(StringComparer.Ordinal);
        if (extra is not null)
        {
            foreach (KeyValuePair<string, JsonElement> kv in extra) ext[kv.Key] = kv.Value.Clone();
        }
        Extra = new ReadOnlyDictionary<string, JsonElement>(ext);
    }

    /// <summary>The context URI as written.</summary>
    public string? Anchor { get; }

    /// <summary>Relation type → targets, in document order.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<LinkTarget>> Relations { get; }

    /// <summary>Unknown members (preserved).</summary>
    public IReadOnlyDictionary<string, JsonElement> Extra { get; }

    /// <summary>The targets of <paramref name="rel"/>.</summary>
    /// <param name="rel">The relation type.</param>
    /// <returns>The targets.</returns>
    public IReadOnlyList<LinkTarget> GetTargets(string rel) => Relations.TryGetValue(rel, out IReadOnlyList<LinkTarget>? t) ? t : [];

    internal static LinkContext Parse(JsonElement o)
    {
        var rels = new OrderedDictionary<string, IReadOnlyList<LinkTarget>>(StringComparer.Ordinal);
        var extra = new OrderedDictionary<string, JsonElement>(StringComparer.Ordinal);
        string? anchor = null;
        foreach (JsonProperty p in o.EnumerateObject())
        {
            if (p.Name == "anchor" && p.Value.ValueKind == JsonValueKind.String)
            {
                anchor = p.Value.GetString();
            }
            else if (p.Value.ValueKind == JsonValueKind.Array)
            {
                var targets = new List<LinkTarget>();
                bool ok = true;
                foreach (JsonElement t in p.Value.EnumerateArray())
                {
                    if (t.ValueKind == JsonValueKind.Object && LwsJson.GetString(t, "href") is not null) targets.Add(LinkTarget.Parse(t));
                    else ok = false;
                }
                if (ok) rels[p.Name] = targets;
                else extra[p.Name] = p.Value;
            }
            else
            {
                extra[p.Name] = p.Value;
            }
        }
        return new LinkContext(anchor, rels, extra);
    }

    internal JsonObject ToJson()
    {
        var o = new JsonObject();
        if (Anchor is not null) o["anchor"] = Anchor;
        foreach (KeyValuePair<string, IReadOnlyList<LinkTarget>> rel in Relations)
        {
            var a = new JsonArray();
            foreach (LinkTarget t in rel.Value) a.Add(t.ToJson());
            o[rel.Key] = a;
        }
        foreach (KeyValuePair<string, JsonElement> e in Extra) o[e.Key] = LwsJson.ToNode(e.Value);
        return o;
    }

    internal LinkContext With(string rel, LinkTarget target)
    {
        var rels = new OrderedDictionary<string, IReadOnlyList<LinkTarget>>(StringComparer.Ordinal);
        foreach (KeyValuePair<string, IReadOnlyList<LinkTarget>> kv in Relations) rels[kv.Key] = kv.Value;
        rels[rel] = [.. GetTargets(rel), target];
        return new LinkContext(Anchor, rels, Extra);
    }

    internal LinkContext Without(string rel, string? href)
    {
        var rels = new OrderedDictionary<string, IReadOnlyList<LinkTarget>>(StringComparer.Ordinal);
        foreach (KeyValuePair<string, IReadOnlyList<LinkTarget>> kv in Relations)
        {
            if (kv.Key != rel)
            {
                rels[kv.Key] = kv.Value;
                continue;
            }
            if (href is null) continue;
            var kept = kv.Value.Where(t => t.Href != href).ToList();
            if (kept.Count > 0) rels[kv.Key] = kept;
        }
        return new LinkContext(Anchor, rels, Extra);
    }
}

/// <summary>A link target object of a linkset.</summary>
public sealed class LinkTarget
{
    /// <summary>Creates a link target.</summary>
    /// <param name="href">The target URI as written.</param>
    /// <param name="attributes">The target attributes (<c>type</c>, <c>title</c>, <c>hreflang</c>, <c>title*</c>, …).</param>
    public LinkTarget(string href, IEnumerable<KeyValuePair<string, JsonElement>>? attributes = null)
    {
        Href = href ?? throw new ArgumentNullException(nameof(href));
        var attrs = new OrderedDictionary<string, JsonElement>(StringComparer.Ordinal);
        if (attributes is not null)
        {
            foreach (KeyValuePair<string, JsonElement> kv in attributes)
            {
                if (kv.Key != "href") attrs[kv.Key] = kv.Value.Clone();
            }
        }
        Attributes = new ReadOnlyDictionary<string, JsonElement>(attrs);
    }

    /// <summary>The target URI as written.</summary>
    public string Href { get; }

    /// <summary>The target attributes, in document order.</summary>
    public IReadOnlyDictionary<string, JsonElement> Attributes { get; }

    /// <summary>A string attribute, or null.</summary>
    /// <param name="name">The attribute name.</param>
    /// <returns>The value.</returns>
    public string? GetAttribute(string name) =>
        Attributes.TryGetValue(name, out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    internal static LinkTarget Parse(JsonElement o) =>
        new(LwsJson.GetString(o, "href")!, o.EnumerateObject().Select(p => new KeyValuePair<string, JsonElement>(p.Name, p.Value)));

    internal JsonObject ToJson()
    {
        var o = new JsonObject { ["href"] = Href };
        foreach (KeyValuePair<string, JsonElement> a in Attributes) o[a.Key] = LwsJson.ToNode(a.Value);
        return o;
    }

    /// <inheritdoc/>
    public override string ToString() => Href;
}

/// <summary>A retrieved linkset resource: its URL, entity tag and content, plus what the server allows.</summary>
public sealed class LinksetDocument
{
    internal LinksetDocument(Uri url, Linkset linkset, ResourceMetadata metadata)
    {
        Url = url;
        Linkset = linkset;
        Metadata = metadata;
    }

    /// <summary>The linkset resource URL: pass it to <c>UpdateLinksetAsync</c> / <c>PatchLinksetAsync</c>.</summary>
    public Uri Url { get; }

    /// <summary>The parsed linkset.</summary>
    public Linkset Linkset { get; }

    /// <summary>The response metadata.</summary>
    public ResourceMetadata Metadata { get; }

    /// <summary>The entity tag: use it as <c>IfMatch</c> for conditional updates.</summary>
    public string? ETag => Metadata.ETag;

    /// <summary>The methods allowed on the linkset resource.</summary>
    public IReadOnlyList<string> Allow => Metadata.Allow;

    /// <summary>The patch formats the linkset resource accepts.</summary>
    public IReadOnlyList<string> AcceptPatch => Metadata.AcceptPatch;

    /// <summary>Whether the server advertises <c>PUT</c> for full replacement.</summary>
    public bool SupportsPut => Allow.Any(m => string.Equals(m, "PUT", StringComparison.OrdinalIgnoreCase));
}
