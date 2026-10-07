// SPDX-License-Identifier: MIT
using System.Collections.ObjectModel;

namespace Ebremer.Lws.Http;

/// <summary>
/// A typed web link (RFC 8288): a target, one relation type, and target attributes.
/// </summary>
public sealed record Link
{
    /// <summary>Creates a link.</summary>
    /// <param name="href">The link target (absolute when parsed from a response).</param>
    /// <param name="rel">The relation type (registered names lower-case; extension relation URIs as-is).</param>
    /// <param name="parameters">Target attributes with lower-case names, excluding <c>rel</c>.</param>
    public Link(Uri href, string rel, IReadOnlyDictionary<string, string>? parameters = null)
    {
        Href = href ?? throw new ArgumentNullException(nameof(href));
        Rel = rel ?? throw new ArgumentNullException(nameof(rel));
        var p = new OrderedDictionary<string, string>(StringComparer.Ordinal);
        if (parameters is not null)
        {
            foreach (KeyValuePair<string, string> kv in parameters) p[kv.Key.ToLowerInvariant()] = kv.Value;
        }
        Parameters = new ReadOnlyDictionary<string, string>(p);
    }

    /// <summary>Creates a link from a target string.</summary>
    /// <param name="href">The link target, an absolute URI or a reference.</param>
    /// <param name="rel">The relation type.</param>
    public Link(string href, string rel)
        : this(new Uri(href, Internal.Uris.HasScheme(href) ? UriKind.Absolute : UriKind.Relative), rel)
    {
    }

    /// <summary>The link target.</summary>
    public Uri Href { get; }

    /// <summary>The relation type.</summary>
    public string Rel { get; }

    /// <summary>The target attributes (lower-case names, values unquoted), excluding <c>rel</c>.</summary>
    public IReadOnlyDictionary<string, string> Parameters { get; }

    /// <summary>The <c>type</c> attribute (target media type hint), or null.</summary>
    public string? Type => GetParameter("type");

    /// <summary>The <c>anchor</c> attribute (link context override, unresolved), or null.</summary>
    public string? Anchor => GetParameter("anchor");

    /// <summary>A <c>rel="type"</c> link declaring a resource type.</summary>
    /// <param name="typeIri">The type IRI.</param>
    /// <returns>The link.</returns>
    public static Link ForType(string typeIri) => new(typeIri, Lws.Rel.Type);

    /// <summary>A target attribute by (case-insensitive) name, or null.</summary>
    /// <param name="name">The attribute name.</param>
    /// <returns>The value.</returns>
    public string? GetParameter(string name) =>
        Parameters.TryGetValue(name.ToLowerInvariant(), out string? v) ? v : null;

    /// <summary>Returns a copy with an extra attribute.</summary>
    /// <param name="name">The attribute name.</param>
    /// <param name="value">The value (empty for a valueless attribute).</param>
    /// <returns>The new link.</returns>
    public Link WithParameter(string name, string value)
    {
        var p = new OrderedDictionary<string, string>(StringComparer.Ordinal);
        foreach (KeyValuePair<string, string> kv in Parameters) p[kv.Key] = kv.Value;
        p[name.ToLowerInvariant()] = value;
        return new Link(Href, Rel, p);
    }

    /// <summary>This link as a <c>Link</c> header field value: <c>&lt;href&gt;; rel="rel"; name="value"</c>.</summary>
    /// <returns>The field value.</returns>
    public string ToHeaderValue() => LinkHeader.Format(this);

    /// <inheritdoc/>
    public bool Equals(Link? other) =>
        other is not null && Internal.Uris.ToText(Href) == Internal.Uris.ToText(other.Href) && Rel == other.Rel
        && Parameters.Count == other.Parameters.Count
        && Parameters.All(p => other.Parameters.TryGetValue(p.Key, out string? v) && v == p.Value);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Internal.Uris.ToText(Href), Rel, Parameters.Count);

    /// <inheritdoc/>
    public override string ToString() => ToHeaderValue();
}
