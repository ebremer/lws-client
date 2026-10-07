// SPDX-License-Identifier: MIT
using System.Collections.ObjectModel;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws;

/// <summary>
/// An immutable type search filter (<c>application/lws-query+json</c>) in conjunctive normal form: every group must
/// match (AND), and a group matches when any of its IRIs does (OR). Each method returns a new query:
/// <code>
/// // (schema:Person OR foaf:Person) AND lws:DataResource, described by a person shape
/// var q = new TypeQuery()
///     .AnyOf("https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person")
///     .AllOf("https://www.w3.org/ns/lws#DataResource")
///     .Relation("describedby").AllOf("https://example.org/shapes/person");
/// </code>
/// An empty query (<c>{}</c>) matches everything. Validation mirrors the server's <c>400</c> rules: every value must
/// be an absolute IRI and no OR group may be empty (<see cref="ArgumentException"/>).
/// </summary>
public sealed partial class TypeQuery
{
    /// <summary>The query media type.</summary>
    public const string MediaType = Lws.MediaType.LwsQueryJson;

    /// <summary>The filter key of resource types.</summary>
    public const string TypeKey = "type";

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9+.\\-]*:[^\\s<>\"{}|\\\\^`]+$")]
    private static partial Regex AbsoluteIriPattern();

    private readonly IReadOnlyDictionary<string, IReadOnlyList<IReadOnlyList<string>>> _filters;

    /// <summary>Creates the empty query.</summary>
    public TypeQuery() => _filters = new ReadOnlyDictionary<string, IReadOnlyList<IReadOnlyList<string>>>(
        new OrderedDictionary<string, IReadOnlyList<IReadOnlyList<string>>>(StringComparer.Ordinal));

    private TypeQuery(OrderedDictionary<string, IReadOnlyList<IReadOnlyList<string>>> filters) =>
        _filters = new ReadOnlyDictionary<string, IReadOnlyList<IReadOnlyList<string>>>(filters);

    /// <summary>The empty query, which matches everything.</summary>
    public static TypeQuery Empty { get; } = new();

    /// <summary>The filter groups per key (<c>type</c> or a relation), in order.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<IReadOnlyList<string>>> Filters => _filters;

    /// <summary>Resources having all of <paramref name="types"/>: each IRI becomes its own AND group.</summary>
    /// <param name="types">Absolute type IRIs.</param>
    /// <returns>The new query.</returns>
    public TypeQuery AllOf(params IEnumerable<string> types) => Relation(TypeKey).AllOf(types);

    /// <summary>Resources having any of <paramref name="types"/>: one OR group (not empty).</summary>
    /// <param name="types">Absolute type IRIs.</param>
    /// <returns>The new query.</returns>
    public TypeQuery AnyOf(params IEnumerable<string> types) => Relation(TypeKey).AnyOf(types);

    /// <summary>A filter on an indexed descriptive link relation (same grammar, under the relation's key).</summary>
    /// <param name="relation">The relation type (or <c>type</c>).</param>
    /// <returns>The clause; its <c>AllOf</c> / <c>AnyOf</c> return the new query.</returns>
    public RelationClause Relation(string relation)
    {
        if (string.IsNullOrEmpty(relation) || relation.StartsWith('@'))
        {
            throw new ArgumentException($"Invalid filter key: {relation}", nameof(relation));
        }
        return new RelationClause(this, relation);
    }

    /// <summary>Whether <paramref name="iri"/> is an absolute IRI (a scheme followed by a non-empty remainder).</summary>
    /// <param name="iri">The value.</param>
    /// <returns>Whether it is absolute.</returns>
    public static bool IsAbsoluteIri(string? iri) => iri is not null && AbsoluteIriPattern().IsMatch(iri);

    private TypeQuery WithGroups(string key, IEnumerable<IReadOnlyList<string>> groups)
    {
        var copy = new OrderedDictionary<string, IReadOnlyList<IReadOnlyList<string>>>(StringComparer.Ordinal);
        foreach (KeyValuePair<string, IReadOnlyList<IReadOnlyList<string>>> kv in _filters) copy[kv.Key] = kv.Value;
        var list = copy.TryGetValue(key, out IReadOnlyList<IReadOnlyList<string>>? existing) ? existing.ToList() : [];
        foreach (IReadOnlyList<string> g in groups)
        {
            if (!list.Any(x => x.SequenceEqual(g))) list.Add(g);
        }
        copy[key] = list.AsReadOnly();
        return new TypeQuery(copy);
    }

    private static string Validate(string iri) =>
        IsAbsoluteIri(iri) ? iri : throw new ArgumentException($"Not an absolute IRI: {iri}", nameof(iri));

    /// <summary>The filter document (no <c>@context</c>); one-element OR groups are plain strings.</summary>
    /// <returns>The document.</returns>
    public JsonObject ToJson()
    {
        var o = new JsonObject();
        foreach (KeyValuePair<string, IReadOnlyList<IReadOnlyList<string>>> kv in _filters)
        {
            var a = new JsonArray();
            foreach (IReadOnlyList<string> g in kv.Value)
            {
                if (g.Count == 1) a.Add(g[0]);
                else a.Add(LwsJson.StringArray(g));
            }
            o[kv.Key] = a;
        }
        return o;
    }

    /// <summary>The serialized filter document (UTF-8).</summary>
    /// <returns>The bytes.</returns>
    public byte[] ToBytes() => LwsJson.ToBytes(ToJson());

    /// <inheritdoc/>
    public override string ToString() => Encoding.UTF8.GetString(ToBytes());

    /// <summary>
    /// Rebuilds a query from an <c>application/lws-query+json</c> document: a string group is <c>AllOf(iri)</c> and
    /// an array group <c>AnyOf(iris)</c>, on the member's key, in order.
    /// </summary>
    /// <param name="json">The document.</param>
    /// <returns>The query.</returns>
    /// <exception cref="ArgumentException">The document is not a valid filter.</exception>
    public static TypeQuery FromJson(JsonElement json)
    {
        if (json.ValueKind != JsonValueKind.Object) throw new ArgumentException("A type query must be a JSON object", nameof(json));
        TypeQuery q = Empty;
        foreach (JsonProperty member in json.EnumerateObject())
        {
            if (member.Value.ValueKind != JsonValueKind.Array)
            {
                throw new ArgumentException($"Query member '{member.Name}' must be a list of groups", nameof(json));
            }
            foreach (JsonElement group in member.Value.EnumerateArray())
            {
                q = group.ValueKind switch
                {
                    JsonValueKind.String => q.Relation(member.Name).AllOf(group.GetString()!),
                    JsonValueKind.Array => q.Relation(member.Name).AnyOf(group.EnumerateArray().Select(e =>
                        e.ValueKind == JsonValueKind.String ? e.GetString()! : throw new ArgumentException($"A group of query member '{member.Name}' must hold IRIs", nameof(json)))),
                    _ => throw new ArgumentException($"A group of query member '{member.Name}' must be an IRI or a list of IRIs", nameof(json)),
                };
            }
        }
        return q;
    }

    /// <summary>A filter clause on one key; <see cref="AllOf"/> and <see cref="AnyOf"/> return the extended query.</summary>
    public readonly struct RelationClause : IEquatable<RelationClause>
    {
        private readonly TypeQuery _query;

        internal RelationClause(TypeQuery query, string key)
        {
            _query = query;
            Key = key;
        }

        /// <summary>The filter key.</summary>
        public string Key { get; }

        /// <summary>Each IRI becomes its own AND group.</summary>
        /// <param name="iris">Absolute IRIs.</param>
        /// <returns>The new query.</returns>
        public TypeQuery AllOf(params IEnumerable<string> iris)
        {
            ArgumentNullException.ThrowIfNull(iris);
            return _query.WithGroups(Key, iris.Select(i => (IReadOnlyList<string>)new[] { Validate(i) }.AsReadOnly()).ToList());
        }

        /// <summary>One OR group of IRIs (must not be empty).</summary>
        /// <param name="iris">Absolute IRIs.</param>
        /// <returns>The new query.</returns>
        public TypeQuery AnyOf(params IEnumerable<string> iris)
        {
            ArgumentNullException.ThrowIfNull(iris);
            var group = iris.Select(Validate).ToList();
            if (group.Count == 0) throw new ArgumentException("An OR group must not be empty", nameof(iris));
            return _query.WithGroups(Key, [group.AsReadOnly()]);
        }

        /// <inheritdoc/>
        public bool Equals(RelationClause other) => ReferenceEquals(_query, other._query) && Key == other.Key;

        /// <inheritdoc/>
        public override bool Equals(object? obj) => obj is RelationClause c && Equals(c);

        /// <inheritdoc/>
        public override int GetHashCode() => HashCode.Combine(_query, Key);

        /// <summary>Equality.</summary>
        /// <param name="left">A clause.</param>
        /// <param name="right">Another clause.</param>
        /// <returns>Whether they are equal.</returns>
        public static bool operator ==(RelationClause left, RelationClause right) => left.Equals(right);

        /// <summary>Inequality.</summary>
        /// <param name="left">A clause.</param>
        /// <param name="right">Another clause.</param>
        /// <returns>Whether they differ.</returns>
        public static bool operator !=(RelationClause left, RelationClause right) => !left.Equals(right);
    }
}

/// <summary>One page of a type index: the distinct resource types visible to the client.</summary>
public sealed class TypeIndexPage
{
    private TypeIndexPage(long? totalItems, IReadOnlyList<string> types, ResourceMetadata metadata, JsonElement raw)
    {
        TotalItems = totalItems;
        Types = types;
        Metadata = metadata;
        Raw = raw;
    }

    /// <summary>The number of types across all pages.</summary>
    public long? TotalItems { get; }

    /// <summary>The type IRIs on this page.</summary>
    public IReadOnlyList<string> Types { get; }

    /// <summary>The first page.</summary>
    public Uri? First => Metadata.GetLink(Lws.Rel.First)?.Href;

    /// <summary>The next page.</summary>
    public Uri? Next => Metadata.GetLink(Lws.Rel.Next)?.Href;

    /// <summary>The previous page.</summary>
    public Uri? Prev => Metadata.GetLink(Lws.Rel.Prev)?.Href;

    /// <summary>The last page.</summary>
    public Uri? Last => Metadata.GetLink(Lws.Rel.Last)?.Href;

    /// <summary>The response metadata.</summary>
    public ResourceMetadata Metadata { get; }

    /// <summary>The JSON document.</summary>
    public JsonElement Raw { get; }

    /// <summary>Parses a type index page.</summary>
    /// <param name="body">The JSON body.</param>
    /// <param name="metadata">The response metadata.</param>
    /// <returns>The page.</returns>
    /// <exception cref="ProtocolException">The body is not a type index.</exception>
    public static TypeIndexPage Parse(JsonElement body, ResourceMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        LwsJson.RequireObject(body, "Type index");
        var types = new List<string>();
        JsonElement? items = LwsJson.Get(body, "items");
        if (items is { ValueKind: JsonValueKind.Array } array)
        {
            foreach (JsonElement n in array.EnumerateArray())
            {
                string? id = n.ValueKind == JsonValueKind.String ? n.GetString() : LwsJson.GetString(n, "id");
                if (id is not null) types.Add(id);
            }
        }
        else if (items is { ValueKind: not JsonValueKind.Null })
        {
            throw new ProtocolException("Type index 'items' is not an array");
        }
        return new TypeIndexPage(LwsJson.GetLong(body, "totalItems"), types.AsReadOnly(), metadata, body.Clone());
    }
}
