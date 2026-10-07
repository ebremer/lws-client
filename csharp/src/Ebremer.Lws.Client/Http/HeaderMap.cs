// SPDX-License-Identifier: MIT
using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;

namespace Ebremer.Lws.Http;

/// <summary>
/// An immutable multimap of HTTP header fields: names are case-insensitive, and the order of names and of each
/// field's values (one per field line) is kept. Values are the raw strings as received.
/// </summary>
public sealed class HeaderMap : IReadOnlyDictionary<string, IReadOnlyList<string>>
{
    private readonly OrderedDictionary<string, IReadOnlyList<string>> _fields;

    /// <summary>An empty header map.</summary>
    public static HeaderMap Empty { get; } = new(new OrderedDictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase));

    private HeaderMap(OrderedDictionary<string, IReadOnlyList<string>> fields) => _fields = fields;

    /// <summary>Builds a header map from name/value pairs (repeated names accumulate values).</summary>
    /// <param name="fields">The header fields.</param>
    /// <returns>The header map.</returns>
    public static HeaderMap From(IEnumerable<KeyValuePair<string, string>> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        return Build(fields.Select(f => (f.Key, (IEnumerable<string>)[f.Value])));
    }

    /// <summary>Builds a header map from names with several values (e.g. a <c>Dictionary&lt;string, string[]&gt;</c>).</summary>
    /// <param name="fields">The header fields.</param>
    /// <returns>The header map.</returns>
    public static HeaderMap From(IEnumerable<KeyValuePair<string, string[]>> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        return Build(fields.Select(f => (f.Key, (IEnumerable<string>)f.Value)));
    }

    /// <summary>Builds a header map from an enumeration of names and values, such as <see cref="HttpHeaders"/>.</summary>
    /// <param name="fields">The header fields.</param>
    /// <returns>The header map.</returns>
    public static HeaderMap From(IEnumerable<KeyValuePair<string, IEnumerable<string>>> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        return Build(fields.Select(f => (f.Key, f.Value)));
    }

    /// <summary>The raw header fields of a response (response and content headers, unparsed).</summary>
    /// <param name="response">The response.</param>
    /// <returns>The header map.</returns>
    public static HeaderMap From(HttpResponseMessage response)
    {
        ArgumentNullException.ThrowIfNull(response);
        var pairs = new List<(string, IEnumerable<string>)>();
        foreach (KeyValuePair<string, HeaderStringValues> h in response.Headers.NonValidated) pairs.Add((h.Key, h.Value));
        foreach (KeyValuePair<string, HeaderStringValues> h in response.Content.Headers.NonValidated) pairs.Add((h.Key, h.Value));
        return Build(pairs);
    }

    private static HeaderMap Build(IEnumerable<(string Name, IEnumerable<string> Values)> fields)
    {
        var lists = new OrderedDictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach ((string name, IEnumerable<string> values) in fields)
        {
            if (string.IsNullOrEmpty(name) || values is null) continue;
            if (!lists.TryGetValue(name, out List<string>? list))
            {
                list = [];
                lists.Add(name, list);
            }
            foreach (string v in values)
            {
                if (v is not null) list.Add(v);
            }
        }
        var frozen = new OrderedDictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (KeyValuePair<string, List<string>> e in lists) frozen.Add(e.Key, e.Value.AsReadOnly());
        return new HeaderMap(frozen);
    }

    /// <summary>The first value of a field, or null.</summary>
    /// <param name="name">The field name (case-insensitive).</param>
    /// <returns>The first value.</returns>
    public string? GetFirst(string name) =>
        _fields.TryGetValue(name, out IReadOnlyList<string>? v) && v.Count > 0 ? v[0] : null;

    /// <summary>Every value of a field (one per field line), possibly empty.</summary>
    /// <param name="name">The field name (case-insensitive).</param>
    /// <returns>The values.</returns>
    public IReadOnlyList<string> GetAll(string name) =>
        _fields.TryGetValue(name, out IReadOnlyList<string>? v) ? v : [];

    /// <summary>All values of a field joined with <c>", "</c> (RFC 9110 section 5.3), or null when absent.</summary>
    /// <param name="name">The field name (case-insensitive).</param>
    /// <returns>The combined value.</returns>
    public string? GetCombined(string name) =>
        _fields.TryGetValue(name, out IReadOnlyList<string>? v) && v.Count > 0 ? string.Join(", ", v) : null;

    /// <inheritdoc/>
    public IReadOnlyList<string> this[string key] => _fields[key];

    /// <inheritdoc/>
    public IEnumerable<string> Keys => _fields.Keys;

    /// <inheritdoc/>
    public IEnumerable<IReadOnlyList<string>> Values => _fields.Values;

    /// <inheritdoc/>
    public int Count => _fields.Count;

    /// <inheritdoc/>
    public bool ContainsKey(string key) => _fields.ContainsKey(key);

    /// <inheritdoc/>
    public bool TryGetValue(string key, [MaybeNullWhen(false)] out IReadOnlyList<string> value) => _fields.TryGetValue(key, out value);

    /// <inheritdoc/>
    public IEnumerator<KeyValuePair<string, IReadOnlyList<string>>> GetEnumerator() => _fields.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    /// <inheritdoc/>
    public override string ToString() =>
        string.Join("\n", _fields.SelectMany(f => f.Value.Select(v => $"{f.Key}: {v}")));
}
