// SPDX-License-Identifier: MIT
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws;

/// <summary>One JSON Patch operation (RFC 6902).</summary>
public sealed record JsonPatchOperation
{
    /// <summary>Creates an operation.</summary>
    /// <param name="op">The operation: <c>add</c>, <c>remove</c>, <c>replace</c>, <c>move</c>, <c>copy</c> or <c>test</c>.</param>
    /// <param name="path">The target JSON Pointer.</param>
    /// <param name="from">The source pointer of <c>move</c> / <c>copy</c>.</param>
    /// <param name="value">The value of <c>add</c> / <c>replace</c> / <c>test</c> (a JSON null is a value; a C# null is none).</param>
    public JsonPatchOperation(string op, string path, string? from = null, JsonElement? value = null)
    {
        Op = op ?? throw new ArgumentNullException(nameof(op));
        Path = path ?? throw new ArgumentNullException(nameof(path));
        From = from;
        Value = value?.Clone();
    }

    /// <summary>The operation name.</summary>
    public string Op { get; }

    /// <summary>The target JSON Pointer.</summary>
    public string Path { get; }

    /// <summary>The source JSON Pointer (<c>move</c>, <c>copy</c>).</summary>
    public string? From { get; }

    /// <summary>The value (<c>add</c>, <c>replace</c>, <c>test</c>).</summary>
    public JsonElement? Value { get; }

    /// <summary>The operation as a JSON object.</summary>
    /// <returns>The object.</returns>
    public JsonObject ToJson()
    {
        var o = new JsonObject { ["op"] = Op };
        if (From is not null) o["from"] = From;
        o["path"] = Path;
        if (Value is { } v) o["value"] = LwsJson.ToNode(v);
        return o;
    }
}

/// <summary>
/// An immutable JSON Patch document (RFC 6902), the LWS baseline patch format
/// (<c>application/json-patch+json</c>). Each method returns a new patch with one more operation:
/// <code>var patch = new JsonPatch().Replace("/age", 31).Add("/city", "Boston");</code>
/// </summary>
public sealed class JsonPatch
{
    /// <summary>The patch media type.</summary>
    public const string MediaType = Lws.MediaType.JsonPatch;

    private readonly IReadOnlyList<JsonPatchOperation> _operations;

    /// <summary>Creates an empty patch.</summary>
    public JsonPatch() => _operations = [];

    /// <summary>Creates a patch from existing operations.</summary>
    /// <param name="operations">The operations, in order.</param>
    public JsonPatch(IEnumerable<JsonPatchOperation> operations) =>
        _operations = (operations ?? throw new ArgumentNullException(nameof(operations))).ToList().AsReadOnly();

    /// <summary>The operations, in order.</summary>
    public IReadOnlyList<JsonPatchOperation> Operations => _operations;

    /// <summary>Adds an <c>add</c> operation.</summary>
    /// <param name="path">The target pointer.</param>
    /// <param name="value">The value (null is JSON null).</param>
    /// <returns>The new patch.</returns>
    public JsonPatch Add(string path, JsonNode? value) => With(new JsonPatchOperation("add", path, null, LwsJson.ToElement(value)));

    /// <summary>Adds a <c>remove</c> operation.</summary>
    /// <param name="path">The target pointer.</param>
    /// <returns>The new patch.</returns>
    public JsonPatch Remove(string path) => With(new JsonPatchOperation("remove", path));

    /// <summary>Adds a <c>replace</c> operation.</summary>
    /// <param name="path">The target pointer.</param>
    /// <param name="value">The value (null is JSON null).</param>
    /// <returns>The new patch.</returns>
    public JsonPatch Replace(string path, JsonNode? value) => With(new JsonPatchOperation("replace", path, null, LwsJson.ToElement(value)));

    /// <summary>Adds a <c>move</c> operation.</summary>
    /// <param name="from">The source pointer.</param>
    /// <param name="path">The target pointer.</param>
    /// <returns>The new patch.</returns>
    public JsonPatch Move(string from, string path) => With(new JsonPatchOperation("move", path, from ?? throw new ArgumentNullException(nameof(from))));

    /// <summary>Adds a <c>copy</c> operation.</summary>
    /// <param name="from">The source pointer.</param>
    /// <param name="path">The target pointer.</param>
    /// <returns>The new patch.</returns>
    public JsonPatch Copy(string from, string path) => With(new JsonPatchOperation("copy", path, from ?? throw new ArgumentNullException(nameof(from))));

    /// <summary>Adds a <c>test</c> operation.</summary>
    /// <param name="path">The target pointer.</param>
    /// <param name="value">The expected value (null is JSON null).</param>
    /// <returns>The new patch.</returns>
    public JsonPatch Test(string path, JsonNode? value) => With(new JsonPatchOperation("test", path, null, LwsJson.ToElement(value)));

    private JsonPatch With(JsonPatchOperation op) => new([.. _operations, op]);

    /// <summary>The patch as a JSON array.</summary>
    /// <returns>The array.</returns>
    public JsonArray ToJson()
    {
        var a = new JsonArray();
        foreach (JsonPatchOperation op in _operations) a.Add(op.ToJson());
        return a;
    }

    /// <summary>The serialized patch document (UTF-8).</summary>
    /// <returns>The bytes.</returns>
    public byte[] ToBytes() => LwsJson.ToBytes(ToJson());

    /// <inheritdoc/>
    public override string ToString() => Encoding.UTF8.GetString(ToBytes());
}

/// <summary>
/// JSON Pointer (RFC 6901) helpers. Escaping matters for linkset patches, whose relation keys are often URIs:
/// <c>JsonPointer.Of("linkset", "0", "https://example.org/rel", "-")</c> is
/// <c>/linkset/0/https:~1~1example.org~1rel/-</c>.
/// </summary>
public static class JsonPointer
{
    /// <summary>Escapes one reference token: <c>~</c> becomes <c>~0</c> and <c>/</c> becomes <c>~1</c>.</summary>
    /// <param name="segment">The unescaped token.</param>
    /// <returns>The escaped token.</returns>
    public static string Escape(string segment)
    {
        ArgumentNullException.ThrowIfNull(segment);
        return segment.Replace("~", "~0", StringComparison.Ordinal).Replace("/", "~1", StringComparison.Ordinal);
    }

    /// <summary>Reverses <see cref="Escape"/>.</summary>
    /// <param name="token">The escaped token.</param>
    /// <returns>The unescaped token.</returns>
    public static string Unescape(string token)
    {
        ArgumentNullException.ThrowIfNull(token);
        return token.Replace("~1", "/", StringComparison.Ordinal).Replace("~0", "~", StringComparison.Ordinal);
    }

    /// <summary>Builds a pointer from unescaped segments; no segments is the whole-document pointer <c>""</c>.</summary>
    /// <param name="segments">The segments.</param>
    /// <returns>The pointer.</returns>
    public static string Of(params IEnumerable<string> segments)
    {
        ArgumentNullException.ThrowIfNull(segments);
        var sb = new StringBuilder();
        foreach (string s in segments) sb.Append('/').Append(Escape(s));
        return sb.ToString();
    }

    /// <summary>Splits a pointer into unescaped segments.</summary>
    /// <param name="pointer">The pointer.</param>
    /// <returns>The segments.</returns>
    /// <exception cref="ArgumentException">The pointer does not start with <c>/</c>.</exception>
    public static IReadOnlyList<string> Parse(string pointer)
    {
        if (string.IsNullOrEmpty(pointer)) return [];
        if (!pointer.StartsWith('/')) throw new ArgumentException($"A JSON Pointer must start with '/': {pointer}", nameof(pointer));
        return pointer[1..].Split('/').Select(Unescape).ToList().AsReadOnly();
    }
}
