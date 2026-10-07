// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Ebremer.Lws.Internal;

/// <summary>JSON helpers shared by the models (internal).</summary>
internal static class LwsJson
{
    /// <summary>Serializer settings: no HTML escaping, so URLs and media types stay readable on the wire.</summary>
    public static readonly JsonSerializerOptions Options = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>Writer settings matching <see cref="Options"/>.</summary>
    public static readonly JsonWriterOptions WriterOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>Parses UTF-8 JSON; malformed input is a <see cref="ProtocolException"/>.</summary>
    public static JsonElement Parse(ReadOnlySpan<byte> utf8, string what)
    {
        try
        {
            var reader = new Utf8JsonReader(utf8, new JsonReaderOptions { CommentHandling = JsonCommentHandling.Disallow });
            using var doc = JsonDocument.ParseValue(ref reader);
            if (reader.Read()) throw new JsonException("trailing content");
            return doc.RootElement.Clone();
        }
        catch (JsonException e)
        {
            throw new ProtocolException($"{what} is not valid JSON: {e.Message}", e);
        }
    }

    /// <summary>Parses JSON text; malformed input is a <see cref="ProtocolException"/>.</summary>
    public static JsonElement Parse(string json, string what)
    {
        ArgumentNullException.ThrowIfNull(json);
        return Parse(System.Text.Encoding.UTF8.GetBytes(json), what);
    }

    /// <summary>Requires a JSON object.</summary>
    public static JsonElement RequireObject(JsonElement e, string what)
    {
        if (e.ValueKind != JsonValueKind.Object) throw new ProtocolException($"{what} is not a JSON object");
        return e;
    }

    /// <summary>A member, if present (any kind).</summary>
    public static JsonElement? Get(JsonElement obj, string name)
    {
        if (obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out JsonElement v)) return v;
        return null;
    }

    /// <summary>A string member, if present and a string.</summary>
    public static string? GetString(JsonElement obj, string name)
    {
        JsonElement? v = Get(obj, name);
        return v is { ValueKind: JsonValueKind.String } s ? s.GetString() : null;
    }

    /// <summary>An integral number member.</summary>
    public static long? GetLong(JsonElement obj, string name)
    {
        JsonElement? v = Get(obj, name);
        if (v is { ValueKind: JsonValueKind.Number } n)
        {
            if (n.TryGetInt64(out long l)) return l;
            if (n.TryGetDouble(out double d) && d == Math.Floor(d) && Math.Abs(d) < 9.2e18) return (long)d;
        }
        return null;
    }

    /// <summary>A string member resolved as a URI reference against <paramref name="baseUri"/>.</summary>
    public static Uri? GetUri(JsonElement obj, string name, Uri? baseUri)
    {
        string? s = GetString(obj, name);
        return s is null ? null : Uris.Resolve(baseUri, s);
    }

    /// <summary>A value that is a string or an array of strings, as a list (non-strings are skipped).</summary>
    public static IReadOnlyList<string> StringOrArray(JsonElement? value)
    {
        if (value is not { } v) return [];
        if (v.ValueKind == JsonValueKind.String) return [v.GetString()!];
        if (v.ValueKind != JsonValueKind.Array) return [];
        var list = new List<string>();
        foreach (JsonElement e in v.EnumerateArray())
        {
            if (e.ValueKind == JsonValueKind.String) list.Add(e.GetString()!);
        }
        return list.AsReadOnly();
    }

    /// <summary>Parses an RFC 3339 date-time; anything unparseable is null (never an error).</summary>
    public static DateTimeOffset? ParseDateTime(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        return DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset d)
            ? d
            : null;
    }

    /// <summary>Formats an instant as RFC 3339 in UTC (fractional seconds only when present).</summary>
    public static string FormatDateTime(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'", CultureInfo.InvariantCulture);

    /// <summary>A detached element for a node (<c>null</c> is JSON null).</summary>
    public static JsonElement ToElement(JsonNode? node) => Parse(node?.ToJsonString(Options) ?? "null", "value");

    /// <summary>A mutable copy of an element.</summary>
    public static JsonNode? ToNode(JsonElement element) => JsonNode.Parse(element.GetRawText());

    /// <summary>The compact UTF-8 serialization of a node.</summary>
    public static byte[] ToBytes(JsonNode node) => JsonSerializer.SerializeToUtf8Bytes(node, Options);

    /// <summary>A JSON array of strings.</summary>
    public static JsonArray StringArray(IEnumerable<string> values)
    {
        var a = new JsonArray();
        foreach (string v in values) a.Add(v);
        return a;
    }

    /// <summary>The members of an object, in document order.</summary>
    public static IEnumerable<JsonProperty> Members(JsonElement obj) =>
        obj.ValueKind == JsonValueKind.Object ? obj.EnumerateObject() : [];
}
