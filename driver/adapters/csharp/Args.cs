// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Ebremer.Lws;

namespace Ebremer.Lws.Driver.Adapter;

/// <summary>A protocol error the adapter itself raises (<c>InvalidArguments</c>, <c>Unsupported</c>).</summary>
internal sealed class AdapterException(string kind, string message) : Exception(message)
{
    public string Kind { get; } = kind;

    public static AdapterException Invalid(string message) => new(Errors.InvalidArguments, message);
}

/// <summary>A request body with the content type it implies.</summary>
internal readonly record struct BodyArg(byte[] Bytes, string ContentType);

/// <summary>
/// Reads and validates request arguments (an absent member is missing or <c>null</c>), and rebuilds the structured
/// ones with the library's own types: bodies, JSON Patches and type queries.
/// </summary>
internal static partial class Args
{
    /// <summary>The default <c>limit</c> of the lazy sequences.</summary>
    public const long DefaultLimit = 1000;

    [GeneratedRegex("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")]
    private static partial Regex Base64Pattern();

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9+.\\-]*:")]
    private static partial Regex SchemePattern();

    public static JsonNode? Get(JsonObject args, string name) => args.TryGetPropertyValue(name, out JsonNode? v) ? v : null;

    public static string RequiredString(JsonObject args, string name) => OptionalString(args, name) ?? throw Missing(name);

    public static string? OptionalString(JsonObject args, string name) => Get(args, name) switch
    {
        null => null,
        JsonValue v when v.GetValueKind() == JsonValueKind.String => v.GetValue<string>(),
        _ => throw MustBe(name, "a string"),
    };

    /// <summary>An absolute URL argument; a relative reference is <c>InvalidArguments</c>.</summary>
    public static Uri RequiredUrl(JsonObject args, string name) => Url(RequiredString(args, name), name);

    public static Uri? OptionalUrl(JsonObject args, string name) => OptionalString(args, name) is { } s ? Url(s, name) : null;

    public static Uri Url(string value, string name)
    {
        if (!SchemePattern().IsMatch(value) || !Uri.TryCreate(value, UriKind.Absolute, out Uri? uri))
        {
            throw AdapterException.Invalid($"argument '{name}' is not an absolute URL: {value}");
        }
        return uri;
    }

    /// <summary>An absolute IRI (a URL or, e.g., a DID).</summary>
    public static string Iri(string value, string name) =>
        SchemePattern().IsMatch(value) ? value : throw AdapterException.Invalid($"argument '{name}' is not an absolute IRI: {value}");

    public static bool? OptionalBoolean(JsonObject args, string name) => Get(args, name) switch
    {
        null => null,
        JsonValue v when v.GetValueKind() is JsonValueKind.True or JsonValueKind.False => v.GetValue<bool>(),
        _ => throw MustBe(name, "a boolean"),
    };

    /// <summary>A non-negative integer argument (<c>2.0</c> counts as 2).</summary>
    public static long? OptionalNonNegativeInteger(JsonObject args, string name)
    {
        JsonNode? v = Get(args, name);
        if (v is null) return null;
        if (v is JsonValue value && value.GetValueKind() == JsonValueKind.Number)
        {
            JsonElement e = value.GetValue<JsonElement>();
            if (e.TryGetInt64(out long l) && l >= 0) return l;
            if (e.TryGetDouble(out double d) && d >= 0 && d == Math.Floor(d) && d < 9.2e18) return (long)d;
        }
        throw MustBe(name, "a non-negative integer");
    }

    public static JsonObject RequiredObject(JsonObject args, string name) => OptionalObject(args, name) ?? throw Missing(name);

    public static JsonObject? OptionalObject(JsonObject args, string name) => Get(args, name) switch
    {
        null => null,
        JsonObject o => o,
        _ => throw MustBe(name, "an object"),
    };

    public static JsonArray RequiredArray(JsonObject args, string name) => OptionalArray(args, name) ?? throw Missing(name);

    public static JsonArray? OptionalArray(JsonObject args, string name) => Get(args, name) switch
    {
        null => null,
        JsonArray a => a,
        _ => throw MustBe(name, "an array"),
    };

    /// <summary>The strings of an array argument.</summary>
    public static List<string> Strings(JsonArray array, string name) =>
        [.. array.Select(v => v is JsonValue s && s.GetValueKind() == JsonValueKind.String
            ? s.GetValue<string>()
            : throw AdapterException.Invalid($"argument '{name}' must be a list of strings"))];

    /// <summary>The absolute URLs of an array argument.</summary>
    public static List<Uri> Urls(JsonArray array, string name) => [.. Strings(array, name).Select(s => Url(s, name))];

    /// <summary>The optional <c>limit</c> of a lazy sequence.</summary>
    public static long Limit(JsonObject args) => OptionalNonNegativeInteger(args, "limit") ?? DefaultLimit;

    /// <summary>Strict, padded, standard base64.</summary>
    public static byte[] Base64(string value, string name)
    {
        if (!Base64Pattern().IsMatch(value)) throw AdapterException.Invalid($"argument '{name}' is not base64");
        return Convert.FromBase64String(value);
    }

    /// <summary>An RFC 3339 date-time.</summary>
    public static DateTimeOffset DateTime(string value, string name) =>
        DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset d) && value.Contains('T', StringComparison.OrdinalIgnoreCase)
            ? d
            : throw AdapterException.Invalid($"argument '{name}' is not an RFC 3339 date-time: {value}");

    /// <summary>A <c>body</c> argument as bytes, with the content type it implies.</summary>
    public static BodyArg Body(JsonNode? body, string? contentType)
    {
        if (body is null) return new BodyArg([], contentType ?? "application/octet-stream");
        if (body is not JsonObject o) throw MustBe("body", "an object");
        if (Get(o, "text") is JsonValue t && t.GetValueKind() == JsonValueKind.String)
        {
            return new BodyArg(Encoding.UTF8.GetBytes(t.GetValue<string>()), contentType ?? "text/plain");
        }
        if (Get(o, "base64") is JsonValue b && b.GetValueKind() == JsonValueKind.String)
        {
            return new BodyArg(Base64(b.GetValue<string>(), "body.base64"), contentType ?? "application/octet-stream");
        }
        if (o.ContainsKey("json"))
        {
            JsonNode? json = Get(o, "json");
            return new BodyArg(Encoding.UTF8.GetBytes(json?.ToJsonString(Results.Json) ?? "null"), contentType ?? "application/json");
        }
        throw AdapterException.Invalid("argument 'body' must have text, base64 or json");
    }

    /// <summary>An RFC 6902 operations array, rebuilt with the library's <see cref="JsonPatch"/> builder.</summary>
    public static JsonPatch Patch(JsonNode? operations)
    {
        if (operations is not JsonArray array) throw AdapterException.Invalid("argument 'patch' must be an array of operations");
        var patch = new JsonPatch();
        foreach (JsonNode? op in array)
        {
            if (op is not JsonObject o || Get(o, "op") is not JsonValue name || name.GetValueKind() != JsonValueKind.String)
            {
                throw AdapterException.Invalid("a patch operation must be an object with an op");
            }
            string kind = name.GetValue<string>();
            patch = kind switch
            {
                "add" => patch.Add(Pointer(o, "path", kind), Value(o, kind)),
                "remove" => patch.Remove(Pointer(o, "path", kind)),
                "replace" => patch.Replace(Pointer(o, "path", kind), Value(o, kind)),
                "move" => patch.Move(Pointer(o, "from", kind), Pointer(o, "path", kind)),
                "copy" => patch.Copy(Pointer(o, "from", kind), Pointer(o, "path", kind)),
                "test" => patch.Test(Pointer(o, "path", kind), Value(o, kind)),
                _ => throw AdapterException.Invalid($"unknown patch operation '{kind}'"),
            };
        }
        return patch;
    }

    private static string Pointer(JsonObject op, string member, string kind) =>
        Get(op, member) is JsonValue v && v.GetValueKind() == JsonValueKind.String
            ? v.GetValue<string>()
            : throw AdapterException.Invalid($"patch operation '{kind}' needs a string '{member}'");

    /// <summary>The <c>value</c> member; JSON <c>null</c> is a value here, only a missing member is not.</summary>
    private static JsonNode? Value(JsonObject op, string kind) =>
        op.TryGetPropertyValue("value", out JsonNode? v) ? v?.DeepClone() : throw AdapterException.Invalid($"patch operation '{kind}' needs a 'value'");

    /// <summary>
    /// An <c>application/lws-query+json</c> document, rebuilt with the library's <see cref="TypeQuery"/> builder: a string
    /// group is <c>AllOf(iri)</c> and an array group <c>AnyOf(iris…)</c>, on the key's relation, in order.
    /// </summary>
    public static TypeQuery Query(JsonNode? query)
    {
        if (query is not JsonObject o) throw MustBe("query", "an object");
        var q = new TypeQuery();
        foreach (KeyValuePair<string, JsonNode?> member in o)
        {
            if (member.Value is not JsonArray groups) throw AdapterException.Invalid($"query member '{member.Key}' must be a list of groups");
            foreach (JsonNode? group in groups)
            {
                q = group switch
                {
                    JsonValue s when s.GetValueKind() == JsonValueKind.String => q.Relation(member.Key).AllOf(s.GetValue<string>()),
                    JsonArray iris => q.Relation(member.Key).AnyOf(Strings(iris, "query." + member.Key)),
                    _ => throw AdapterException.Invalid($"a group of query member '{member.Key}' must be an IRI or a list of IRIs"),
                };
            }
        }
        return q;
    }

    /// <summary>A JSON document argument as a detached element (for the library's parsers).</summary>
    public static JsonElement Element(JsonNode node) => JsonSerializer.SerializeToElement(node, Results.Json);

    /// <summary>Parses a document argument with the library's parser; a document it rejects is a malformed argument.</summary>
    public static T Document<T>(Func<T> parse, string name)
    {
        try
        {
            return parse();
        }
        catch (ProtocolException e)
        {
            throw AdapterException.Invalid($"argument '{name}' is not a valid document: {e.Message}");
        }
    }

    private static AdapterException Missing(string name) => AdapterException.Invalid($"missing argument '{name}'");

    private static AdapterException MustBe(string name, string what) => AdapterException.Invalid($"argument '{name}' must be {what}");
}
