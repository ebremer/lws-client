// SPDX-License-Identifier: MIT
using System.Collections.ObjectModel;
using System.Text.Json;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws.Http;

/// <summary>RFC 9457 problem details attached to an error response.</summary>
public sealed class ProblemDetails
{
    private static readonly HashSet<string> Standard = ["type", "title", "status", "detail", "instance"];

    private ProblemDetails(JsonElement raw)
    {
        Raw = raw;
        Type = LwsJson.GetString(raw, "type");
        Title = LwsJson.GetString(raw, "title");
        Status = LwsJson.Get(raw, "status") is { ValueKind: JsonValueKind.Number } s && s.TryGetInt32(out int st) ? st : null;
        Detail = LwsJson.GetString(raw, "detail");
        Instance = LwsJson.GetString(raw, "instance");
        var ext = new OrderedDictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (JsonProperty p in raw.EnumerateObject())
        {
            if (!Standard.Contains(p.Name)) ext[p.Name] = p.Value;
        }
        Extensions = new ReadOnlyDictionary<string, JsonElement>(ext);
    }

    /// <summary>The problem type URI reference.</summary>
    public string? Type { get; }

    /// <summary>A short, human-readable summary.</summary>
    public string? Title { get; }

    /// <summary>The HTTP status code in the document.</summary>
    public int? Status { get; }

    /// <summary>A human-readable explanation of this occurrence.</summary>
    public string? Detail { get; }

    /// <summary>A URI reference identifying this occurrence.</summary>
    public string? Instance { get; }

    /// <summary>All other members, in document order.</summary>
    public IReadOnlyDictionary<string, JsonElement> Extensions { get; }

    /// <summary>The complete document.</summary>
    public JsonElement Raw { get; }

    /// <summary>Builds problem details from a JSON object.</summary>
    /// <param name="json">The document.</param>
    /// <returns>The problem details.</returns>
    /// <exception cref="ArgumentException">The document is not an object.</exception>
    public static ProblemDetails FromJson(JsonElement json)
    {
        if (json.ValueKind != JsonValueKind.Object) throw new ArgumentException("Problem details must be a JSON object", nameof(json));
        return new ProblemDetails(json.Clone());
    }

    /// <summary>
    /// Parses a problem document from an error response body: accepted when the content type is
    /// <c>application/problem+json</c>, or any JSON type whose object has a <c>type</c>, <c>title</c> or <c>detail</c>.
    /// </summary>
    /// <param name="contentType">The response content type.</param>
    /// <param name="body">The response body.</param>
    /// <returns>The problem details, or null.</returns>
    public static ProblemDetails? Parse(string? contentType, ReadOnlySpan<byte> body)
    {
        if (body.IsEmpty || !HeaderLists.IsJson(contentType)) return null;
        JsonElement node;
        try
        {
            node = LwsJson.Parse(body, "problem details");
        }
        catch (ProtocolException)
        {
            return null;
        }
        if (node.ValueKind != JsonValueKind.Object) return null;
        bool problemType = HeaderLists.Essence(contentType) == Lws.MediaType.ProblemJson;
        if (!problemType && !(node.TryGetProperty("type", out _) || node.TryGetProperty("title", out _) || node.TryGetProperty("detail", out _)))
        {
            return null;
        }
        return new ProblemDetails(node);
    }

    /// <inheritdoc/>
    public override string ToString() => Raw.GetRawText();
}
