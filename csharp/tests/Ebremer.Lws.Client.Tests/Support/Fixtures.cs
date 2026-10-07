// SPDX-License-Identifier: MIT
using System.Reflection;
using System.Text.Json;

namespace Ebremer.Lws.Tests.Support;

/// <summary>Loads the shared fixtures of <c>conformance/fixtures</c> (the repository's language-neutral test vectors).</summary>
internal static class Fixtures
{
    private static readonly Lazy<string> Root = new(Locate);

    /// <summary>The fixtures directory.</summary>
    public static string Directory => Root.Value;

    /// <summary>Loads a fixture by its path relative to <c>conformance/fixtures</c>.</summary>
    public static JsonElement Load(string relativePath)
    {
        string path = Path.Combine(Directory, relativePath);
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllBytes(path));
        return doc.RootElement.Clone();
    }

    /// <summary>Every fixture file, relative to the fixtures directory.</summary>
    public static IEnumerable<string> All() =>
        System.IO.Directory.EnumerateFiles(Directory, "*.json", SearchOption.AllDirectories)
            .Select(p => Path.GetRelativePath(Directory, p).Replace('\\', '/'))
            .Order(StringComparer.Ordinal);

    private static string Locate()
    {
        string? configured = typeof(Fixtures).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => a.Key == "LwsConformanceDir")?.Value;
        if (configured is not null && System.IO.Directory.Exists(Path.Combine(configured, "fixtures"))) return Path.Combine(configured, "fixtures");
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            string candidate = Path.Combine(dir.FullName, "conformance", "fixtures");
            if (System.IO.Directory.Exists(candidate)) return candidate;
        }
        throw new InvalidOperationException("Cannot find conformance/fixtures from " + AppContext.BaseDirectory);
    }

    public static string Str(this JsonElement e, string name) => e.GetProperty(name).GetString()!;

    public static string? OptStr(this JsonElement e, string name) =>
        e.TryGetProperty(name, out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    public static IEnumerable<JsonElement> Arr(this JsonElement e, string name) => e.GetProperty(name).EnumerateArray();

    public static List<string> Strings(this JsonElement e, string name) => e.GetProperty(name).EnumerateArray().Select(x => x.GetString()!).ToList();

    /// <summary>Whether two JSON values are equal (object member order is not significant).</summary>
    public static bool JsonEquals(JsonElement a, JsonElement b)
    {
        if (a.ValueKind != b.ValueKind) return false;
        switch (a.ValueKind)
        {
            case JsonValueKind.Object:
                var am = a.EnumerateObject().ToDictionary(p => p.Name, p => p.Value);
                var bm = b.EnumerateObject().ToDictionary(p => p.Name, p => p.Value);
                return am.Count == bm.Count && am.All(kv => bm.TryGetValue(kv.Key, out JsonElement v) && JsonEquals(kv.Value, v));
            case JsonValueKind.Array:
                var aa = a.EnumerateArray().ToList();
                var ba = b.EnumerateArray().ToList();
                return aa.Count == ba.Count && aa.Zip(ba).All(p => JsonEquals(p.First, p.Second));
            case JsonValueKind.Number:
                return a.GetDecimal() == b.GetDecimal();
            case JsonValueKind.String:
                return a.GetString() == b.GetString();
            default:
                return true;
        }
    }

    public static JsonElement Parse(string json)
    {
        using JsonDocument doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    public static JsonElement ToElement(this System.Text.Json.Nodes.JsonNode node) => Parse(node.ToJsonString());
}
