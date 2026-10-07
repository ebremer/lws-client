// SPDX-License-Identifier: MIT
using System.Text;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws.Http;

/// <summary>Parser and serializer for the <c>Link</c> header field (RFC 8288).</summary>
public static class LinkHeader
{
    /// <summary>
    /// Parses every link-value of the given <c>Link</c> field lines. Targets are resolved against
    /// <paramref name="baseUri"/>; a <c>rel</c> with several space-separated relation types yields one link per type.
    /// Malformed link-values are skipped.
    /// </summary>
    /// <param name="fieldValues">The field lines.</param>
    /// <param name="baseUri">The request URL the targets are relative to.</param>
    /// <returns>The links, in order.</returns>
    public static IReadOnlyList<Link> Parse(IEnumerable<string>? fieldValues, Uri? baseUri)
    {
        var output = new List<Link>();
        if (fieldValues is null) return output;
        foreach (string v in fieldValues)
        {
            if (v is not null) ParseLine(v, baseUri, output);
        }
        return output.AsReadOnly();
    }

    /// <summary>Parses a single <c>Link</c> field line.</summary>
    /// <param name="fieldValue">The field line.</param>
    /// <param name="baseUri">The request URL the targets are relative to.</param>
    /// <returns>The links, in order.</returns>
    public static IReadOnlyList<Link> Parse(string? fieldValue, Uri? baseUri) =>
        Parse(fieldValue is null ? [] : [fieldValue], baseUri);

    private static void ParseLine(string s, Uri? baseUri, List<Link> output)
    {
        int n = s.Length;
        int i = 0;
        while (i < n)
        {
            while (i < n && (IsWs(s[i]) || s[i] == ',')) i++;
            if (i >= n) break;
            if (s[i] != '<')
            {
                i = SkipToNextLinkValue(s, i);
                continue;
            }
            int close = s.IndexOf('>', i + 1);
            if (close < 0) break;
            string target = s[(i + 1)..close].Trim();
            i = close + 1;
            var parameters = new OrderedDictionary<string, string>(StringComparer.Ordinal);
            string? rel = null;
            while (true)
            {
                while (i < n && IsWs(s[i])) i++;
                if (i >= n || s[i] == ',') break;
                if (s[i] != ';')
                {
                    i = SkipToNextLinkValue(s, i);
                    break;
                }
                i++;
                while (i < n && IsWs(s[i])) i++;
                int start = i;
                while (i < n && IsTokenChar(s[i])) i++;
                string name = s[start..i].ToLowerInvariant();
                while (i < n && IsWs(s[i])) i++;
                string value = "";
                if (i < n && s[i] == '=')
                {
                    i++;
                    while (i < n && IsWs(s[i])) i++;
                    if (i < n && s[i] == '"')
                    {
                        var sb = new StringBuilder();
                        i++;
                        while (i < n && s[i] != '"')
                        {
                            if (s[i] == '\\' && i + 1 < n)
                            {
                                sb.Append(s[i + 1]);
                                i += 2;
                            }
                            else
                            {
                                sb.Append(s[i]);
                                i++;
                            }
                        }
                        if (i < n) i++;
                        value = sb.ToString();
                    }
                    else
                    {
                        int vs = i;
                        while (i < n && s[i] != ';' && s[i] != ',' && !IsWs(s[i])) i++;
                        value = s[vs..i];
                    }
                }
                if (name.Length == 0) continue;
                if (name == "rel") rel ??= value;
                else parameters.TryAdd(name, value);
            }
            if (rel is null) continue;
            Uri? href = Uris.Resolve(baseUri, target);
            if (href is null) continue;
            foreach (string r in rel.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries))
            {
                output.Add(new Link(href, NormalizeRel(r), parameters));
            }
        }
    }

    private static int SkipToNextLinkValue(string s, int i)
    {
        bool quoted = false;
        bool angle = false;
        while (i < s.Length)
        {
            char c = s[i];
            if (quoted)
            {
                if (c == '\\') i++;
                else if (c == '"') quoted = false;
            }
            else if (angle)
            {
                if (c == '>') angle = false;
            }
            else if (c == '"')
            {
                quoted = true;
            }
            else if (c == '<')
            {
                angle = true;
            }
            else if (c == ',')
            {
                return i + 1;
            }
            i++;
        }
        return i;
    }

    /// <summary>Registered relation types are case-insensitive (lower-cased); extension relation URIs are kept.</summary>
    /// <param name="rel">A relation type.</param>
    /// <returns>The normalized relation type.</returns>
    public static string NormalizeRel(string rel)
    {
        ArgumentNullException.ThrowIfNull(rel);
        return rel.Contains(':', StringComparison.Ordinal) ? rel : rel.ToLowerInvariant();
    }

    private static bool IsWs(char c) => c is ' ' or '\t' or '\r' or '\n';

    internal static bool IsTokenChar(char c) =>
        c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9'
        || "!#$%&'*+-.^_`|~".Contains(c, StringComparison.Ordinal);

    /// <summary>Serializes a link: <c>&lt;href&gt;; rel="rel"; name="value"</c>.</summary>
    /// <param name="link">The link.</param>
    /// <returns>The field value.</returns>
    public static string Format(Link link)
    {
        ArgumentNullException.ThrowIfNull(link);
        var sb = new StringBuilder();
        sb.Append('<').Append(Uris.ToText(link.Href)).Append(">; rel=").Append(Quote(link.Rel));
        foreach (KeyValuePair<string, string> p in link.Parameters)
        {
            sb.Append("; ").Append(p.Key);
            if (p.Value.Length > 0) sb.Append('=').Append(Quote(p.Value));
        }
        return sb.ToString();
    }

    /// <summary>Serializes several links into one field value, separated by <c>", "</c>.</summary>
    /// <param name="links">The links.</param>
    /// <returns>The field value.</returns>
    public static string Format(IEnumerable<Link> links)
    {
        ArgumentNullException.ThrowIfNull(links);
        return string.Join(", ", links.Select(Format));
    }

    private static string Quote(string v) => "\"" + v.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";

    /// <summary>The first link with relation <paramref name="rel"/>, or null.</summary>
    /// <param name="links">The links.</param>
    /// <param name="rel">The relation type.</param>
    /// <returns>The link.</returns>
    public static Link? First(IEnumerable<Link> links, string rel)
    {
        string r = NormalizeRel(rel);
        return links.FirstOrDefault(l => l.Rel == r);
    }

    /// <summary>All links with relation <paramref name="rel"/>.</summary>
    /// <param name="links">The links.</param>
    /// <param name="rel">The relation type.</param>
    /// <returns>The links.</returns>
    public static IReadOnlyList<Link> All(IEnumerable<Link> links, string rel)
    {
        string r = NormalizeRel(rel);
        return links.Where(l => l.Rel == r).ToList().AsReadOnly();
    }
}
