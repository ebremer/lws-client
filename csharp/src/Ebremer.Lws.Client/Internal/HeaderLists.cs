// SPDX-License-Identifier: MIT
using System.Text;

namespace Ebremer.Lws.Internal;

/// <summary>Splitting of comma-separated list header fields and media type helpers (internal).</summary>
internal static class HeaderLists
{
    /// <summary>Splits list-based field values on commas outside quoted strings; elements are trimmed, empties dropped.</summary>
    public static IReadOnlyList<string> Split(IEnumerable<string> values)
    {
        var output = new List<string>();
        foreach (string v in values)
        {
            if (v is null) continue;
            var cur = new StringBuilder();
            bool quoted = false;
            for (int i = 0; i < v.Length; i++)
            {
                char c = v[i];
                if (quoted)
                {
                    cur.Append(c);
                    if (c == '\\' && i + 1 < v.Length) cur.Append(v[++i]);
                    else if (c == '"') quoted = false;
                }
                else if (c == '"')
                {
                    quoted = true;
                    cur.Append(c);
                }
                else if (c == ',')
                {
                    Add(output, cur);
                    cur.Clear();
                }
                else
                {
                    cur.Append(c);
                }
            }
            Add(output, cur);
        }
        return output.AsReadOnly();
    }

    private static void Add(List<string> output, StringBuilder cur)
    {
        string s = cur.ToString().Trim();
        if (s.Length > 0) output.Add(s);
    }

    /// <summary>The media type without parameters, lower-cased, or null.</summary>
    public static string? Essence(string? contentType)
    {
        if (contentType is null) return null;
        int i = contentType.IndexOf(';', StringComparison.Ordinal);
        string s = (i < 0 ? contentType : contentType[..i]).Trim().Trim('"');
        return s.Length == 0 ? null : s.ToLowerInvariant();
    }

    /// <summary>Whether the media type is JSON (<c>application/json</c> or any <c>+json</c> suffix).</summary>
    public static bool IsJson(string? contentType)
    {
        string? e = Essence(contentType);
        return e is not null && (e == "application/json" || e.EndsWith("+json", StringComparison.Ordinal));
    }

    /// <summary>The <c>charset</c> parameter of a content type, or null.</summary>
    public static string? Charset(string? contentType)
    {
        if (contentType is null) return null;
        foreach (string part in contentType.Split(';'))
        {
            string p = part.Trim();
            if (p.StartsWith("charset=", StringComparison.OrdinalIgnoreCase))
            {
                string name = p[8..].Trim().Trim('"');
                return name.Length == 0 ? null : name;
            }
        }
        return null;
    }

    /// <summary>Decodes text with the charset of the content type (UTF-8 by default or when unknown).</summary>
    public static string Decode(ReadOnlySpan<byte> bytes, string? contentType)
    {
        Encoding encoding = Encoding.UTF8;
        string? charset = Charset(contentType);
        if (charset is not null)
        {
            try
            {
                encoding = Encoding.GetEncoding(charset);
            }
            catch (ArgumentException)
            {
                Encoding? codePage = CodePagesEncodingProvider.Instance.GetEncoding(charset);
                if (codePage is not null) encoding = codePage;
            }
        }
        if (encoding is UTF8Encoding && bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            bytes = bytes[3..];
        }
        return encoding.GetString(bytes);
    }
}
