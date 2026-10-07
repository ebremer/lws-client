// SPDX-License-Identifier: MIT
using System.Text.RegularExpressions;

namespace Ebremer.Lws.Internal;

/// <summary>URI reference resolution and comparisons (internal).</summary>
internal static partial class Uris
{
    [GeneratedRegex("^[A-Za-z][A-Za-z0-9+.\\-]*:")]
    private static partial Regex SchemePrefix();

    /// <summary>Whether a reference starts with a scheme (an absolute URI, not a path that .NET would read as a file URI).</summary>
    public static bool HasScheme(string reference) => SchemePrefix().IsMatch(reference);

    /// <summary>
    /// Resolves a URI reference against a base (RFC 3986 section 5.2), or returns null when it is malformed or
    /// relative without a base. An absolute path such as <c>/a/b</c> is never taken for a file URI.
    /// </summary>
    public static Uri? Resolve(Uri? baseUri, string reference)
    {
        ArgumentNullException.ThrowIfNull(reference);
        string r = reference.Trim();
        if (HasScheme(r)) return Uri.TryCreate(r, UriKind.Absolute, out Uri? abs) ? abs : null;
        if (baseUri is null || !baseUri.IsAbsoluteUri) return null;
        return Uri.TryCreate(baseUri, r, out Uri? resolved) ? resolved : null;
    }

    /// <summary>The string form used on the wire and in comparisons: the absolute URI, or the original string.</summary>
    public static string ToText(Uri uri) => uri.IsAbsoluteUri ? uri.AbsoluteUri : uri.OriginalString;

    /// <summary>Requires an absolute http(s) URL as a request target.</summary>
    public static Uri RequireHttp(Uri? uri, string paramName)
    {
        ArgumentNullException.ThrowIfNull(uri, paramName);
        if (!uri.IsAbsoluteUri || uri.IsFile || !HasScheme(uri.OriginalString)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ArgumentException($"Not an absolute http(s) URL: {uri.OriginalString}", paramName);
        }
        return uri;
    }

    /// <summary>Whether two URIs share scheme, host and effective port.</summary>
    public static bool SameOrigin(Uri a, Uri b) =>
        a.IsAbsoluteUri && b.IsAbsoluteUri
        && string.Equals(a.Scheme, b.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(a.IdnHost, b.IdnHost, StringComparison.OrdinalIgnoreCase)
        && a.Port == b.Port;

    /// <summary>
    /// Whether <paramref name="uri"/> is logically contained in <paramref name="realm"/>: same origin, and the path
    /// equals the realm path or lies beneath it (the realm path is treated as a directory).
    /// </summary>
    public static bool Contains(Uri realm, Uri uri)
    {
        if (!SameOrigin(realm, uri)) return false;
        string rp = realm.AbsolutePath;
        string up = uri.AbsolutePath.Length == 0 ? "/" : uri.AbsolutePath;
        if (rp.Length == 0 || rp == "/") return true;
        if (up == rp) return true;
        string dir = rp.EndsWith('/') ? rp : rp + "/";
        return up.StartsWith(dir, StringComparison.Ordinal) || up + "/" == dir;
    }

    /// <summary>Loopback hosts that may use plain HTTP for authorization servers.</summary>
    public static bool IsLoopback(Uri u)
    {
        if (!u.IsAbsoluteUri) return false;
        string h = u.Host.ToLowerInvariant();
        return h is "localhost" or "127.0.0.1" or "[::1]" or "::1" || h.EndsWith(".localhost", StringComparison.Ordinal);
    }

    /// <summary>The string without its fragment.</summary>
    public static string WithoutFragment(string s)
    {
        int i = s.IndexOf('#', StringComparison.Ordinal);
        return i < 0 ? s : s[..i];
    }

    /// <summary>Compares two URI strings ignoring one trailing slash.</summary>
    public static bool EqualsIgnoringTrailingSlash(string? a, string? b)
    {
        if (a is null || b is null) return false;
        return Strip(a) == Strip(b);

        static string Strip(string s) => s.EndsWith('/') ? s[..^1] : s;
    }
}
