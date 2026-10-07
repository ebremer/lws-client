// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Text;

namespace Ebremer.Lws.Http;

/// <summary>
/// The identity hint of a create request, sent as the <c>Slug</c> header (RFC 5023 section 9.7; the LWS core
/// specification defines the hint but not its header).
/// </summary>
public static class Slug
{
    /// <summary>The header field name.</summary>
    public const string HeaderName = "Slug";

    /// <summary>Percent-encodes a slug: non-ASCII (as UTF-8), control characters and <c>%</c>.</summary>
    /// <param name="slug">The identity hint.</param>
    /// <returns>The header value.</returns>
    public static string Encode(string slug)
    {
        ArgumentNullException.ThrowIfNull(slug);
        var sb = new StringBuilder();
        foreach (byte b in Encoding.UTF8.GetBytes(slug))
        {
            if (b >= 0x20 && b < 0x7f && b != '%') sb.Append((char)b);
            else sb.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }
}
