// SPDX-License-Identifier: MIT
using System.Globalization;
using Ebremer.Lws.Http;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws;

/// <summary>The metadata of a storage resource, parsed from response headers.</summary>
public sealed class ResourceMetadata
{
    /// <summary>Creates the metadata of a response.</summary>
    /// <param name="url">The final request URL (after redirects).</param>
    /// <param name="status">The HTTP status code.</param>
    /// <param name="headers">The response headers.</param>
    public ResourceMetadata(Uri url, int status, HeaderMap headers)
    {
        Url = url ?? throw new ArgumentNullException(nameof(url));
        Status = status;
        Headers = headers ?? throw new ArgumentNullException(nameof(headers));
        Links = LinkHeader.Parse(headers.GetAll("link"), url);
    }

    /// <summary>The final request URL.</summary>
    public Uri Url { get; }

    /// <summary>The HTTP status code.</summary>
    public int Status { get; }

    /// <summary>The raw response headers.</summary>
    public HeaderMap Headers { get; }

    /// <summary>Every <c>Link</c> header link (one per relation type), resolved against <see cref="Url"/>.</summary>
    public IReadOnlyList<Link> Links { get; }

    /// <summary>The entity tag, verbatim including quotes and any <c>W/</c> prefix: send it back unchanged in <c>If-Match</c>.</summary>
    public string? ETag => Headers.GetFirst("etag");

    /// <summary>The raw <c>Last-Modified</c> header value.</summary>
    public string? LastModifiedRaw => Headers.GetFirst("last-modified");

    /// <summary>The <c>Last-Modified</c> date, when parseable.</summary>
    public DateTimeOffset? LastModified =>
        LastModifiedRaw is { } raw
        && DateTimeOffset.TryParseExact(raw.Trim(), "r", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset d)
            ? d
            : null;

    /// <summary>The <c>Content-Type</c> header value.</summary>
    public string? ContentType => Headers.GetFirst("content-type");

    /// <summary>The <c>Content-Length</c>, when present.</summary>
    public long? ContentLength =>
        Headers.GetFirst("content-length") is { } v && long.TryParse(v.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out long n) ? n : null;

    /// <summary>The linkset resource (<c>rel="linkset"</c>).</summary>
    public Uri? Linkset => GetLink(Lws.Rel.Linkset)?.Href;

    /// <summary>The parent container (<c>rel="up"</c>).</summary>
    public Uri? Parent => GetLink(Lws.Rel.Up)?.Href;

    /// <summary>The storage (<c>rel="https://www.w3.org/ns/lws#storage"</c>).</summary>
    public Uri? Storage => GetLink(Lws.Rel.Storage)?.Href;

    /// <summary>The resource types (the targets of <c>rel="type"</c> links).</summary>
    public IReadOnlyList<string> Types => GetLinks(Lws.Rel.Type).Select(l => Uris.ToText(l.Href)).ToList().AsReadOnly();

    /// <summary>Whether the resource is a container.</summary>
    public bool IsContainer => HasType(Lws.Types.Container);

    /// <summary>Whether the resource is a data resource.</summary>
    public bool IsDataResource => HasType(Lws.Types.DataResource);

    /// <summary>The methods of the <c>Allow</c> header.</summary>
    public IReadOnlyList<string> Allow => HeaderLists.Split(Headers.GetAll("allow"));

    /// <summary>The patch formats of the <c>Accept-Patch</c> header.</summary>
    public IReadOnlyList<string> AcceptPatch => HeaderLists.Split(Headers.GetAll("accept-patch"));

    /// <summary>Whether a <c>rel="type"</c> link declares <paramref name="type"/>.</summary>
    /// <param name="type">A type (short term, compact or full IRI).</param>
    /// <returns>Whether it is declared.</returns>
    public bool HasType(string type) => Lws.HasType(Types, type);

    /// <summary>The first link with relation <paramref name="rel"/>, or null.</summary>
    /// <param name="rel">The relation type.</param>
    /// <returns>The link.</returns>
    public Link? GetLink(string rel) => LinkHeader.First(Links, rel);

    /// <summary>All links with relation <paramref name="rel"/>.</summary>
    /// <param name="rel">The relation type.</param>
    /// <returns>The links.</returns>
    public IReadOnlyList<Link> GetLinks(string rel) => LinkHeader.All(Links, rel);

    /// <summary>The first value of a header (case-insensitive name), or null.</summary>
    /// <param name="name">The header name.</param>
    /// <returns>The value.</returns>
    public string? GetHeader(string name) => Headers.GetFirst(name);

    /// <inheritdoc/>
    public override string ToString() => $"{Status} {Uris.ToText(Url)}";
}
