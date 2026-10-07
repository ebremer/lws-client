// SPDX-License-Identifier: MIT
using System.Net.Http.Headers;
using Ebremer.Lws.Auth;
using Ebremer.Lws.Http;

namespace Ebremer.Lws;

/// <summary>Configuration of an <see cref="LwsClient"/>.</summary>
public sealed record LwsClientOptions
{
    /// <summary>
    /// The HTTP client to use. Configure its handler with <c>AllowAutoRedirect = false</c>: the client follows
    /// redirects itself so that credentials are re-evaluated for every target. Not disposed by the client.
    /// </summary>
    public HttpClient? HttpClient { get; init; }

    /// <summary>
    /// The HTTP handler to use (e.g. a test double), when <see cref="HttpClient"/> is not given. It should not follow
    /// redirects either. Not disposed by the client.
    /// </summary>
    public HttpMessageHandler? HttpMessageHandler { get; init; }

    /// <summary>Request authentication (e.g. <see cref="TokenExchangeAuthenticator"/>); anonymous when null.</summary>
    public IAuthenticator? Authenticator { get; init; }

    /// <summary>The <c>User-Agent</c> header (default <c>lws-client-csharp/0.1.0</c>; null sends none).</summary>
    public string? UserAgent { get; init; } = LwsClient.DefaultUserAgent;

    /// <summary>Headers sent with every request.</summary>
    public IReadOnlyDictionary<string, string>? DefaultHeaders { get; init; }

    /// <summary>The timeout of each HTTP request (each redirect hop), default 30 seconds.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>The most redirects followed for one operation (default 10).</summary>
    public int MaxRedirects { get; init; } = 10;
}

/// <summary>Options accepted by every operation.</summary>
public record RequestOptions
{
    /// <summary>Extra request headers.</summary>
    public IReadOnlyDictionary<string, string>? Headers { get; init; }

    /// <summary>A timeout for this operation's requests, instead of <see cref="LwsClientOptions.Timeout"/>.</summary>
    public TimeSpan? Timeout { get; init; }
}

/// <summary>Options of <see cref="LwsClient.ReadAsync"/>.</summary>
public sealed record ReadOptions : RequestOptions
{
    /// <summary>The <c>Accept</c> header (content negotiation).</summary>
    public string? Accept { get; init; }

    /// <summary>A byte range: <c>new RangeHeaderValue(0, 99)</c> is <c>bytes=0-99</c>, <c>(null, 100)</c> the last 100 bytes.</summary>
    public RangeHeaderValue? Range { get; init; }

    /// <summary>Conditional read: answered <c>304</c> (<see cref="Resource.NotModified"/>) while the entity tag matches.</summary>
    public string? IfNoneMatch { get; init; }

    /// <summary>Conditional read by date.</summary>
    public DateTimeOffset? IfModifiedSince { get; init; }

    /// <summary>The <c>Prefer</c> header (e.g. link relation preferences).</summary>
    public string? Prefer { get; init; }
}

/// <summary>Options of the create operations.</summary>
public sealed record CreateOptions : RequestOptions
{
    /// <summary>The identity hint for the new resource's name, sent as <c>Slug</c>.</summary>
    public string? Slug { get; init; }

    /// <summary>User-managed metadata links, sent as <c>Link</c> headers.</summary>
    public IReadOnlyList<Link>? Links { get; init; }

    /// <summary>Additional type IRIs, sent as <c>Link: &lt;type&gt;; rel="type"</c>.</summary>
    public IReadOnlyList<string>? Types { get; init; }
}

/// <summary>Options of <see cref="LwsClient.UpdateAsync(Uri, ReadOnlyMemory{byte}, string, UpdateOptions?, CancellationToken)"/> and the patch operations.</summary>
public sealed record UpdateOptions : RequestOptions
{
    /// <summary>Only update while the current entity tag matches (optimistic concurrency); else <see cref="PreconditionFailedException"/>.</summary>
    public string? IfMatch { get; init; }

    /// <summary><c>If-None-Match</c> (e.g. <c>"*"</c> to create only).</summary>
    public string? IfNoneMatch { get; init; }

    /// <summary>Links sent with the update (applied to the linkset only with <see cref="SetLinkset"/>).</summary>
    public IReadOnlyList<Link>? Links { get; init; }

    /// <summary>Update the content and the linkset atomically (<c>Prefer: set-linkset</c>).</summary>
    public bool SetLinkset { get; init; }
}

/// <summary>Options of <see cref="LwsClient.DeleteAsync"/>.</summary>
public sealed record DeleteOptions : RequestOptions
{
    /// <summary>Only delete while the current entity tag matches.</summary>
    public string? IfMatch { get; init; }

    /// <summary>Delete a container and everything in it (<c>Depth: infinity</c>).</summary>
    public bool Recursive { get; init; }
}
