// SPDX-License-Identifier: MIT
using System.Net;
using System.Text;
using Ebremer.Lws.Http;

namespace Ebremer.Lws.Tests.Support;

/// <summary>A request as the fake server received it.</summary>
internal sealed record Recorded(string Method, Uri Uri, HeaderMap Headers, byte[] Body)
{
    public string Text => Encoding.UTF8.GetString(Body);

    public string? Header(string name) => Headers.GetFirst(name);

    public IReadOnlyList<string> HeaderValues(string name) => Headers.GetAll(name);

    public string Url => Uri.AbsoluteUri;
}

/// <summary>
/// An in-process HTTP test double: routes by method and absolute URL, records every request, and never follows
/// redirects (like a handler with <c>AllowAutoRedirect = false</c>).
/// </summary>
internal sealed class FakeServer : HttpMessageHandler
{
    private readonly List<(string Method, string Url, Func<Recorded, HttpResponseMessage> Respond)> _routes = [];
    private readonly List<Recorded> _requests = [];

    public IReadOnlyList<Recorded> Requests
    {
        get
        {
            lock (_requests) return [.. _requests];
        }
    }

    public Func<Recorded, CancellationToken, Task>? BeforeRespond { get; set; }

    /// <summary>Adds a route; a later route for the same method and URL wins.</summary>
    public FakeServer On(string method, string url, Func<Recorded, HttpResponseMessage> respond)
    {
        lock (_routes) _routes.Insert(0, (method, new Uri(url).AbsoluteUri, respond));
        return this;
    }

    /// <summary>Adds a route answering with a fixed response factory.</summary>
    public FakeServer On(string method, string url, Func<HttpResponseMessage> respond) => On(method, url, _ => respond());

    /// <summary>Answers the given responses in order, then repeats the last.</summary>
    public FakeServer OnSequence(string method, string url, params Func<Recorded, HttpResponseMessage>[] responses)
    {
        int i = 0;
        return On(method, url, r => responses[Math.Min(Interlocked.Increment(ref i) - 1, responses.Length - 1)](r));
    }

    public IEnumerable<Recorded> RequestsTo(string method, string url) =>
        Requests.Where(r => r.Method == method && r.Url == new Uri(url).AbsoluteUri);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        byte[] body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        var pairs = new List<KeyValuePair<string, string[]>>();
        foreach (var h in request.Headers.NonValidated) pairs.Add(new(h.Key, [.. h.Value]));
        if (request.Content is not null)
        {
            foreach (var h in request.Content.Headers.NonValidated) pairs.Add(new(h.Key, [.. h.Value]));
        }
        var recorded = new Recorded(request.Method.Method, request.RequestUri!, HeaderMap.From(pairs), body);
        lock (_requests) _requests.Add(recorded);
        if (BeforeRespond is { } before) await before(recorded, cancellationToken);
        Func<Recorded, HttpResponseMessage>? respond;
        lock (_routes)
        {
            respond = _routes.FirstOrDefault(r => r.Method == recorded.Method && r.Url == recorded.Uri.AbsoluteUri).Respond;
        }
        HttpResponseMessage response = respond is null ? Respond.Status(404) : respond(recorded);
        response.RequestMessage = request;
        return response;
    }
}

/// <summary>Response factories for the fake server.</summary>
internal static class Respond
{
    public static HttpResponseMessage Status(int status, params (string Name, string Value)[] headers) => Make(status, null, null, headers);

    public static HttpResponseMessage Json(int status, string json, string contentType = "application/json", params (string Name, string Value)[] headers) =>
        Make(status, Encoding.UTF8.GetBytes(json), contentType, headers);

    public static HttpResponseMessage Text(int status, string text, string contentType = "text/plain", params (string Name, string Value)[] headers) =>
        Make(status, Encoding.UTF8.GetBytes(text), contentType, headers);

    public static HttpResponseMessage Make(int status, byte[]? body, string? contentType, params (string Name, string Value)[] headers)
    {
        var response = new HttpResponseMessage((HttpStatusCode)status) { Content = new ByteArrayContent(body ?? []) };
        if (contentType is not null) response.Content.Headers.TryAddWithoutValidation("Content-Type", contentType);
        foreach ((string name, string value) in headers)
        {
            if (!response.Headers.TryAddWithoutValidation(name, value)) response.Content.Headers.TryAddWithoutValidation(name, value);
        }
        return response;
    }
}
