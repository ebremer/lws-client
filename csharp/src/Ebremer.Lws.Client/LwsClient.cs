// SPDX-License-Identifier: MIT
using Ebremer.Lws.Auth;
using Ebremer.Lws.Http;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws;

/// <summary>
/// Client for the W3C Linked Web Storage (LWS) Protocol 1.0.
/// <code>
/// using var client = new LwsClient(new LwsClientOptions
/// {
///     Authenticator = new TokenExchangeAuthenticator(SelfSignedCredentials.DidKey(SigningKey.GenerateP256())),
/// });
/// StorageDescription storage = await client.DiscoverStorageAsync(new Uri("https://storage.example/root/"));
/// CreateResult note = await client.CreateTextAsync(storage.GetStorageRoot(), "Hello", options: new() { Slug = "hello.txt" });
/// await foreach (ContainedResource item in client.ListContainerAsync(storage.GetStorageRoot())) Console.WriteLine(item.Id);
/// </code>
/// Instances are immutable and thread-safe. Every operation is asynchronous and takes a
/// <see cref="CancellationToken"/>. Errors are <see cref="LwsException"/>s (for example
/// <see cref="NotFoundException"/>, <see cref="PreconditionFailedException"/>, <see cref="ConflictException"/>);
/// arguments that are not absolute http(s) URLs are <see cref="ArgumentException"/>s.
/// </summary>
/// <remarks>
/// Redirects are followed by the client itself (at most <see cref="LwsClientOptions.MaxRedirects"/>), authorizing
/// every hop afresh for its own URL, so an access token is never sent outside its realm. <c>POST</c> is never sent
/// twice, except for the single retry after a <c>401</c> that the authenticator handled (when nothing was created).
/// </remarks>
public sealed partial class LwsClient : IDisposable
{
    /// <summary>The library version.</summary>
    public const string Version = "0.1.0";

    /// <summary>The default <c>User-Agent</c>.</summary>
    public const string DefaultUserAgent = "lws-client-csharp/" + Version;

    private static readonly HttpMethod Query = new("QUERY");

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly IReadOnlyList<KeyValuePair<string, string>> _defaultHeaders;

    /// <summary>Creates a client.</summary>
    /// <param name="options">The configuration (default: anonymous, a private HTTP client).</param>
    public LwsClient(LwsClientOptions? options = null)
        : this(options ?? new LwsClientOptions(), null)
    {
    }

    private LwsClient(LwsClientOptions options, HttpClient? shared)
    {
        if (options.MaxRedirects < 0) throw new ArgumentOutOfRangeException(nameof(options), "MaxRedirects must not be negative");
        if (options.Timeout <= TimeSpan.Zero && options.Timeout != System.Threading.Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Timeout must be positive");
        }
        Options = options;
        if (shared is not null)
        {
            _http = shared;
        }
        else if (options.HttpClient is not null)
        {
            _http = options.HttpClient;
        }
        else if (options.HttpMessageHandler is not null)
        {
            _http = new HttpClient(options.HttpMessageHandler, disposeHandler: false) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
            _ownsHttp = true;
        }
        else
        {
            _http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false })
            {
                Timeout = System.Threading.Timeout.InfiniteTimeSpan,
            };
            _ownsHttp = true;
        }
        var defaults = new List<KeyValuePair<string, string>>();
        if (options.DefaultHeaders is not null) defaults.AddRange(options.DefaultHeaders);
        _defaultHeaders = defaults.AsReadOnly();
    }

    /// <summary>The configuration.</summary>
    public LwsClientOptions Options { get; }

    /// <summary>The configured authenticator, if any.</summary>
    public IAuthenticator? Authenticator => Options.Authenticator;

    /// <summary>A client with another authenticator, sharing this client's HTTP connections (dispose it independently).</summary>
    /// <param name="authenticator">The authenticator, or null for anonymous requests.</param>
    /// <returns>The new client.</returns>
    public LwsClient WithAuthenticator(IAuthenticator? authenticator) => new(Options with { Authenticator = authenticator }, _http);

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }

    // ============================================================================================
    // The request pipeline
    // ============================================================================================

    /// <summary>A request body: bytes are replayable (auth retry, 307/308), a stream is sent at most once.</summary>
    internal abstract class RequestBody
    {
        public abstract bool Replayable { get; }

        public abstract HttpContent CreateContent();
    }

    internal sealed class BytesBody(ReadOnlyMemory<byte> bytes) : RequestBody
    {
        public override bool Replayable => true;

        public override HttpContent CreateContent() => new ReadOnlyMemoryContent(bytes);
    }

    internal sealed class StreamBody(Stream stream) : RequestBody
    {
        private int _used;

        public override bool Replayable => false;

        public override HttpContent CreateContent()
        {
            if (Interlocked.Exchange(ref _used, 1) == 1) throw new InvalidOperationException("A stream body can be sent only once");
            return new StreamContent(stream);
        }
    }

    internal sealed record Call(HttpMethod Method, Uri Uri, RequestBody? Body, IReadOnlyList<KeyValuePair<string, string>> Headers, TimeSpan? Timeout);

    internal sealed record RawResponse(string Method, Uri Uri, int Status, HeaderMap Headers, byte[] Body);

    private TimeSpan TimeoutFor(Call call) => call.Timeout ?? Options.Timeout;

    /// <summary>Sends a call (authenticating, retrying once after a handled 401, following redirects) and buffers the final response.</summary>
    internal async Task<RawResponse> SendAsync(Call call, CancellationToken cancellationToken)
    {
        (HttpResponseMessage response, HttpMethod method, Uri uri) = await SendCoreAsync(call, cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] body = await ReadBodyAsync(response, method, uri, TimeoutFor(call), cancellationToken).ConfigureAwait(false);
            return new RawResponse(method.Method, uri, (int)response.StatusCode, HeaderMap.From(response), body);
        }
        finally
        {
            Release(response);
        }
    }

    internal async Task<(HttpResponseMessage Response, HttpMethod Method, Uri Uri)> SendCoreAsync(Call call, CancellationToken cancellationToken)
    {
        HttpMethod method = call.Method;
        Uri uri = call.Uri;
        RequestBody? body = call.Body;
        IReadOnlyList<KeyValuePair<string, string>> headers = call.Headers;
        IAuthenticator? authenticator = Options.Authenticator;
        bool userAuth = Find(headers, "Authorization") is not null || Find(_defaultHeaders, "Authorization") is not null;
        if (authenticator is not null && body is { Replayable: false })
        {
            await EstablishCredentialsAsync(authenticator, call, cancellationToken).ConfigureAwait(false);
        }
        for (int hops = 0; ; hops++)
        {
            AuthRequest attempt = await PrepareAsync(method, uri, headers, userAuth, cancellationToken).ConfigureAwait(false);
            HttpResponseMessage response = await DispatchAsync(attempt, method, body, TimeoutFor(call), cancellationToken).ConfigureAwait(false);
            if ((int)response.StatusCode == 401 && authenticator is not null && body is not { Replayable: false })
            {
                bool retry;
                try
                {
                    retry = await authenticator.HandleChallengeAsync(attempt, new AuthResponse(uri, 401, HeaderMap.From(response)), cancellationToken)
                        .ConfigureAwait(false);
                }
                catch
                {
                    Release(response);
                    throw;
                }
                if (retry)
                {
                    Release(response);
                    attempt = await PrepareAsync(method, uri, headers, userAuth, cancellationToken).ConfigureAwait(false);
                    response = await DispatchAsync(attempt, method, body, TimeoutFor(call), cancellationToken).ConfigureAwait(false);
                }
            }

            int status = (int)response.StatusCode;
            if (status is not (301 or 302 or 303 or 307 or 308)) return (response, method, uri);
            string? location = response.Headers.NonValidated.TryGetValues("Location", out System.Net.Http.Headers.HeaderStringValues values) ? values.FirstOrDefault() : null;
            Uri? target = location is null ? null : Uris.Resolve(uri, location);
            if (target is null || target.Scheme is not ("http" or "https")) return (response, method, uri);
            bool safe = method == HttpMethod.Get || method == HttpMethod.Head || method == HttpMethod.Options || method == Query;
            HttpMethod nextMethod = method;
            RequestBody? nextBody = body;
            switch (status)
            {
                case 303 when safe:
                    // See Other: retrieve the result with GET (HEAD stays HEAD), without a body.
                    if (method != HttpMethod.Head) nextMethod = HttpMethod.Get;
                    nextBody = null;
                    headers = headers.Where(h => !h.Key.StartsWith("Content-", StringComparison.OrdinalIgnoreCase)).ToList();
                    break;
                case 301 or 302 when safe:
                    break;
                case 307 or 308 when body is not { Replayable: false }:
                    break;
                default:
                    return (response, method, uri);
            }
            Release(response);
            if (hops + 1 > Options.MaxRedirects)
            {
                throw new ProtocolException($"Too many redirects (more than {Options.MaxRedirects}) at {Uris.ToText(uri)}");
            }
            // An Authorization header the caller set explicitly survives same-origin redirects only; tokens of the
            // authenticator are re-evaluated for the new URL by PrepareAsync.
            if (userAuth && !Uris.SameOrigin(uri, target)) userAuth = false;
            method = nextMethod;
            uri = target;
            body = nextBody;
        }
    }

    /// <summary>Before streaming a body that cannot be replayed, establishes a token with a <c>HEAD</c> of the target.</summary>
    private async Task EstablishCredentialsAsync(IAuthenticator authenticator, Call call, CancellationToken cancellationToken)
    {
        var probe = new AuthRequest(call.Method.Method, call.Uri, _defaultHeaders);
        await authenticator.AuthorizeAsync(probe, cancellationToken).ConfigureAwait(false);
        if (probe.GetHeader("Authorization") is not null) return;
        (HttpResponseMessage head, _, _) = await SendCoreAsync(new Call(HttpMethod.Head, call.Uri, null, [], call.Timeout), cancellationToken)
            .ConfigureAwait(false);
        Release(head);
    }

    private async Task<AuthRequest> PrepareAsync(HttpMethod method, Uri uri, IReadOnlyList<KeyValuePair<string, string>> callHeaders,
        bool keepUserAuthorization, CancellationToken cancellationToken)
    {
        var request = new AuthRequest(method.Method, uri);
        foreach (KeyValuePair<string, string> h in _defaultHeaders) request.AddHeader(h.Key, h.Value);
        if (Options.UserAgent is { } ua && request.GetHeader("User-Agent") is null && Find(callHeaders, "User-Agent") is null)
        {
            request.AddHeader("User-Agent", ua);
        }
        foreach (string name in callHeaders.Select(h => h.Key).Distinct(StringComparer.OrdinalIgnoreCase)) request.RemoveHeader(name);
        foreach (KeyValuePair<string, string> h in callHeaders) request.AddHeader(h.Key, h.Value);
        if (!keepUserAuthorization) request.RemoveHeader("Authorization");
        if (Options.Authenticator is { } authenticator) await authenticator.AuthorizeAsync(request, cancellationToken).ConfigureAwait(false);
        return request;
    }

    private async Task<HttpResponseMessage> DispatchAsync(AuthRequest attempt, HttpMethod method, RequestBody? body, TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var message = new HttpRequestMessage(method, attempt.Uri) { Content = body?.CreateContent() };
        foreach (KeyValuePair<string, string> h in attempt.Headers)
        {
            if (string.Equals(h.Key, "Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
            if (message.Headers.TryAddWithoutValidation(h.Key, h.Value)) continue;
            if (message.Content is null)
            {
                if (!string.Equals(h.Key, "Content-Type", StringComparison.OrdinalIgnoreCase)) continue;
                message.Content = new ByteArrayContent([]);
            }
            message.Content.Headers.TryAddWithoutValidation(h.Key, h.Value);
        }
        using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (timeout != System.Threading.Timeout.InfiniteTimeSpan) cts.CancelAfter(timeout);
        try
        {
            return await _http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
        }
        catch (Exception e) when (IsTransport(e, cancellationToken))
        {
            message.Dispose();
            throw Transport(e, method, attempt.Uri, timeout);
        }
        catch
        {
            message.Dispose();
            throw;
        }
    }

    private static async Task<byte[]> ReadBodyAsync(HttpResponseMessage response, HttpMethod method, Uri uri, TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (timeout != System.Threading.Timeout.InfiniteTimeSpan) cts.CancelAfter(timeout);
        try
        {
            return await response.Content.ReadAsByteArrayAsync(cts.Token).ConfigureAwait(false);
        }
        catch (Exception e) when (IsTransport(e, cancellationToken))
        {
            throw Transport(e, method, uri, timeout);
        }
    }

    /// <summary>A failure to get a response: an HTTP stack error, or a cancellation that is a timeout (not the caller's).</summary>
    private static bool IsTransport(Exception e, CancellationToken cancellationToken) =>
        e is HttpRequestException or IOException || (e is OperationCanceledException && !cancellationToken.IsCancellationRequested);

    private static LwsTransportException Transport(Exception e, HttpMethod method, Uri uri, TimeSpan timeout) => e is OperationCanceledException
        ? new LwsTransportException($"{method} {Uris.ToText(uri)} timed out after {timeout.TotalSeconds:0.###} s", new TimeoutException(e.Message, e))
        : new LwsTransportException($"{method} {Uris.ToText(uri)} failed: {e.Message}", e);

    private static void Release(HttpResponseMessage response)
    {
        HttpRequestMessage? request = response.RequestMessage;
        response.Dispose();
        request?.Dispose();
    }

    private static string? Find(IEnumerable<KeyValuePair<string, string>> headers, string name)
    {
        foreach (KeyValuePair<string, string> h in headers)
        {
            if (string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)) return h.Value;
        }
        return null;
    }

    // ============================================================================================
    // Helpers of the operations
    // ============================================================================================

    private sealed class HeaderList : List<KeyValuePair<string, string>>
    {
        public HeaderList Set(string name, string? value)
        {
            RemoveAll(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase));
            if (value is not null) Add(new(name, value));
            return this;
        }

        public HeaderList Append(string name, string value)
        {
            Add(new(name, value));
            return this;
        }

        public HeaderList With(RequestOptions? options)
        {
            if (options?.Headers is { } extra)
            {
                foreach (KeyValuePair<string, string> h in extra) Set(h.Key, h.Value);
            }
            return this;
        }
    }

    private Task<RawResponse> SendAsync(HttpMethod method, Uri uri, RequestBody? body, HeaderList headers, RequestOptions? options,
        CancellationToken cancellationToken) =>
        SendAsync(new Call(method, uri, body, headers.With(options), options?.Timeout), cancellationToken);

    private static void Check(RawResponse response)
    {
        if (response.Status / 100 != 2) throw HttpException.Create(response.Method, response.Uri, response.Status, response.Headers, response.Body);
    }

    private static ResourceMetadata Metadata(RawResponse response) => new(response.Uri, response.Status, response.Headers);

    private static void RequireLwsJson(RawResponse response)
    {
        string? essence = HeaderLists.Essence(response.Headers.GetFirst("content-type"));
        if (essence is null) return;
        if (essence is not (Lws.MediaType.LwsJson or Lws.MediaType.LdJson or Lws.MediaType.Json))
        {
            throw new ProtocolException($"Unexpected media type {essence} for an LWS JSON representation at {Uris.ToText(response.Uri)}");
        }
    }

    private static Uri Target(Uri? url, string paramName) => Uris.RequireHttp(url, paramName);
}
