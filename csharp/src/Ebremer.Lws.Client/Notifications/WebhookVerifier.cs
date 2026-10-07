// SPDX-License-Identifier: MIT
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Ebremer.Lws.Auth;
using Ebremer.Lws.Http;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws.Notifications;

/// <summary>Options of <see cref="WebhookVerifier"/>.</summary>
public sealed record WebhookVerifierOptions
{
    /// <summary>The client that retrieves storage descriptions (the signing keys). Default: a new anonymous client.</summary>
    public LwsClient? Client { get; init; }

    /// <summary>A custom storage description source; overrides <see cref="Client"/>.</summary>
    public Func<Uri, CancellationToken, Task<StorageDescription>>? StorageDescriptionResolver { get; init; }

    /// <summary>
    /// Only accept deliveries signed by these storages (compared as URLs). When set, even to an empty list, the
    /// signing storage must be in it.
    /// </summary>
    public IReadOnlyCollection<Uri>? TrustedStorages { get; init; }

    /// <summary>The maximum age of a signature's <c>created</c> time (default 300 seconds).</summary>
    public TimeSpan MaxAge { get; init; } = TimeSpan.FromSeconds(300);

    /// <summary>The tolerated clock skew for <c>created</c> times in the future (default 300 seconds).</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(300);

    /// <summary>How long storage descriptions (keys) are cached (default 10 minutes).</summary>
    public TimeSpan KeyCacheTtl { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>The clock (default <see cref="TimeProvider.System"/>).</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}

/// <summary>A webhook delivery whose digest and signature verified.</summary>
/// <param name="Notification">The parsed notification.</param>
/// <param name="KeyId">The <c>keyid</c> of the signing key.</param>
/// <param name="Storage">The storage that signed the delivery.</param>
/// <param name="Label">The signature label used (e.g. <c>sig1</c>).</param>
/// <param name="Algorithm">The RFC 9421 algorithm (e.g. <c>ecdsa-p256-sha256</c>).</param>
public sealed record VerifiedNotification(Notification Notification, string KeyId, Uri Storage, string Label, string Algorithm);

/// <summary>
/// Verifies signed webhook deliveries (<c>lws10-notifications-webhook</c>): RFC 9530 <c>Content-Digest</c> and RFC
/// 9421 HTTP Message Signatures whose key is published in the signing storage's description (found through the
/// signature <c>keyid</c>).
/// <code>
/// var verifier = new WebhookVerifier(new WebhookVerifierOptions { Client = client, TrustedStorages = [storage.Id] });
/// VerifiedNotification v = await verifier.VerifyAsync("POST", registeredInboxUrl, headers, body);
/// </code>
/// The URL passed to <see cref="VerifyAsync(string, Uri, HeaderMap, ReadOnlyMemory{byte}, CancellationToken)"/> must
/// be the inbox URL as registered in the subscription (not the URL a reverse proxy forwarded to), because
/// <c>@scheme</c>, <c>@authority</c> and <c>@path</c> are signed.
/// </summary>
public sealed class WebhookVerifier : IDisposable
{
    /// <summary>The components every LWS webhook signature must cover.</summary>
    public static readonly IReadOnlyList<string> RequiredComponents =
        ["@method", "@scheme", "@authority", "@path", "content-type", "content-digest"];

    private readonly WebhookVerifierOptions _options;
    private readonly Func<Uri, CancellationToken, Task<StorageDescription>> _descriptions;
    private readonly LwsClient? _ownedClient;
    private readonly HashSet<string>? _trusted;
    private readonly ConcurrentDictionary<string, (StorageDescription Description, DateTimeOffset Fetched)> _cache = new(StringComparer.Ordinal);

    /// <summary>Creates a verifier.</summary>
    /// <param name="options">The options.</param>
    public WebhookVerifier(WebhookVerifierOptions? options = null)
    {
        _options = options ?? new WebhookVerifierOptions();
        if (_options.StorageDescriptionResolver is { } resolver)
        {
            _descriptions = resolver;
        }
        else
        {
            LwsClient client = _options.Client ?? (_ownedClient = new LwsClient());
            _descriptions = (uri, ct) => client.GetStorageDescriptionAsync(uri, null, ct);
        }
        if (_options.TrustedStorages is { } trusted) _trusted = [.. trusted.Select(t => Canonical(t))];
    }

    /// <inheritdoc/>
    public void Dispose() => _ownedClient?.Dispose();

    /// <summary>Verifies a delivery.</summary>
    /// <param name="method">The request method (<c>POST</c>).</param>
    /// <param name="inboxUrl">The inbox URL as registered.</param>
    /// <param name="headers">The request headers (every field line).</param>
    /// <param name="body">The raw request body.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The verified notification.</returns>
    /// <exception cref="SignatureVerificationException">Anything does not verify.</exception>
    public async Task<VerifiedNotification> VerifyAsync(string method, Uri inboxUrl, HeaderMap headers, ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(inboxUrl);
        ArgumentNullException.ThrowIfNull(headers);
        if (!inboxUrl.IsAbsoluteUri) throw new ArgumentException("The inbox URL must be absolute", nameof(inboxUrl));

        CheckDigest(Field(headers, "content-digest"), body.Span);

        IReadOnlyDictionary<string, SfMember> inputs = Dictionary(Field(headers, "signature-input"), "Signature-Input");
        IReadOnlyDictionary<string, SfMember> signatures = Dictionary(Field(headers, "signature"), "Signature");
        string? label = null;
        SfInnerList? covered = null;
        foreach (KeyValuePair<string, SfMember> e in inputs)
        {
            if (e.Value is SfInnerList il && il.Parameters.TryGetValue("keyid", out object? k) && k is string && signatures.ContainsKey(e.Key))
            {
                label = e.Key;
                covered = il;
                break;
            }
        }
        if (label is null || covered is null) throw Fail("No signature with a keyid in Signature-Input and Signature");
        if (signatures[label] is not SfItem { Value: SfByteSequence signatureBytes }) throw Fail($"Signature {label} is not a byte sequence");

        var components = new HashSet<string>(StringComparer.Ordinal);
        foreach (SfItem item in covered.Items)
        {
            if (item.Value is not string name) throw Fail("A covered component is not a string");
            if (item.Parameters.Count > 0) throw Fail($"Unsupported component parameters on {name}");
            if (!components.Add(name)) throw Fail($"Duplicate covered component {name}");
        }
        foreach (string r in RequiredComponents)
        {
            if (!components.Contains(r)) throw Fail($"Required component not covered: {r}");
        }
        IReadOnlyDictionary<string, object> parameters = covered.Parameters;
        if (!parameters.TryGetValue("created", out object? createdValue) || createdValue is not long created)
        {
            throw Fail("The signature parameters lack an integer 'created'");
        }
        long now = _options.TimeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (created < now - (long)_options.MaxAge.TotalSeconds) throw Fail($"Signature too old (created {created})");
        if (created > now + (long)_options.ClockSkew.TotalSeconds) throw Fail($"Signature created in the future (created {created})");
        if (parameters.TryGetValue("expires", out object? expires) && (expires is not long exp || exp < now)) throw Fail("Signature expired");
        string keyid = (string)parameters["keyid"];
        string? alg = parameters.TryGetValue("alg", out object? a) && a is string s ? s : null;

        int hash = keyid.IndexOf('#', StringComparison.Ordinal);
        if (hash <= 0 || hash == keyid.Length - 1) throw Fail($"keyid is not a URL with a fragment: {keyid}");
        Uri storageId = Uris.Resolve(null, keyid[..hash]) is { } sid && sid.Scheme is "http" or "https"
            ? sid
            : throw Fail($"keyid is not an absolute http(s) URL: {keyid}");
        if (_trusted is not null && !_trusted.Contains(Canonical(storageId))) throw Fail($"Storage {Uris.ToText(storageId)} is not trusted");

        string signatureBase = SignatureBase(method, inboxUrl, headers, covered);
        byte[] signature = signatureBytes.ToArray();

        string cacheKey = Canonical(storageId);
        bool fromCache = _cache.TryGetValue(cacheKey, out var cached) && cached.Fetched + _options.KeyCacheTtl > _options.TimeProvider.GetUtcNow();
        StorageDescription description = fromCache ? cached.Description : await FetchAsync(storageId, cancellationToken).ConfigureAwait(false);
        string algorithm;
        try
        {
            algorithm = VerifyWith(description, storageId, keyid, alg, signatureBase, signature);
        }
        catch (SignatureVerificationException) when (fromCache)
        {
            // The key may have rotated: refetch the description once.
            description = await FetchAsync(storageId, cancellationToken).ConfigureAwait(false);
            algorithm = VerifyWith(description, storageId, keyid, alg, signatureBase, signature);
        }

        Notification notification;
        try
        {
            notification = Notification.Parse(body.Span);
        }
        catch (ProtocolException e)
        {
            throw new SignatureVerificationException($"The signed body is not a valid notification: {e.Message}", e);
        }
        if (Canonical(notification.Storage) != Canonical(storageId))
        {
            throw Fail($"Notification storage {Uris.ToText(notification.Storage)} does not match the signing storage {Uris.ToText(storageId)}");
        }
        return new VerifiedNotification(notification, keyid, storageId, label, algorithm);
    }

    /// <summary>Verifies a delivery received by an <see cref="HttpListener"/>.</summary>
    /// <param name="request">The request (its body is read to the end).</param>
    /// <param name="inboxUrl">The inbox URL as registered (not necessarily <see cref="HttpListenerRequest.Url"/>).</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The verified notification.</returns>
    /// <exception cref="SignatureVerificationException">Anything does not verify.</exception>
    public async Task<VerifiedNotification> VerifyAsync(HttpListenerRequest request, Uri inboxUrl, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var fields = new List<KeyValuePair<string, string[]>>();
        foreach (string? name in request.Headers.AllKeys)
        {
            if (name is not null && request.Headers.GetValues(name) is { } values) fields.Add(new(name, values));
        }
        using var buffer = new MemoryStream();
        await request.InputStream.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
        return await VerifyAsync(request.HttpMethod, inboxUrl, HeaderMap.From(fields), buffer.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Builds the RFC 9421 signature base for the covered components (exposed for diagnostics).</summary>
    /// <param name="method">The request method.</param>
    /// <param name="url">The target URL.</param>
    /// <param name="headers">The request headers.</param>
    /// <param name="covered">The covered components with the signature parameters.</param>
    /// <returns>The signature base.</returns>
    /// <exception cref="SignatureVerificationException">A component is unsupported or missing.</exception>
    public static string SignatureBase(string method, Uri url, HeaderMap headers, SfInnerList covered)
    {
        ArgumentNullException.ThrowIfNull(covered);
        var sb = new StringBuilder();
        foreach (SfItem item in covered.Items)
        {
            string name = item.Value as string ?? throw Fail("A covered component is not a string");
            sb.Append(StructuredFields.SerializeBareItem(name)).Append(": ").Append(ComponentValue(name, method, url, headers)).Append('\n');
        }
        sb.Append("\"@signature-params\": ").Append(StructuredFields.Serialize(covered));
        return sb.ToString();
    }

    private static string ComponentValue(string name, string method, Uri url, HeaderMap headers)
    {
        string path = url.AbsolutePath.Length == 0 ? "/" : url.AbsolutePath;
        switch (name)
        {
            case "@method":
                return method.ToUpperInvariant();
            case "@scheme":
                return url.Scheme.ToLowerInvariant();
            case "@authority":
                return url.IsDefaultPort ? url.IdnHost.ToLowerInvariant() : url.IdnHost.ToLowerInvariant() + ":" + url.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
            case "@path":
                return path;
            case "@query":
                return url.Query.Length == 0 ? "?" : url.Query;
            case "@target-uri":
                return url.AbsoluteUri;
            case "@request-target":
                return path + url.Query;
            default:
                if (name.StartsWith('@')) throw Fail($"Unsupported derived component {name}");
                IReadOnlyList<string> values = headers.GetAll(name);
                if (values.Count == 0) throw Fail($"Covered header field missing: {name}");
                return string.Join(", ", values.Select(v => v.Trim()));
        }
    }

    private static string VerifyWith(StorageDescription description, Uri storageId, string keyid, string? alg, string signatureBase, byte[] signature)
    {
        if (Canonical(description.Id) != Canonical(storageId))
        {
            throw Fail($"Storage description id {Uris.ToText(description.Id)} does not match the keyid storage {Uris.ToText(storageId)}");
        }
        VerificationMethod method = description.FindVerificationMethod(keyid)
            ?? throw Fail($"Verification method {keyid} not found in the storage description");
        if (!description.IsAuthenticationMethod(method)) throw Fail($"Verification method {keyid} is not referenced from authentication");
        if (method.PublicKeyJwk is not { } jwk) throw Fail($"Verification method {keyid} has no publicKeyJwk");
        VerificationKey key;
        try
        {
            key = VerificationKey.FromJwk(jwk);
        }
        catch (ArgumentException e)
        {
            throw new SignatureVerificationException($"Unusable verification key {keyid}: {e.Message}", e);
        }
        string keyAlgorithm = key.Curve switch
        {
            "P-256" => "ecdsa-p256-sha256",
            "P-384" => "ecdsa-p384-sha384",
            "Ed25519" => "ed25519",
            _ => throw Fail($"Unsupported verification key type {key.KeyType} {key.Curve}"),
        };
        if (alg is not null && alg != keyAlgorithm) throw Fail($"alg {alg} does not match the key type ({keyAlgorithm})");
        if (!key.Verify(Encoding.UTF8.GetBytes(signatureBase), signature)) throw Fail("The signature does not verify");
        return keyAlgorithm;
    }

    private async Task<StorageDescription> FetchAsync(Uri storageId, CancellationToken cancellationToken)
    {
        StorageDescription description;
        try
        {
            description = await _descriptions(storageId, cancellationToken).ConfigureAwait(false);
        }
        catch (LwsException e)
        {
            throw new SignatureVerificationException($"Cannot retrieve the storage description {Uris.ToText(storageId)}: {e.Message}", e);
        }
        if (description is null) throw Fail($"No storage description for {Uris.ToText(storageId)}");
        _cache[Canonical(storageId)] = (description, _options.TimeProvider.GetUtcNow());
        return description;
    }

    private static void CheckDigest(string header, ReadOnlySpan<byte> body)
    {
        IReadOnlyDictionary<string, SfMember> digests = Dictionary(header, "Content-Digest");
        bool any = false;
        foreach ((string name, Func<byte[], byte[]> hash) in new (string, Func<byte[], byte[]>)[] { ("sha-256", SHA256.HashData), ("sha-512", SHA512.HashData) })
        {
            if (!digests.TryGetValue(name, out SfMember? member)) continue;
            any = true;
            if (member is not SfItem { Value: SfByteSequence expected }) throw Fail($"Malformed {name} digest");
            byte[] actual = hash(body.ToArray());
            if (!CryptographicOperations.FixedTimeEquals(actual, expected.Value.Span)) throw Fail($"Content-Digest {name} mismatch");
        }
        if (!any) throw Fail("Content-Digest has no supported algorithm (sha-256, sha-512)");
    }

    private static string Field(HeaderMap headers, string name) =>
        headers.GetCombined(name) ?? throw Fail($"Missing {name} header");

    private static IReadOnlyDictionary<string, SfMember> Dictionary(string value, string what)
    {
        try
        {
            return StructuredFields.ParseDictionary(value);
        }
        catch (StructuredFieldFormatException e)
        {
            throw new SignatureVerificationException($"Malformed {what}: {e.Message}", e);
        }
    }

    /// <summary>A URL as compared for storage identity: the absolute form (scheme and host lower-cased, default port dropped).</summary>
    private static string Canonical(Uri uri) => Uris.WithoutFragment(uri.AbsoluteUri);

    private static SignatureVerificationException Fail(string message) => new(message);
}
