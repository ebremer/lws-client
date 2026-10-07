// SPDX-License-Identifier: MIT
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Ebremer.Lws.Access;
using Ebremer.Lws.Http;
using Ebremer.Lws.Internal;
using Ebremer.Lws.Notifications;

namespace Ebremer.Lws;

public sealed partial class LwsClient
{
    private const string AcceptDescription = Lws.MediaType.LwsCid + ", " + Lws.MediaType.LdJson + ";q=0.9, " + Lws.MediaType.Json + ";q=0.8";
    private const string AcceptLinkset = Lws.MediaType.LinksetJson + ", " + Lws.MediaType.Json + ";q=0.5";

    // ============================================================================================
    // Discovery
    // ============================================================================================

    /// <summary>
    /// Finds the storage a resource belongs to (its <c>rel="https://www.w3.org/ns/lws#storage"</c> link, from a
    /// <c>HEAD</c>, or a <c>GET</c> when <c>HEAD</c> is answered 405 or 501) and retrieves the storage description.
    /// </summary>
    /// <param name="resourceUrl">Any resource of the storage.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The storage description.</returns>
    /// <exception cref="ProtocolException">The response has no storage link, or the description is invalid.</exception>
    public async Task<StorageDescription> DiscoverStorageAsync(Uri resourceUrl, RequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        Uri url = Target(resourceUrl, nameof(resourceUrl));
        RawResponse r = await SendAsync(HttpMethod.Head, url, null, new HeaderList(), options, cancellationToken).ConfigureAwait(false);
        if (r.Status is 405 or 501) r = await SendAsync(HttpMethod.Get, url, null, new HeaderList(), options, cancellationToken).ConfigureAwait(false);
        Uri? storage = Metadata(r).Storage;
        // A 401 SHOULD carry the storage link too, so that anonymous discovery works.
        if (storage is null || !(r.Status / 100 == 2 || r.Status == 401))
        {
            Check(r);
            throw new ProtocolException($"The response for {Uris.ToText(url)} has no storage link (rel=\"{Lws.Rel.Storage}\")");
        }
        return await GetStorageDescriptionAsync(storage, options, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Retrieves and parses a storage description (<c>application/lws+cid</c>).</summary>
    /// <param name="storageUrl">The storage URL.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The storage description.</returns>
    /// <exception cref="ProtocolException">The document is not a storage description.</exception>
    public async Task<StorageDescription> GetStorageDescriptionAsync(Uri storageUrl, RequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        Uri url = Target(storageUrl, nameof(storageUrl));
        RawResponse r = await SendAsync(HttpMethod.Get, url, null, new HeaderList().Set("Accept", AcceptDescription), options, cancellationToken)
            .ConfigureAwait(false);
        Check(r);
        string? ct = r.Headers.GetFirst("content-type");
        if (ct is not null && !HeaderLists.IsJson(ct) && HeaderLists.Essence(ct) != Lws.MediaType.LwsCid)
        {
            throw new ProtocolException($"The storage description has the unexpected media type {ct}");
        }
        return StorageDescription.Parse(LwsJson.Parse(r.Body, "Storage description"), r.Uri);
    }

    // ============================================================================================
    // Reading
    // ============================================================================================

    /// <summary>Retrieves a resource's metadata (<c>HEAD</c>).</summary>
    /// <param name="url">The resource.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The metadata.</returns>
    public async Task<ResourceMetadata> HeadAsync(Uri url, RequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        RawResponse r = await SendAsync(HttpMethod.Head, Target(url, nameof(url)), null, new HeaderList(), options, cancellationToken).ConfigureAwait(false);
        Check(r);
        return Metadata(r);
    }

    /// <summary>
    /// Reads a resource (<c>GET</c>). A conditional read answered <c>304</c> returns a result whose
    /// <see cref="Resource.NotModified"/> is true instead of throwing; <c>206</c> is a normal result.
    /// </summary>
    /// <param name="url">The resource.</param>
    /// <param name="options">Accept, range, conditional and preference options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The resource.</returns>
    public async Task<Resource> ReadAsync(Uri url, ReadOptions? options = null, CancellationToken cancellationToken = default)
    {
        RawResponse r = await SendAsync(HttpMethod.Get, Target(url, nameof(url)), null, ReadHeaders(options), options, cancellationToken)
            .ConfigureAwait(false);
        return ToResource(r);
    }

    /// <summary>Reads a resource as a stream (for large content). Dispose the result.</summary>
    /// <param name="url">The resource.</param>
    /// <param name="options">Accept, range, conditional and preference options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The streaming resource.</returns>
    public async Task<ResourceStream> ReadStreamAsync(Uri url, ReadOptions? options = null, CancellationToken cancellationToken = default)
    {
        var call = new Call(HttpMethod.Get, Target(url, nameof(url)), null, ReadHeaders(options).With(options), options?.Timeout);
        (HttpResponseMessage response, HttpMethod method, Uri final) = await SendCoreAsync(call, cancellationToken).ConfigureAwait(false);
        int status = (int)response.StatusCode;
        var metadata = new ResourceMetadata(final, status, HeaderMap.From(response));
        if (status == 304)
        {
            Release(response);
            return new ResourceStream(metadata, Stream.Null, true, null);
        }
        if (status / 100 != 2)
        {
            try
            {
                byte[] error = await ReadBodyAsync(response, method, final, TimeoutFor(call), cancellationToken).ConfigureAwait(false);
                throw HttpException.Create(method.Method, final, status, metadata.Headers, error);
            }
            finally
            {
                Release(response);
            }
        }
        Stream content = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        return new ResourceStream(metadata, content, false, response);
    }

    /// <summary>Reads one page of a container listing (<c>Accept: application/lws+json</c>); also takes opaque page URLs.</summary>
    /// <param name="url">The container or page.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page.</returns>
    /// <exception cref="ProtocolException">The response is not an LWS container representation.</exception>
    public async Task<ContainerPage> ReadContainerAsync(Uri url, RequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        Uri u = Target(url, nameof(url));
        RawResponse r = await SendAsync(HttpMethod.Get, u, null, new HeaderList().Set("Accept", Lws.MediaType.LwsJson), options, cancellationToken)
            .ConfigureAwait(false);
        ContainerPage page = ToPage(r);
        if (!page.IsContainer)
        {
            throw new ProtocolException($"{Uris.ToText(r.Uri)} is not a container (type [{string.Join(", ", page.Types)}])");
        }
        return page;
    }

    /// <summary>Every member of a container, fetched lazily page by page (following <c>rel="next"</c>).</summary>
    /// <param name="url">The container.</param>
    /// <param name="options">Request options (for every page).</param>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>The members.</returns>
    public IAsyncEnumerable<ContainedResource> ListContainerAsync(Uri url, RequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        Uri u = Target(url, nameof(url));
        return PaginateAsync(u, ct => ReadContainerAsync(u, options, ct), p => p.Next, (next, ct) => ReadContainerAsync(next, options, ct),
            p => p.Items, cancellationToken);
    }

    // ============================================================================================
    // Creating
    // ============================================================================================

    /// <summary>Creates a data resource in a container (<c>POST</c>); the server assigns its URL (<see cref="CreateResult.Location"/>).</summary>
    /// <param name="containerUrl">The container.</param>
    /// <param name="body">The content.</param>
    /// <param name="contentType">The content type.</param>
    /// <param name="options">Slug, links and types.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The result.</returns>
    /// <exception cref="ProtocolException">The response has no <c>Location</c>.</exception>
    public Task<CreateResult> CreateAsync(Uri containerUrl, ReadOnlyMemory<byte> body, string contentType, CreateOptions? options = null,
        CancellationToken cancellationToken = default) =>
        CreateCoreAsync(containerUrl, new BytesBody(body), contentType, options, cancellationToken);

    /// <summary>Creates a data resource from a stream (sent once: a token is established first, with a <c>HEAD</c> if needed).</summary>
    /// <param name="containerUrl">The container.</param>
    /// <param name="body">The content.</param>
    /// <param name="contentType">The content type.</param>
    /// <param name="options">Slug, links and types.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The result.</returns>
    public Task<CreateResult> CreateAsync(Uri containerUrl, Stream body, string contentType, CreateOptions? options = null,
        CancellationToken cancellationToken = default) =>
        CreateCoreAsync(containerUrl, new StreamBody(body ?? throw new ArgumentNullException(nameof(body))), contentType, options, cancellationToken);

    /// <summary>Creates a text data resource (UTF-8).</summary>
    /// <param name="containerUrl">The container.</param>
    /// <param name="text">The text.</param>
    /// <param name="contentType">The content type (default <c>text/plain</c>).</param>
    /// <param name="options">Slug, links and types.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The result.</returns>
    public Task<CreateResult> CreateTextAsync(Uri containerUrl, string text, string contentType = "text/plain", CreateOptions? options = null,
        CancellationToken cancellationToken = default) =>
        CreateAsync(containerUrl, Encoding.UTF8.GetBytes(text ?? throw new ArgumentNullException(nameof(text))), contentType, options, cancellationToken);

    /// <summary>Creates a JSON data resource (<c>application/json</c>) from any value, serialized with <see cref="JsonSerializer"/>.</summary>
    /// <typeparam name="T">The value type (a <c>JsonNode</c>, a <c>JsonElement</c>, a record, an anonymous object, …).</typeparam>
    /// <param name="containerUrl">The container.</param>
    /// <param name="value">The value.</param>
    /// <param name="options">Slug, links and types.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The result.</returns>
    [RequiresUnreferencedCode("Uses reflection-based JSON serialization; use the JsonTypeInfo overload when trimming.")]
    [RequiresDynamicCode("Uses reflection-based JSON serialization; use the JsonTypeInfo overload for native AOT.")]
    public Task<CreateResult> CreateJsonAsync<T>(Uri containerUrl, T value, CreateOptions? options = null, CancellationToken cancellationToken = default) =>
        CreateAsync(containerUrl, JsonSerializer.SerializeToUtf8Bytes(value, LwsJson.Options), Lws.MediaType.Json, options, cancellationToken);

    /// <summary>Creates a JSON data resource (<c>application/json</c>) with source-generated serialization metadata.</summary>
    /// <typeparam name="T">The value type.</typeparam>
    /// <param name="containerUrl">The container.</param>
    /// <param name="value">The value.</param>
    /// <param name="typeInfo">The serialization metadata.</param>
    /// <param name="options">Slug, links and types.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The result.</returns>
    public Task<CreateResult> CreateJsonAsync<T>(Uri containerUrl, T value, JsonTypeInfo<T> typeInfo, CreateOptions? options = null,
        CancellationToken cancellationToken = default) =>
        CreateAsync(containerUrl, JsonSerializer.SerializeToUtf8Bytes(value, typeInfo), Lws.MediaType.Json, options, cancellationToken);

    /// <summary>Creates a sub-container (<c>POST</c> with <c>Link: &lt;https://www.w3.org/ns/lws#Container&gt;; rel="type"</c>, empty body).</summary>
    /// <param name="parentUrl">The parent container.</param>
    /// <param name="options">Slug, links and types.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The result.</returns>
    public async Task<CreateResult> CreateContainerAsync(Uri parentUrl, CreateOptions? options = null, CancellationToken cancellationToken = default)
    {
        Uri u = Target(parentUrl, nameof(parentUrl));
        RawResponse r = await SendAsync(HttpMethod.Post, u, new BytesBody(ReadOnlyMemory<byte>.Empty), CreateHeaders(options, Lws.Types.Container),
            options, cancellationToken).ConfigureAwait(false);
        return ToCreateResult(r);
    }

    private async Task<CreateResult> CreateCoreAsync(Uri containerUrl, RequestBody body, string contentType, CreateOptions? options,
        CancellationToken cancellationToken)
    {
        Uri u = Target(containerUrl, nameof(containerUrl));
        ArgumentNullException.ThrowIfNull(contentType);
        HeaderList headers = CreateHeaders(options, null).Set("Content-Type", contentType);
        RawResponse r = await SendAsync(HttpMethod.Post, u, body, headers, options, cancellationToken).ConfigureAwait(false);
        return ToCreateResult(r);
    }

    // ============================================================================================
    // Updating and deleting
    // ============================================================================================

    /// <summary>Replaces a resource's content (<c>PUT</c>); use <see cref="UpdateOptions.IfMatch"/> to avoid lost updates.</summary>
    /// <param name="url">The resource.</param>
    /// <param name="body">The new content.</param>
    /// <param name="contentType">The content type.</param>
    /// <param name="options">Conditions, links and <c>set-linkset</c>.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The result.</returns>
    public Task<UpdateResult> UpdateAsync(Uri url, ReadOnlyMemory<byte> body, string contentType, UpdateOptions? options = null,
        CancellationToken cancellationToken = default) =>
        UpdateCoreAsync(HttpMethod.Put, url, new BytesBody(body), contentType, options, cancellationToken);

    /// <summary>Replaces a resource's content from a stream (<c>PUT</c>).</summary>
    /// <param name="url">The resource.</param>
    /// <param name="body">The new content.</param>
    /// <param name="contentType">The content type.</param>
    /// <param name="options">Conditions, links and <c>set-linkset</c>.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The result.</returns>
    public Task<UpdateResult> UpdateAsync(Uri url, Stream body, string contentType, UpdateOptions? options = null,
        CancellationToken cancellationToken = default) =>
        UpdateCoreAsync(HttpMethod.Put, url, new StreamBody(body ?? throw new ArgumentNullException(nameof(body))), contentType, options, cancellationToken);

    /// <summary>Applies a JSON Patch (<c>application/json-patch+json</c>, the LWS baseline patch format).</summary>
    /// <param name="url">The resource.</param>
    /// <param name="patch">The patch.</param>
    /// <param name="options">Conditions, links and <c>set-linkset</c>.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The result.</returns>
    public Task<UpdateResult> PatchAsync(Uri url, JsonPatch patch, UpdateOptions? options = null, CancellationToken cancellationToken = default) =>
        UpdateCoreAsync(HttpMethod.Patch, url, new BytesBody((patch ?? throw new ArgumentNullException(nameof(patch))).ToBytes()),
            Lws.MediaType.JsonPatch, options, cancellationToken);

    /// <summary>Applies a patch in any format the server advertises in <c>Accept-Patch</c> (e.g. <c>application/sparql-update</c>).</summary>
    /// <param name="url">The resource.</param>
    /// <param name="patch">The patch document.</param>
    /// <param name="patchContentType">Its media type.</param>
    /// <param name="options">Conditions, links and <c>set-linkset</c>.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The result.</returns>
    public Task<UpdateResult> PatchAsync(Uri url, ReadOnlyMemory<byte> patch, string patchContentType, UpdateOptions? options = null,
        CancellationToken cancellationToken = default) =>
        UpdateCoreAsync(HttpMethod.Patch, url, new BytesBody(patch), patchContentType, options, cancellationToken);

    private async Task<UpdateResult> UpdateCoreAsync(HttpMethod method, Uri url, RequestBody body, string contentType, UpdateOptions? options,
        CancellationToken cancellationToken)
    {
        Uri u = Target(url, nameof(url));
        ArgumentNullException.ThrowIfNull(contentType);
        RawResponse r = await SendAsync(method, u, body, UpdateHeaders(options, contentType), options, cancellationToken).ConfigureAwait(false);
        Check(r);
        return new UpdateResult(r.Status, Metadata(r), r.Body);
    }

    /// <summary>Deletes a resource; a non-empty container needs <see cref="DeleteOptions.Recursive"/> (else <see cref="ConflictException"/>).</summary>
    /// <param name="url">The resource.</param>
    /// <param name="options">Condition and recursion.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A task.</returns>
    public async Task DeleteAsync(Uri url, DeleteOptions? options = null, CancellationToken cancellationToken = default)
    {
        var headers = new HeaderList().Set("If-Match", options?.IfMatch);
        if (options?.Recursive == true) headers.Set("Depth", "infinity");
        RawResponse r = await SendAsync(HttpMethod.Delete, Target(url, nameof(url)), null, headers, options, cancellationToken).ConfigureAwait(false);
        Check(r);
    }

    // ============================================================================================
    // Metadata (linksets)
    // ============================================================================================

    /// <summary>The linkset resource URL of a resource (<c>HEAD</c>, <c>rel="linkset"</c>).</summary>
    /// <param name="resourceUrl">The resource.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The linkset URL.</returns>
    /// <exception cref="ProtocolException">The resource has no linkset link.</exception>
    public async Task<Uri> LinksetUrlAsync(Uri resourceUrl, RequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        ResourceMetadata m = await HeadAsync(resourceUrl, options, cancellationToken).ConfigureAwait(false);
        return m.Linkset ?? throw new ProtocolException($"{Uris.ToText(m.Url)} has no linkset link");
    }

    /// <summary>Discovers and reads a resource's linkset (<c>application/linkset+json</c>).</summary>
    /// <param name="resourceUrl">The resource.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The linkset document.</returns>
    public async Task<LinksetDocument> ReadLinksetAsync(Uri resourceUrl, RequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        Uri linkset = await LinksetUrlAsync(resourceUrl, options, cancellationToken).ConfigureAwait(false);
        return await ReadLinksetResourceAsync(linkset, options, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads a linkset resource at a known URL.</summary>
    /// <param name="linksetUrl">The linkset resource.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The linkset document.</returns>
    public async Task<LinksetDocument> ReadLinksetResourceAsync(Uri linksetUrl, RequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        RawResponse r = await SendAsync(HttpMethod.Get, Target(linksetUrl, nameof(linksetUrl)), null, new HeaderList().Set("Accept", AcceptLinkset),
            options, cancellationToken).ConfigureAwait(false);
        Check(r);
        return new LinksetDocument(r.Uri, Linkset.Parse(LwsJson.Parse(r.Body, "Linkset")), Metadata(r));
    }

    /// <summary>Replaces a linkset (<c>PUT</c>; only when the server allows it, else <see cref="MethodNotAllowedException"/>).</summary>
    /// <param name="linksetUrl">The linkset resource.</param>
    /// <param name="linkset">The new linkset.</param>
    /// <param name="options">The <c>IfMatch</c> condition.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The result.</returns>
    public Task<UpdateResult> UpdateLinksetAsync(Uri linksetUrl, Linkset linkset, UpdateOptions? options = null, CancellationToken cancellationToken = default) =>
        UpdateCoreAsync(HttpMethod.Put, linksetUrl, new BytesBody(LwsJson.ToBytes((linkset ?? throw new ArgumentNullException(nameof(linkset))).ToJson())),
            Lws.MediaType.LinksetJson, options, cancellationToken);

    /// <summary>Patches a linkset with JSON Patch; <see cref="JsonPointer"/> escapes relation keys that are URIs.</summary>
    /// <param name="linksetUrl">The linkset resource.</param>
    /// <param name="patch">The patch.</param>
    /// <param name="options">The <c>IfMatch</c> condition.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The result.</returns>
    public Task<UpdateResult> PatchLinksetAsync(Uri linksetUrl, JsonPatch patch, UpdateOptions? options = null, CancellationToken cancellationToken = default) =>
        PatchAsync(linksetUrl, patch, options, cancellationToken);

    // ============================================================================================
    // Notifications
    // ============================================================================================

    /// <summary>Creates a webhook subscription at a notification service endpoint.</summary>
    /// <param name="serviceUrl">The notification service endpoint.</param>
    /// <param name="request">The subscription request.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The subscription.</returns>
    /// <exception cref="ProtocolException">The response has neither a subscription URL nor a <c>Location</c>.</exception>
    public async Task<Subscription> SubscribeAsync(Uri serviceUrl, WebhookSubscriptionRequest request, RequestOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        Uri u = Target(serviceUrl, nameof(serviceUrl));
        ArgumentNullException.ThrowIfNull(request);
        RawResponse r = await SendAsync(HttpMethod.Post, u, new BytesBody(LwsJson.ToBytes(request.ToJson())), JsonHeaders(), options, cancellationToken)
            .ConfigureAwait(false);
        Check(r);
        Uri? location = r.Headers.GetFirst("location") is { } l ? Uris.Resolve(r.Uri, l) : null;
        if (r.Body.Length == 0 || r.Body.All(b => b is (byte)' ' or (byte)'\n' or (byte)'\r' or (byte)'\t'))
        {
            if (location is null) throw new ProtocolException("The subscription response has neither a body nor a Location");
            return Subscription.Parse(LwsJson.Parse($"{{\"type\":\"{Lws.SubscriptionType.Webhook}\"}}", "Subscription"), r.Uri, location);
        }
        return Subscription.Parse(LwsJson.Parse(r.Body, "Subscription"), r.Uri, location);
    }

    /// <summary>Creates a webhook subscription at a storage's notification service, checking that it offers webhooks.</summary>
    /// <param name="service">The notification service (<see cref="StorageDescription.NotificationService"/>).</param>
    /// <param name="request">The subscription request.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The subscription.</returns>
    /// <exception cref="ProtocolException">The service does not support <c>WebhookSubscription</c>.</exception>
    public Task<Subscription> SubscribeAsync(Service service, WebhookSubscriptionRequest request, RequestOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(service);
        if (service.SubscriptionTypes.Count > 0 && !service.SubscriptionTypes.Contains(Lws.SubscriptionType.Webhook))
        {
            throw new ProtocolException($"The notification service {Uris.ToText(service.ServiceEndpoint)} does not support {Lws.SubscriptionType.Webhook}");
        }
        return SubscribeAsync(service.ServiceEndpoint, request, options, cancellationToken);
    }

    /// <summary>The subscriber's subscriptions: the container listing of the notification service.</summary>
    /// <param name="serviceUrl">The notification service endpoint.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>The subscriptions.</returns>
    public IAsyncEnumerable<ContainedResource> ListSubscriptionsAsync(Uri serviceUrl, RequestOptions? options = null, CancellationToken cancellationToken = default) =>
        ListContainerAsync(serviceUrl, options, cancellationToken);

    /// <summary>Retrieves a subscription's current state.</summary>
    /// <param name="url">The subscription URL.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The subscription.</returns>
    public async Task<Subscription> GetSubscriptionAsync(Uri url, RequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        RawResponse r = await SendAsync(HttpMethod.Get, Target(url, nameof(url)), null, new HeaderList().Set("Accept", Lws.MediaType.LwsJson), options,
            cancellationToken).ConfigureAwait(false);
        Check(r);
        return Subscription.Parse(LwsJson.Parse(r.Body, "Subscription"), r.Uri, r.Uri);
    }

    /// <summary>Cancels a subscription (<c>DELETE</c>).</summary>
    /// <param name="url">The subscription URL.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A task.</returns>
    public Task UnsubscribeAsync(Uri url, RequestOptions? options = null, CancellationToken cancellationToken = default) =>
        DeleteAsync(url, Delete(options), cancellationToken);

    // ============================================================================================
    // Access requests and grants
    // ============================================================================================

    /// <summary>Submits an access request; returns its URL.</summary>
    /// <param name="serviceUrl">The access request service endpoint.</param>
    /// <param name="request">The request.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The URL of the created request (<c>Location</c>).</returns>
    public Task<Uri> RequestAccessAsync(Uri serviceUrl, AccessRequest request, RequestOptions? options = null, CancellationToken cancellationToken = default) =>
        PostForLocationAsync(serviceUrl, (request ?? throw new ArgumentNullException(nameof(request))).ToJson(), options, cancellationToken);

    /// <summary>The access requests: the container listing of the service.</summary>
    /// <param name="serviceUrl">The access request service endpoint.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>The requests.</returns>
    public IAsyncEnumerable<ContainedResource> ListAccessRequestsAsync(Uri serviceUrl, RequestOptions? options = null, CancellationToken cancellationToken = default) =>
        ListContainerAsync(serviceUrl, options, cancellationToken);

    /// <summary>Retrieves an access request.</summary>
    /// <param name="url">The request URL.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The request (its <see cref="AccessDocument.Raw"/> is the document as sent).</returns>
    public async Task<AccessRequest> GetAccessRequestAsync(Uri url, RequestOptions? options = null, CancellationToken cancellationToken = default) =>
        AccessRequest.Parse(await GetJsonAsync(url, options, cancellationToken).ConfigureAwait(false));

    /// <summary>Cancels (deletes) an access request.</summary>
    /// <param name="url">The request URL.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A task.</returns>
    public Task CancelAccessRequestAsync(Uri url, RequestOptions? options = null, CancellationToken cancellationToken = default) =>
        DeleteAsync(url, Delete(options), cancellationToken);

    /// <summary>Creates an access grant (as storage controller); returns its URL.</summary>
    /// <param name="serviceUrl">The access grant service endpoint.</param>
    /// <param name="grant">The grant.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The URL of the created grant (<c>Location</c>).</returns>
    public Task<Uri> GrantAccessAsync(Uri serviceUrl, AccessGrant grant, RequestOptions? options = null, CancellationToken cancellationToken = default) =>
        PostForLocationAsync(serviceUrl, (grant ?? throw new ArgumentNullException(nameof(grant))).ToJson(), options, cancellationToken);

    /// <summary>The access grants: the container listing of the service.</summary>
    /// <param name="serviceUrl">The access grant service endpoint.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>The grants.</returns>
    public IAsyncEnumerable<ContainedResource> ListAccessGrantsAsync(Uri serviceUrl, RequestOptions? options = null, CancellationToken cancellationToken = default) =>
        ListContainerAsync(serviceUrl, options, cancellationToken);

    /// <summary>Retrieves an access grant.</summary>
    /// <param name="url">The grant URL.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The grant (its <see cref="AccessDocument.Raw"/> is the document as sent).</returns>
    public async Task<AccessGrant> GetAccessGrantAsync(Uri url, RequestOptions? options = null, CancellationToken cancellationToken = default) =>
        AccessGrant.Parse(await GetJsonAsync(url, options, cancellationToken).ConfigureAwait(false));

    /// <summary>Revokes (deletes) an access grant.</summary>
    /// <param name="url">The grant URL.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A task.</returns>
    public Task RevokeAccessGrantAsync(Uri url, RequestOptions? options = null, CancellationToken cancellationToken = default) =>
        DeleteAsync(url, Delete(options), cancellationToken);

    // ============================================================================================
    // Type index and type search
    // ============================================================================================

    /// <summary>Reads a type index page (the service endpoint, or an opaque page URL).</summary>
    /// <param name="url">The type index service or page.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page.</returns>
    public async Task<TypeIndexPage> ReadTypeIndexAsync(Uri url, RequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        RawResponse r = await SendAsync(HttpMethod.Get, Target(url, nameof(url)), null, new HeaderList().Set("Accept", Lws.MediaType.LwsJson), options,
            cancellationToken).ConfigureAwait(false);
        Check(r);
        RequireLwsJson(r);
        return TypeIndexPage.Parse(LwsJson.Parse(r.Body, "Type index"), Metadata(r));
    }

    /// <summary>Every type IRI of a type index, fetched lazily page by page.</summary>
    /// <param name="serviceUrl">The type index service endpoint.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>The type IRIs.</returns>
    public IAsyncEnumerable<string> ListTypesAsync(Uri serviceUrl, RequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        Uri u = Target(serviceUrl, nameof(serviceUrl));
        return PaginateAsync(u, ct => ReadTypeIndexAsync(u, options, ct), p => p.Next, (next, ct) => ReadTypeIndexAsync(next, options, ct),
            p => p.Types, cancellationToken);
    }

    /// <summary>
    /// Runs a type search (HTTP <c>QUERY</c>, RFC 10008, with an <c>application/lws-query+json</c> filter) and returns the
    /// first page. The page's <see cref="ContainerPage.Id"/> is the page URL when the body has no <c>id</c>.
    /// </summary>
    /// <param name="serviceUrl">The type search service endpoint.</param>
    /// <param name="query">The filter.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The first page of results.</returns>
    public async Task<ContainerPage> SearchTypesAsync(Uri serviceUrl, TypeQuery query, RequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        Uri u = Target(serviceUrl, nameof(serviceUrl));
        ArgumentNullException.ThrowIfNull(query);
        HeaderList headers = new HeaderList().Set("Content-Type", Lws.MediaType.LwsQueryJson).Set("Accept", Lws.MediaType.LwsJson);
        RawResponse r = await SendAsync(Query, u, new BytesBody(query.ToBytes()), headers, options, cancellationToken).ConfigureAwait(false);
        return ToPage(r);
    }

    /// <summary>Every search result: the first page by <c>QUERY</c>, further pages by <c>GET</c> of the opaque <c>next</c> links.</summary>
    /// <param name="serviceUrl">The type search service endpoint.</param>
    /// <param name="query">The filter.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>The results.</returns>
    public IAsyncEnumerable<ContainedResource> SearchAllAsync(Uri serviceUrl, TypeQuery query, RequestOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        Uri u = Target(serviceUrl, nameof(serviceUrl));
        ArgumentNullException.ThrowIfNull(query);
        return PaginateAsync(u, ct => SearchTypesAsync(u, query, options, ct), p => p.Next, (next, ct) => ReadSearchPageAsync(next, options, ct),
            p => p.Items, cancellationToken);
    }

    private async Task<ContainerPage> ReadSearchPageAsync(Uri url, RequestOptions? options, CancellationToken cancellationToken)
    {
        RawResponse r = await SendAsync(HttpMethod.Get, url, null, new HeaderList().Set("Accept", Lws.MediaType.LwsJson), options, cancellationToken)
            .ConfigureAwait(false);
        return ToPage(r);
    }

    /// <summary>The query formats a search service accepts (<c>OPTIONS</c>, <c>Accept-Query</c>).</summary>
    /// <param name="serviceUrl">The type search service endpoint.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The media types.</returns>
    public async Task<IReadOnlyList<string>> AcceptedQueryFormatsAsync(Uri serviceUrl, RequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        RawResponse r = await SendAsync(HttpMethod.Options, Target(serviceUrl, nameof(serviceUrl)), null, new HeaderList(), options, cancellationToken)
            .ConfigureAwait(false);
        Check(r);
        return HeaderLists.Split(r.Headers.GetAll("accept-query"))
            .Select(m => m.Length >= 2 && m[0] == '"' && m[^1] == '"' ? m[1..^1] : m)
            .ToList().AsReadOnly();
    }

    // ============================================================================================
    // Low-level access
    // ============================================================================================

    /// <summary>
    /// Sends any request through the client's pipeline (authentication, redirects). An error status throws the
    /// matching <see cref="HttpException"/>; <c>304</c> yields a not-modified result.
    /// </summary>
    /// <param name="method">The method.</param>
    /// <param name="url">The target.</param>
    /// <param name="body">The body, if any.</param>
    /// <param name="contentType">The body's content type.</param>
    /// <param name="options">Request options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The response as a resource.</returns>
    public async Task<Resource> RequestAsync(HttpMethod method, Uri url, ReadOnlyMemory<byte>? body = null, string? contentType = null,
        RequestOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(method);
        RawResponse r = await SendAsync(method, Target(url, nameof(url)), body is { } b ? new BytesBody(b) : null,
            new HeaderList().Set("Content-Type", contentType), options, cancellationToken).ConfigureAwait(false);
        return ToResource(r);
    }

    // ============================================================================================
    // Internals of the operations
    // ============================================================================================

    private static async IAsyncEnumerable<T> PaginateAsync<TPage, T>(Uri first, Func<CancellationToken, Task<TPage>> load, Func<TPage, Uri?> next,
        Func<Uri, CancellationToken, Task<TPage>> fetch, Func<TPage, IEnumerable<T>> items, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal) { first.AbsoluteUri };
        TPage page = await load(cancellationToken).ConfigureAwait(false);
        while (true)
        {
            foreach (T item in items(page)) yield return item;
            Uri? n = next(page);
            if (n is null || !seen.Add(n.AbsoluteUri)) yield break;
            page = await fetch(n, cancellationToken).ConfigureAwait(false);
        }
    }

    private static Resource ToResource(RawResponse r)
    {
        if (r.Status == 304) return new Resource(Metadata(r), [], true, owned: true);
        Check(r);
        return new Resource(Metadata(r), r.Body, false, owned: true);
    }

    private static ContainerPage ToPage(RawResponse r)
    {
        Check(r);
        RequireLwsJson(r);
        return ContainerPage.Parse(LwsJson.Parse(r.Body, "Container representation"), Metadata(r));
    }

    private static CreateResult ToCreateResult(RawResponse r)
    {
        Check(r);
        string location = r.Headers.GetFirst("location")
            ?? throw new ProtocolException($"The create response (HTTP {r.Status}) from {Uris.ToText(r.Uri)} has no Location header");
        Uri resolved = Uris.Resolve(r.Uri, location) ?? throw new ProtocolException($"Invalid Location header: {location}");
        return new CreateResult(resolved, Metadata(r), r.Body);
    }

    private async Task<Uri> PostForLocationAsync(Uri serviceUrl, System.Text.Json.Nodes.JsonObject document, RequestOptions? options,
        CancellationToken cancellationToken)
    {
        RawResponse r = await SendAsync(HttpMethod.Post, Target(serviceUrl, nameof(serviceUrl)), new BytesBody(LwsJson.ToBytes(document)), JsonHeaders(),
            options, cancellationToken).ConfigureAwait(false);
        return ToCreateResult(r).Location;
    }

    private async Task<JsonElement> GetJsonAsync(Uri url, RequestOptions? options, CancellationToken cancellationToken)
    {
        RawResponse r = await SendAsync(HttpMethod.Get, Target(url, nameof(url)), null, new HeaderList().Set("Accept", Lws.MediaType.LwsJson), options,
            cancellationToken).ConfigureAwait(false);
        Check(r);
        return LwsJson.Parse(r.Body, $"Response of {Uris.ToText(r.Uri)}");
    }

    private static HeaderList JsonHeaders() =>
        new HeaderList().Set("Content-Type", Lws.MediaType.LwsJson).Set("Accept", Lws.MediaType.LwsJson);

    private static DeleteOptions? Delete(RequestOptions? options) =>
        options is null ? null : options as DeleteOptions ?? new DeleteOptions { Headers = options.Headers, Timeout = options.Timeout };

    private static HeaderList ReadHeaders(ReadOptions? o)
    {
        var h = new HeaderList();
        if (o is null) return h;
        h.Set("Accept", o.Accept);
        if (o.Range is not null) h.Set("Range", o.Range.ToString());
        h.Set("If-None-Match", o.IfNoneMatch);
        if (o.IfModifiedSince is { } since) h.Set("If-Modified-Since", since.UtcDateTime.ToString("r", CultureInfo.InvariantCulture));
        h.Set("Prefer", o.Prefer);
        return h;
    }

    private static HeaderList CreateHeaders(CreateOptions? o, string? containerType)
    {
        var h = new HeaderList();
        if (containerType is not null) h.Append("Link", LinkHeader.Format(Link.ForType(containerType)));
        foreach (string t in o?.Types ?? []) h.Append("Link", LinkHeader.Format(Link.ForType(t)));
        foreach (Link l in o?.Links ?? []) h.Append("Link", LinkHeader.Format(l));
        if (o?.Slug is { } slug) h.Set(Slug.HeaderName, Slug.Encode(slug));
        return h;
    }

    private static HeaderList UpdateHeaders(UpdateOptions? o, string contentType)
    {
        var h = new HeaderList().Set("Content-Type", contentType);
        if (o is null) return h;
        h.Set("If-Match", o.IfMatch).Set("If-None-Match", o.IfNoneMatch);
        foreach (Link l in o.Links ?? []) h.Append("Link", LinkHeader.Format(l));
        if (o.SetLinkset) h.Set("Prefer", Lws.Prefer.SetLinkset);
        return h;
    }
}
