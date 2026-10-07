// SPDX-License-Identifier: MIT
using System.Text.Json;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws;

/// <summary>
/// The result of reading a resource: its metadata and content. A conditional read answered with
/// <c>304 Not Modified</c> is not an error: <see cref="NotModified"/> is true and the body is empty. A
/// <c>206 Partial Content</c> answer exposes <see cref="ContentRange"/>.
/// </summary>
public sealed class Resource
{
    private readonly byte[] _body;

    /// <summary>Creates a resource.</summary>
    /// <param name="metadata">The response metadata.</param>
    /// <param name="body">The content (copied).</param>
    /// <param name="notModified">Whether the server answered <c>304 Not Modified</c>.</param>
    public Resource(ResourceMetadata metadata, ReadOnlySpan<byte> body, bool notModified)
    {
        Metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
        _body = body.ToArray();
        NotModified = notModified;
    }

    internal Resource(ResourceMetadata metadata, byte[] body, bool notModified, bool owned)
    {
        Metadata = metadata;
        _body = owned ? body : (byte[])body.Clone();
        NotModified = notModified;
    }

    /// <summary>The response metadata.</summary>
    public ResourceMetadata Metadata { get; }

    /// <summary>Whether the server answered <c>304 Not Modified</c>.</summary>
    public bool NotModified { get; }

    /// <summary>The content (empty for <c>HEAD</c> and <c>304</c>).</summary>
    public ReadOnlyMemory<byte> Body => _body;

    /// <summary>The final request URL.</summary>
    public Uri Url => Metadata.Url;

    /// <summary>The HTTP status.</summary>
    public int Status => Metadata.Status;

    /// <summary>The entity tag, verbatim.</summary>
    public string? ETag => Metadata.ETag;

    /// <summary>The content type.</summary>
    public string? ContentType => Metadata.ContentType;

    /// <summary>The <c>Content-Range</c> of a partial (<c>206</c>) response.</summary>
    public string? ContentRange => Metadata.GetHeader("content-range");

    /// <summary>A copy of the content bytes.</summary>
    /// <returns>The bytes.</returns>
    public byte[] ToArray() => (byte[])_body.Clone();

    /// <summary>The content decoded with the <c>charset</c> of the content type (UTF-8 by default).</summary>
    /// <returns>The text.</returns>
    public string GetText() => HeaderLists.Decode(_body, ContentType);

    /// <summary>The content parsed as JSON.</summary>
    /// <returns>The JSON value.</returns>
    /// <exception cref="ProtocolException">The content is not JSON.</exception>
    public JsonElement GetJson() => LwsJson.Parse(_body, $"Content of {Uris.ToText(Url)}");

    /// <summary>The content deserialized from JSON with <see cref="JsonSerializer"/>.</summary>
    /// <typeparam name="T">The target type.</typeparam>
    /// <param name="options">Serializer options.</param>
    /// <returns>The value.</returns>
    /// <exception cref="ProtocolException">The content cannot be bound to <typeparamref name="T"/>.</exception>
    [System.Diagnostics.CodeAnalysis.RequiresUnreferencedCode("Uses reflection-based JSON deserialization.")]
    [System.Diagnostics.CodeAnalysis.RequiresDynamicCode("Uses reflection-based JSON deserialization.")]
    public T? GetJson<T>(JsonSerializerOptions? options = null)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(_body, options ?? LwsJson.Options);
        }
        catch (JsonException e)
        {
            throw new ProtocolException($"Cannot bind the content of {Uris.ToText(Url)} to {typeof(T).Name}: {e.Message}", e);
        }
    }

    /// <inheritdoc/>
    public override string ToString() => $"Resource {Uris.ToText(Url)} ({Status}, {_body.Length} bytes)";
}
