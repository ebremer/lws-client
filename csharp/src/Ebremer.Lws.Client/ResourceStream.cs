// SPDX-License-Identifier: MIT
namespace Ebremer.Lws;

/// <summary>
/// A resource read as a stream (for large content). Dispose it to release the connection.
/// </summary>
public sealed class ResourceStream : IDisposable, IAsyncDisposable
{
    private readonly HttpResponseMessage? _response;

    internal ResourceStream(ResourceMetadata metadata, Stream content, bool notModified, HttpResponseMessage? response)
    {
        Metadata = metadata;
        Content = content;
        NotModified = notModified;
        _response = response;
    }

    /// <summary>The response metadata.</summary>
    public ResourceMetadata Metadata { get; }

    /// <summary>The content stream (empty for <c>304</c>).</summary>
    public Stream Content { get; }

    /// <summary>Whether the server answered <c>304 Not Modified</c>.</summary>
    public bool NotModified { get; }

    /// <inheritdoc/>
    public void Dispose()
    {
        Content.Dispose();
        _response?.RequestMessage?.Dispose();
        _response?.Dispose();
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        await Content.DisposeAsync().ConfigureAwait(false);
        _response?.RequestMessage?.Dispose();
        _response?.Dispose();
    }
}
