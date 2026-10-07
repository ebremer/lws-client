// SPDX-License-Identifier: MIT
using Ebremer.Lws.Internal;

namespace Ebremer.Lws;

/// <summary>The outcome of a create operation.</summary>
public sealed class CreateResult
{
    private readonly byte[] _body;

    internal CreateResult(Uri location, ResourceMetadata metadata, byte[] body)
    {
        Location = location;
        Metadata = metadata;
        _body = body;
    }

    /// <summary>The absolute URL of the new resource (<c>Location</c>).</summary>
    public Uri Location { get; }

    /// <summary>The <c>201</c> response metadata (links to the linkset, the parent and the types).</summary>
    public ResourceMetadata Metadata { get; }

    /// <summary>The response body, often empty.</summary>
    public ReadOnlyMemory<byte> Body => _body;

    /// <summary>The linkset of the new resource, when announced.</summary>
    public Uri? Linkset => Metadata.Linkset;

    /// <summary>The entity tag of the new resource, when announced.</summary>
    public string? ETag => Metadata.ETag;

    /// <inheritdoc/>
    public override string ToString() => $"Created {Uris.ToText(Location)}";
}

/// <summary>The outcome of an update (<c>PUT</c>) or a patch (<c>PATCH</c>).</summary>
public sealed class UpdateResult
{
    private readonly byte[] _body;

    internal UpdateResult(int status, ResourceMetadata metadata, byte[] body)
    {
        Status = status;
        Metadata = metadata;
        _body = body;
    }

    /// <summary>The status: <c>200</c> or <c>204</c> (or another 2xx).</summary>
    public int Status { get; }

    /// <summary>The new entity tag, when the server returned one.</summary>
    public string? ETag => Metadata.ETag;

    /// <summary>The response metadata.</summary>
    public ResourceMetadata Metadata { get; }

    /// <summary>The response body, if the server returned a representation.</summary>
    public ReadOnlyMemory<byte> Body => _body;

    /// <inheritdoc/>
    public override string ToString() => $"Updated {Uris.ToText(Metadata.Url)} ({Status})";
}
