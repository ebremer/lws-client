// SPDX-License-Identifier: MIT
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Ebremer.Lws;
using Ebremer.Lws.Notifications;

namespace Ebremer.Lws.Driver.Adapter;

/// <summary>The shared result shapes of PROTOCOL.md section 3.1, built from the library's own results.</summary>
internal static partial class Results
{
    /// <summary>The serializer settings of protocol lines (compact, no HTML escaping).</summary>
    public static readonly JsonSerializerOptions Json = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>Content types whose bodies are reported as text.</summary>
    [GeneratedRegex("^(text/[^;]*|application/(json|xml)|[^;]*\\+(json|xml))\\s*(;|$)", RegexOptions.IgnoreCase)]
    private static partial Regex Textual();

    public static string Text(Uri uri) => uri.IsAbsoluteUri ? uri.AbsoluteUri : uri.OriginalString;

    public static JsonArray Strings(IEnumerable<string> values) => [.. values.Select(v => (JsonNode)v)];

    public static JsonNode? Raw(JsonElement element) => JsonNode.Parse(element.GetRawText());

    /// <summary>Sets an optional member, omitting it when absent.</summary>
    public static void Put(JsonObject o, string name, string? value)
    {
        if (value is not null) o[name] = value;
    }

    public static void Put(JsonObject o, string name, Uri? value)
    {
        if (value is not null) o[name] = Text(value);
    }

    public static void Put(JsonObject o, string name, long? value)
    {
        if (value is { } v) o[name] = v;
    }

    /// <summary>A response body: text for textual content types, else base64.</summary>
    public static JsonObject Body(Resource resource)
    {
        string? contentType = resource.ContentType;
        return contentType is not null && Textual().IsMatch(contentType.Trim())
            ? new JsonObject { ["text"] = resource.GetText() }
            : new JsonObject { ["base64"] = Convert.ToBase64String(resource.Body.Span) };
    }

    /// <summary>Metadata: the parsed response headers.</summary>
    public static JsonObject Metadata(ResourceMetadata m)
    {
        var o = new JsonObject { ["url"] = Text(m.Url), ["status"] = m.Status };
        Put(o, "etag", m.ETag);
        Put(o, "lastModified", m.LastModifiedRaw);
        Put(o, "contentType", m.ContentType);
        Put(o, "contentLength", m.ContentLength);
        o["links"] = new JsonArray([.. m.Links.Select(l => (JsonNode)new JsonObject
        {
            ["href"] = Text(l.Href),
            ["rel"] = l.Rel,
            ["params"] = new JsonObject([.. l.Parameters.Select(p => new KeyValuePair<string, JsonNode?>(p.Key, p.Value))]),
        })]);
        Put(o, "linkset", m.Linkset);
        Put(o, "parent", m.Parent);
        Put(o, "storage", m.Storage);
        o["types"] = Strings(m.Types);
        o["allow"] = Strings(m.Allow);
        o["acceptPatch"] = Strings(m.AcceptPatch);
        return o;
    }

    /// <summary>Item: one member of a listing.</summary>
    public static JsonObject Item(ContainedResource i)
    {
        var o = new JsonObject { ["id"] = Text(i.Id), ["types"] = Strings(i.Types) };
        Put(o, "format", i.Format);
        Put(o, "size", i.Size);
        Put(o, "modified", i.ModifiedRaw);
        return o;
    }

    /// <summary>Page: a container page or a page of search results.</summary>
    public static JsonObject Page(ContainerPage p)
    {
        var o = new JsonObject { ["id"] = Text(p.Id), ["types"] = Strings(p.Types) };
        Put(o, "totalItems", p.TotalItems);
        o["items"] = new JsonArray([.. p.Items.Select(i => (JsonNode)Item(i))]);
        Put(o, "first", p.First);
        Put(o, "next", p.Next);
        Put(o, "prev", p.Prev);
        Put(o, "last", p.Last);
        o["metadata"] = Metadata(p.Metadata);
        return o;
    }

    /// <summary>Update: the result of a PUT or PATCH.</summary>
    public static JsonObject Update(UpdateResult u)
    {
        var o = new JsonObject { ["status"] = u.Status };
        Put(o, "etag", u.ETag);
        o["metadata"] = Metadata(u.Metadata);
        return o;
    }

    /// <summary>Created: the result of a create.</summary>
    public static JsonObject Created(CreateResult c) => new() { ["location"] = Text(c.Location), ["metadata"] = Metadata(c.Metadata) };

    /// <summary>Storage: a storage description; <c>storageRoot</c> is omitted when the library's <c>GetStorageRoot()</c> fails.</summary>
    public static JsonObject Storage(StorageDescription s)
    {
        var o = new JsonObject { ["id"] = Text(s.Id), ["types"] = Strings(s.Types) };
        try
        {
            o["storageRoot"] = Text(s.GetStorageRoot());
        }
        catch (ProtocolException)
        {
            // no storage root: omitted
        }
        o["services"] = new JsonArray([.. s.Services.Select(svc =>
        {
            var service = new JsonObject();
            Put(service, "id", svc.Id);
            service["types"] = Strings(svc.Types);
            service["serviceEndpoint"] = Text(svc.ServiceEndpoint);
            if (svc.GetProperty("subscriptionType") is not null) service["subscriptionType"] = Strings(svc.SubscriptionTypes);
            return (JsonNode)service;
        })]);
        o["verificationMethods"] = new JsonArray([.. s.VerificationMethods.Select(vm =>
        {
            var method = new JsonObject();
            Put(method, "id", vm.Id);
            Put(method, "type", vm.Type);
            Put(method, "controller", vm.Controller);
            return (JsonNode)method;
        })]);
        o["raw"] = Raw(s.Raw);
        return o;
    }

    /// <summary>Subscription.</summary>
    public static JsonObject Subscription(Subscription s)
    {
        var o = new JsonObject { ["subscription"] = Text(s.Url), ["types"] = Strings(s.Types) };
        Put(o, "expires", s.ExpiresRaw);
        o["raw"] = Raw(s.Raw);
        return o;
    }

    /// <summary>A verified notification.</summary>
    public static JsonObject Verified(VerifiedNotification v) => new()
    {
        ["storage"] = Text(v.Storage),
        ["keyid"] = v.KeyId,
        ["activities"] = new JsonArray([.. v.Notification.Activities.Select(a =>
        {
            var activity = new JsonObject();
            Put(activity, "id", string.IsNullOrEmpty(a.Id) ? null : a.Id);
            activity["types"] = Strings(a.Types);
            activity["object"] = Text(a.Object.Id);
            activity["objectTypes"] = Strings(a.Object.Types);
            return (JsonNode)activity;
        })]),
        ["raw"] = Raw(v.Notification.Raw),
    };

    /// <summary>A type index page.</summary>
    public static JsonObject TypeIndex(TypeIndexPage page)
    {
        var o = new JsonObject();
        Put(o, "totalItems", page.TotalItems);
        o["types"] = Strings(page.Types);
        Put(o, "first", page.First);
        Put(o, "next", page.Next);
        Put(o, "prev", page.Prev);
        Put(o, "last", page.Last);
        return o;
    }

    /// <summary>A linkset document read from a resource.</summary>
    public static JsonObject Linkset(LinksetDocument doc)
    {
        var o = new JsonObject { ["url"] = Text(doc.Url) };
        Put(o, "etag", doc.ETag);
        o["linkset"] = doc.Linkset.ToJson();
        o["allow"] = Strings(doc.Allow);
        o["acceptPatch"] = Strings(doc.AcceptPatch);
        return o;
    }
}
