// SPDX-License-Identifier: MIT
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws.Notifications;

/// <summary>
/// A webhook subscription request (<c>lws10-notifications-webhook</c>). A container topic covers the container and
/// everything transitively contained in it.
/// </summary>
public sealed record WebhookSubscriptionRequest
{
    /// <summary>Creates a request.</summary>
    /// <param name="inbox">Where the server POSTs notifications.</param>
    /// <param name="topics">The resources to watch (at least one).</param>
    /// <param name="expires">When the subscription should expire.</param>
    public WebhookSubscriptionRequest(Uri inbox, IEnumerable<Uri> topics, DateTimeOffset? expires = null)
    {
        Inbox = inbox ?? throw new ArgumentNullException(nameof(inbox));
        Topics = (topics ?? throw new ArgumentNullException(nameof(topics))).ToList().AsReadOnly();
        if (Topics.Count == 0) throw new ArgumentException("At least one topic is required", nameof(topics));
        Expires = expires;
    }

    /// <summary>The resources to watch.</summary>
    public IReadOnlyList<Uri> Topics { get; }

    /// <summary>Where the server POSTs notifications.</summary>
    public Uri Inbox { get; }

    /// <summary>When the subscription should expire.</summary>
    public DateTimeOffset? Expires { get; init; }

    /// <summary>The <c>application/lws+json</c> request body.</summary>
    /// <returns>The document.</returns>
    public JsonObject ToJson()
    {
        var o = new JsonObject
        {
            ["@context"] = new JsonArray(Lws.Context),
            ["type"] = Lws.SubscriptionType.Webhook,
            ["topic"] = LwsJson.StringArray(Topics.Select(Uris.ToText)),
            ["inbox"] = Uris.ToText(Inbox),
        };
        if (Expires is { } e) o["expires"] = LwsJson.FormatDateTime(e);
        return o;
    }
}

/// <summary>A subscription as returned by the notification service.</summary>
public sealed class Subscription
{
    private Subscription(string? type, Uri url, string? expiresRaw, JsonElement raw)
    {
        Type = type;
        Url = url;
        ExpiresRaw = expiresRaw;
        Expires = LwsJson.ParseDateTime(expiresRaw);
        Raw = raw;
    }

    /// <summary>The subscription type (<c>WebhookSubscription</c>).</summary>
    public string? Type { get; }

    /// <summary>The raw <c>type</c> values.</summary>
    public IReadOnlyList<string> Types => LwsJson.StringOrArray(LwsJson.Get(Raw, "type"));

    /// <summary>The URL managing the subscription (the <c>subscription</c> member): GET to inspect, DELETE to cancel.</summary>
    public Uri Url { get; }

    /// <summary>When the subscription expires, if parseable.</summary>
    public DateTimeOffset? Expires { get; }

    /// <summary>The <c>expires</c> value as sent.</summary>
    public string? ExpiresRaw { get; }

    /// <summary>The JSON document.</summary>
    public JsonElement Raw { get; }

    /// <summary>
    /// Parses a subscription document; <paramref name="location"/> (the <c>Location</c> header, or the request URL)
    /// is used when the body has no <c>subscription</c> member.
    /// </summary>
    /// <param name="json">The document.</param>
    /// <param name="baseUri">The URL relative references resolve against.</param>
    /// <param name="location">The fallback subscription URL.</param>
    /// <returns>The subscription.</returns>
    /// <exception cref="ProtocolException">There is no subscription URL.</exception>
    public static Subscription Parse(JsonElement json, Uri? baseUri, Uri? location)
    {
        LwsJson.RequireObject(json, "Subscription");
        Uri url = LwsJson.GetUri(json, "subscription", baseUri) ?? location
            ?? throw new ProtocolException("The subscription response has no subscription URL");
        return new Subscription(LwsJson.StringOrArray(LwsJson.Get(json, "type")).FirstOrDefault(), url,
            LwsJson.GetString(json, "expires"), json.Clone());
    }

    /// <inheritdoc/>
    public override string ToString() => Uris.ToText(Url);
}

/// <summary>
/// An LWS notification envelope: the storage it concerns and one or more Activity Streams activities
/// (<c>Create</c>, <c>Update</c>, <c>Delete</c>, …). A single <c>activity</c> object is exposed as a one-element list.
/// </summary>
public sealed class Notification
{
    private Notification(Uri storage, IReadOnlyList<Activity> activities, JsonElement raw)
    {
        Storage = storage;
        Activities = activities;
        Raw = raw;
    }

    /// <summary>The storage the notification belongs to.</summary>
    public Uri Storage { get; }

    /// <summary>The activities, in order.</summary>
    public IReadOnlyList<Activity> Activities { get; }

    /// <summary>The JSON document.</summary>
    public JsonElement Raw { get; }

    /// <summary>Parses a notification from UTF-8 JSON.</summary>
    /// <param name="utf8Json">The body.</param>
    /// <returns>The notification.</returns>
    /// <exception cref="ProtocolException">It is not a valid notification.</exception>
    public static Notification Parse(ReadOnlySpan<byte> utf8Json) => Parse(LwsJson.Parse(utf8Json, "Notification"));

    /// <summary>Parses a notification from JSON text.</summary>
    /// <param name="json">The body.</param>
    /// <returns>The notification.</returns>
    /// <exception cref="ProtocolException">It is not a valid notification.</exception>
    public static Notification Parse(string json) => Parse(Encoding.UTF8.GetBytes(json ?? throw new ArgumentNullException(nameof(json))));

    /// <summary>Parses a notification document.</summary>
    /// <param name="json">The document.</param>
    /// <returns>The notification.</returns>
    /// <exception cref="ProtocolException">It is not a valid notification (its <c>type</c> must be <c>Notification</c>).</exception>
    public static Notification Parse(JsonElement json)
    {
        LwsJson.RequireObject(json, "Notification");
        if (!Lws.HasType(LwsJson.StringOrArray(LwsJson.Get(json, "type")), Lws.Types.Notification))
        {
            throw new ProtocolException("The document type is not Notification");
        }
        string storageText = LwsJson.GetString(json, "storage") ?? throw new ProtocolException("The notification has no storage");
        Uri storage = Uris.Resolve(null, storageText) ?? throw new ProtocolException("The notification storage is not an absolute URL");
        var activities = new List<Activity>();
        switch (LwsJson.Get(json, "activity"))
        {
            case { ValueKind: JsonValueKind.Object } single:
                activities.Add(Activity.Parse(single));
                break;
            case { ValueKind: JsonValueKind.Array } many:
                foreach (JsonElement a in many.EnumerateArray()) activities.Add(Activity.Parse(LwsJson.RequireObject(a, "Activity")));
                break;
            default:
                throw new ProtocolException("The notification has no activity");
        }
        return new Notification(storage, activities.AsReadOnly(), json.Clone());
    }
}

/// <summary>An Activity Streams activity describing a change.</summary>
public sealed class Activity
{
    private Activity(JsonElement raw, ActivityObject obj)
    {
        Raw = raw;
        Id = LwsJson.GetString(raw, "id");
        Types = LwsJson.StringOrArray(LwsJson.Get(raw, "type"));
        Object = obj;
        Actor = LwsJson.GetUri(raw, "actor", null);
        Target = LwsJson.GetUri(raw, "target", null);
        Origin = LwsJson.GetUri(raw, "origin", null);
        PublishedRaw = LwsJson.GetString(raw, "published");
        Published = LwsJson.ParseDateTime(PublishedRaw);
    }

    /// <summary>The activity id, if any.</summary>
    public string? Id { get; }

    /// <summary>The activity types (e.g. <c>Create</c>).</summary>
    public IReadOnlyList<string> Types { get; }

    /// <summary>The resource concerned.</summary>
    public ActivityObject Object { get; }

    /// <summary>The agent that performed the change.</summary>
    public Uri? Actor { get; }

    /// <summary>The container a resource was added to (<c>Create</c>).</summary>
    public Uri? Target { get; }

    /// <summary>The container a resource was removed from (<c>Delete</c>).</summary>
    public Uri? Origin { get; }

    /// <summary>When the activity occurred, if parseable.</summary>
    public DateTimeOffset? Published { get; }

    /// <summary>The <c>published</c> value as sent.</summary>
    public string? PublishedRaw { get; }

    /// <summary>The JSON object.</summary>
    public JsonElement Raw { get; }

    /// <summary>Whether this is a <c>Create</c> activity.</summary>
    public bool IsCreate => HasType(Lws.Activities.Create);

    /// <summary>Whether this is an <c>Update</c> activity.</summary>
    public bool IsUpdate => HasType(Lws.Activities.Update);

    /// <summary>Whether this is a <c>Delete</c> activity.</summary>
    public bool IsDelete => HasType(Lws.Activities.Delete);

    /// <summary>Whether the activity has <paramref name="type"/> (<c>T</c>, <c>as:T</c> and the full IRI match).</summary>
    /// <param name="type">An activity type.</param>
    /// <returns>Whether it matches.</returns>
    public bool HasType(string type) =>
        Types.Contains(type) || Types.Contains("as:" + type) || Types.Contains("https://www.w3.org/ns/activitystreams#" + type);

    internal static Activity Parse(JsonElement o)
    {
        if (LwsJson.Get(o, "object") is not { ValueKind: JsonValueKind.Object } obj)
        {
            throw new ProtocolException("The activity has no object");
        }
        Uri id = LwsJson.GetString(obj, "id") is { } idText && Uris.Resolve(null, idText) is { } u
            ? u
            : throw new ProtocolException("The activity object has no valid id");
        return new Activity(o.Clone(), new ActivityObject(id, LwsJson.StringOrArray(LwsJson.Get(obj, "type")), obj.Clone()));
    }
}

/// <summary>The resource an activity is about.</summary>
/// <param name="Id">The resource URL.</param>
/// <param name="Types">The resource types (<c>Container</c>, <c>DataResource</c>, …).</param>
/// <param name="Raw">The JSON object.</param>
public sealed record ActivityObject(Uri Id, IReadOnlyList<string> Types, JsonElement Raw)
{
    /// <summary>Whether the resource is a container.</summary>
    public bool IsContainer => Lws.HasType(Types, Lws.Types.Container);

    /// <summary>Whether the resource is a data resource.</summary>
    public bool IsDataResource => Lws.HasType(Types, Lws.Types.DataResource);
}
