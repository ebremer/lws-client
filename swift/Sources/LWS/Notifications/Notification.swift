// SPDX-License-Identifier: MIT
import Foundation

/// A webhook subscription request (`lws10-notifications-webhook`). A container topic covers the container and
/// everything transitively contained in it.
public struct WebhookSubscriptionRequest: Sendable, Hashable {
    /// The resources to watch.
    public let topics: [URL]
    /// Where the server POSTs notifications.
    public let inbox: URL
    /// When the subscription should expire.
    public var expires: Date?

    /// Creates a request.
    /// - Throws: ``LWSError/invalidArgument(_:)`` without topics.
    public init(topics: [URL], inbox: URL, expires: Date? = nil) throws {
        guard !topics.isEmpty else { throw LWSError.invalidArgument("At least one topic is required") }
        self.topics = topics
        self.inbox = inbox
        self.expires = expires
    }

    /// The `application/lws+json` request body.
    public var json: JSONObject {
        var o: JSONObject = [
            "@context": .array([.string(Vocabulary.context)]),
            "type": .string(SubscriptionType.webhook),
            "topic": LWSJSON.strings(topics.map(\.absoluteString)),
            "inbox": .string(inbox.absoluteString),
        ]
        if let expires { o["expires"] = .string(Dates.formatRFC3339(expires)) }
        return o
    }
}

/// A subscription as returned by the notification service.
public struct Subscription: Sendable, CustomStringConvertible {
    /// The subscription type (`WebhookSubscription`).
    public let type: String?
    /// The URL managing the subscription (the `subscription` member): GET to inspect, DELETE to cancel.
    public let url: URL
    /// The `expires` value as sent.
    public let expiresRaw: String?
    /// The JSON document.
    public let raw: JSONObject

    /// The raw `type` values.
    public var types: [String] { raw.strings("type") }

    /// When the subscription expires, if parseable.
    public var expires: Date? { Dates.parseRFC3339(expiresRaw) }

    /// Parses a subscription document; `location` (the `Location` header, or the request URL) is used when the
    /// body has no `subscription` member.
    /// - Throws: ``LWSError/protocolError(_:)`` when there is no subscription URL.
    public static func parse(_ json: JSONValue, base: URL?, location: URL?) throws -> Subscription {
        let o = try LWSJSON.object(json, "Subscription")
        guard let url = o.url("subscription", base: base) ?? location else {
            throw LWSError.protocolError("The subscription response has no subscription URL")
        }
        return Subscription(type: o.strings("type").first, url: url, expiresRaw: o.string("expires"), raw: o)
    }

    public var description: String { url.absoluteString }
}

/// An LWS notification envelope: the storage it concerns and one or more Activity Streams activities
/// (`Create`, `Update`, `Delete`, …). A single `activity` object is exposed as a one-element list.
public struct Notification: Sendable {
    /// The storage the notification belongs to.
    public let storage: URL
    /// The activities, in order.
    public let activities: [Activity]
    /// The JSON document.
    public let raw: JSONObject

    /// Parses a notification from UTF-8 JSON.
    /// - Throws: ``LWSError/protocolError(_:)`` when it is not a valid notification.
    public static func parse(_ data: Data) throws -> Notification {
        try parse(LWSJSON.parse(data, "Notification"))
    }

    /// Parses a notification document; its `type` must be `Notification`.
    /// - Throws: ``LWSError/protocolError(_:)`` when it is not a valid notification.
    public static func parse(_ json: JSONValue) throws -> Notification {
        let o = try LWSJSON.object(json, "Notification")
        guard Vocabulary.hasType(o.strings("type"), ResourceType.notification) else {
            throw LWSError.protocolError("The document type is not Notification")
        }
        guard let storageText = o.string("storage") else { throw LWSError.protocolError("The notification has no storage") }
        guard let storage = URLs.resolve(storageText, against: nil) else {
            throw LWSError.protocolError("The notification storage is not an absolute URL")
        }
        let activities: [Activity]
        switch o["activity"] {
        case .object(let a)?: activities = [try Activity.parse(a)]
        case .array(let many)?: activities = try many.map { try Activity.parse(try LWSJSON.object($0, "Activity")) }
        default: throw LWSError.protocolError("The notification has no activity")
        }
        return Notification(storage: storage, activities: activities, raw: o)
    }
}

/// An Activity Streams activity describing a change.
public struct Activity: Sendable {
    /// The activity id, if any.
    public let id: String?
    /// The activity types (e.g. `Create`).
    public let types: [String]
    /// The resource concerned.
    public let object: ActivityObject
    /// The agent that performed the change.
    public let actor: URL?
    /// The container a resource was added to (`Create`).
    public let target: URL?
    /// The container a resource was removed from (`Delete`).
    public let origin: URL?
    /// The `published` value as sent.
    public let publishedRaw: String?
    /// The JSON object.
    public let raw: JSONObject

    /// When the activity occurred, if parseable.
    public var published: Date? { Dates.parseRFC3339(publishedRaw) }

    /// Whether this is a `Create` activity.
    public var isCreate: Bool { hasType(ActivityType.create) }
    /// Whether this is an `Update` activity.
    public var isUpdate: Bool { hasType(ActivityType.update) }
    /// Whether this is a `Delete` activity.
    public var isDelete: Bool { hasType(ActivityType.delete) }

    /// Whether the activity has `type` (`T`, `as:T` and the full IRI match).
    public func hasType(_ type: String) -> Bool {
        types.contains(type) || types.contains("as:" + type) || types.contains("https://www.w3.org/ns/activitystreams#" + type)
    }

    static func parse(_ o: JSONObject) throws -> Activity {
        guard case .object(let obj)? = o["object"] else { throw LWSError.protocolError("The activity has no object") }
        guard let idText = obj.string("id"), let id = URLs.resolve(idText, against: nil) else {
            throw LWSError.protocolError("The activity object has no valid id")
        }
        return Activity(id: o.string("id"), types: o.strings("type"), object: ActivityObject(id: id, types: obj.strings("type"), raw: obj),
                        actor: o.url("actor", base: nil), target: o.url("target", base: nil), origin: o.url("origin", base: nil),
                        publishedRaw: o.string("published"), raw: o)
    }
}

/// The resource an activity is about.
public struct ActivityObject: Sendable {
    /// The resource URL.
    public let id: URL
    /// The resource types (`Container`, `DataResource`, …).
    public let types: [String]
    /// The JSON object.
    public let raw: JSONObject

    /// Whether the resource is a container.
    public var isContainer: Bool { Vocabulary.hasType(types, ResourceType.container) }
    /// Whether the resource is a data resource.
    public var isDataResource: Bool { Vocabulary.hasType(types, ResourceType.dataResource) }
}
