// SPDX-License-Identifier: MIT
import Foundation
import LWS

/// The shared result shapes of PROTOCOL.md section 3.1, built from the library's own results.
enum Results {
    static func strings<S: Sequence>(_ values: S) -> JSONValue where S.Element == String {
        .array(values.map { .string($0) })
    }

    /// Sets an optional member, omitting it when absent.
    static func put(_ o: inout JSONObject, _ name: String, _ value: String?) {
        if let value { o[name] = .string(value) }
    }

    static func put(_ o: inout JSONObject, _ name: String, _ value: URL?) {
        if let value { o[name] = .string(value.absoluteString) }
    }

    static func put(_ o: inout JSONObject, _ name: String, _ value: Int64?) {
        if let value { o[name] = .int(value) }
    }

    /// Whether a content type is textual: `text/*`, `application/json`, `application/xml`, or a `+json` / `+xml`
    /// suffix.
    static func isTextual(_ contentType: String) -> Bool {
        let essence = contentType.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)[0]
            .trimmingCharacters(in: .whitespaces).lowercased()
        return essence.hasPrefix("text/") || essence == "application/json" || essence == "application/xml"
            || essence.hasSuffix("+json") || essence.hasSuffix("+xml")
    }

    /// A response body: text for textual content types, else base64.
    static func body(_ resource: Resource) -> JSONValue {
        if let ct = resource.contentType, isTextual(ct) { return ["text": .string(resource.text)] }
        return ["base64": .string(resource.body.base64EncodedString())]
    }

    /// Metadata: the parsed response headers.
    static func metadata(_ m: ResourceMetadata) -> JSONValue {
        var o: JSONObject = ["url": .string(m.url.absoluteString), "status": .int(Int64(m.status))]
        put(&o, "etag", m.etag)
        put(&o, "lastModified", m.lastModifiedRaw)
        put(&o, "contentType", m.contentType)
        put(&o, "contentLength", m.contentLength)
        o["links"] = .array(m.links.map { l in
            .object(["href": .string(l.href.absoluteString), "rel": .string(l.rel),
                     "params": .object(JSONObject(l.orderedParameters.map { ($0.0, .string($0.1)) }))])
        })
        put(&o, "linkset", m.linkset)
        put(&o, "parent", m.parent)
        put(&o, "storage", m.storage)
        o["types"] = strings(m.types)
        o["allow"] = strings(m.allow)
        o["acceptPatch"] = strings(m.acceptPatch)
        return .object(o)
    }

    /// Item: one member of a listing.
    static func item(_ i: ContainedResource) -> JSONValue {
        var o: JSONObject = ["id": .string(i.id.absoluteString), "types": strings(i.types)]
        put(&o, "format", i.format)
        put(&o, "size", i.size)
        put(&o, "modified", i.modifiedRaw)
        return .object(o)
    }

    /// Page: a container page or a page of search results.
    static func page(_ p: ContainerPage) -> JSONValue {
        var o: JSONObject = ["id": .string(p.id.absoluteString), "types": strings(p.types)]
        put(&o, "totalItems", p.totalItems)
        o["items"] = .array(p.items.map(item))
        put(&o, "first", p.first)
        put(&o, "next", p.next)
        put(&o, "prev", p.prev)
        put(&o, "last", p.last)
        o["metadata"] = metadata(p.metadata)
        return .object(o)
    }

    /// Update: the result of a PUT or PATCH.
    static func update(_ u: UpdateResult) -> JSONValue {
        var o: JSONObject = ["status": .int(Int64(u.status))]
        put(&o, "etag", u.etag)
        o["metadata"] = metadata(u.metadata)
        return .object(o)
    }

    /// Created: the result of a create.
    static func created(_ c: CreateResult) -> JSONValue {
        ["location": .string(c.location.absoluteString), "metadata": metadata(c.metadata)]
    }

    /// Storage: a storage description; `storageRoot` is omitted when the library's `storageRoot()` fails.
    static func storage(_ s: StorageDescription) -> JSONValue {
        var o: JSONObject = ["id": .string(s.id.absoluteString), "types": strings(s.types)]
        put(&o, "storageRoot", try? s.storageRoot())
        o["services"] = .array(s.services.map { svc in
            var service = JSONObject()
            put(&service, "id", svc.id)
            service["types"] = strings(svc.types)
            service["serviceEndpoint"] = .string(svc.serviceEndpoint.absoluteString)
            if svc.property("subscriptionType") != nil { service["subscriptionType"] = strings(svc.subscriptionTypes) }
            return .object(service)
        })
        o["verificationMethods"] = .array(s.verificationMethods.map { vm in
            var method = JSONObject()
            put(&method, "id", vm.id)
            put(&method, "type", vm.type)
            put(&method, "controller", vm.controller)
            return .object(method)
        })
        o["raw"] = .object(s.raw)
        return .object(o)
    }

    /// Subscription.
    static func subscription(_ s: Subscription) -> JSONValue {
        var o: JSONObject = ["subscription": .string(s.url.absoluteString), "types": strings(s.types)]
        put(&o, "expires", s.expiresRaw)
        o["raw"] = .object(s.raw)
        return .object(o)
    }

    /// A verified notification.
    static func verified(_ v: VerifiedNotification) -> JSONValue {
        [
            "storage": .string(v.storage.absoluteString),
            "keyid": .string(v.keyID),
            "activities": .array(v.notification.activities.map { a in
                var activity = JSONObject()
                put(&activity, "id", a.id?.isEmpty == false ? a.id : nil)
                activity["types"] = strings(a.types)
                activity["object"] = .string(a.object.id.absoluteString)
                activity["objectTypes"] = strings(a.object.types)
                return .object(activity)
            }),
            "raw": .object(v.notification.raw),
        ]
    }

    /// A type index page.
    static func typeIndex(_ page: TypeIndexPage) -> JSONValue {
        var o = JSONObject()
        put(&o, "totalItems", page.totalItems)
        o["types"] = strings(page.types)
        put(&o, "first", page.first)
        put(&o, "next", page.next)
        put(&o, "prev", page.prev)
        put(&o, "last", page.last)
        return .object(o)
    }

    /// A linkset document read from a resource.
    static func linkset(_ doc: LinksetDocument) -> JSONValue {
        var o: JSONObject = ["url": .string(doc.url.absoluteString)]
        put(&o, "etag", doc.etag)
        o["linkset"] = .object(doc.linkset.json)
        o["allow"] = strings(doc.allow)
        o["acceptPatch"] = strings(doc.acceptPatch)
        return .object(o)
    }
}
