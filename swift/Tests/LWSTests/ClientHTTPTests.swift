// SPDX-License-Identifier: MIT
import Foundation
import Testing
@testable import LWS

/// Every operation against an in-process fake server: the requests sent and the results parsed.
@Suite struct ClientHTTPTests {
    private static let base = "https://storage.example"
    private static let root = base + "/root/"
    private let server = FakeServer()
    private let client: LWSClient

    init() {
        client = LWSClient(options: LWSClientOptions(transport: server))
    }

    private var base: String { Self.base }
    private var root: String { Self.root }

    private static var storageDescriptionJSON: String {
        Fixtures.load("responses/storage-description.json")["body"]!.serialized()
    }

    private static func dataLinks(_ url: String, _ parent: String) -> [(String, String)] {
        [
            ("Link", "<\(url).meta>; rel=\"linkset\"; type=\"application/linkset+json\""),
            ("Link", "<\(parent)>; rel=\"up\""),
            ("Link", "<https://www.w3.org/ns/lws#DataResource>; rel=\"type\""),
            ("Link", "</>; rel=\"https://www.w3.org/ns/lws#storage\""),
        ]
    }

    private static func page(_ id: String, _ itemIDs: String...) -> String {
        let o: JSONObject = [
            "@context": "https://www.w3.org/ns/lws/v1",
            "id": .string(id),
            "type": "Container",
            "totalItems": 7,
            "items": .array(itemIDs.map { .object(["id": .string($0), "type": "DataResource", "format": "text/plain"]) }),
        ]
        return o.description
    }

    private static func make(_ status: Int, _ body: Data, _ contentType: String?, _ headers: [(String, String)]) -> HTTPResponse {
        var h = HTTPHeaders(headers)
        if let contentType { h.add("Content-Type", contentType) }
        return HTTPResponse(url: url("about:blank"), status: status, headers: h, body: body)
    }

    private func linkValues(_ r: Recorded) -> [String] {
        r.headerValues("Link").flatMap { LinkHeader.parse($0, base: nil) }.map(\.headerValue)
    }

    // MARK: - Discovery

    @Test func discoverStorageFollowsTheStorageLink() async throws {
        server.on("HEAD", root) { _ in Respond.status(200, ("Link", "</>; rel=\"https://www.w3.org/ns/lws#storage\"")) }
        server.on("GET", base + "/") { _ in Respond.json(200, Self.storageDescriptionJSON, contentType: "application/lws+cid") }
        let s = try await client.discoverStorage(url(root))
        #expect(s.id.absoluteString == base + "/")
        #expect(try s.storageRoot().absoluteString == root)
        let get = server.requests("GET", base + "/")
        #expect(get.count == 1)
        #expect(get.first?.header("Accept") == "application/lws+cid, application/ld+json;q=0.9, application/json;q=0.8")
        #expect(get.first?.header("User-Agent") == LWSClient.defaultUserAgent)
    }

    @Test func discoverStorageFallsBackToGetAndAcceptsAnAnonymous401() async throws {
        server.on("HEAD", root) { _ in Respond.status(405, ("Allow", "GET")) }
        server.on("GET", root) { _ in
            Respond.status(401, ("WWW-Authenticate", "Bearer realm=\"x\""), ("Link", "</>; rel=\"https://www.w3.org/ns/lws#storage\""))
        }
        server.on("GET", base + "/") { _ in Respond.json(200, Self.storageDescriptionJSON, contentType: "application/ld+json") }
        let s = try await client.discoverStorage(url(root))
        #expect(s.id.absoluteString == base + "/")
        #expect(server.requests.map(\.method) == ["HEAD", "GET", "GET"])
    }

    @Test func discoverStorageFailures() async throws {
        server.on("HEAD", root) { _ in Respond.status(200) }
        #expect(kind(await error { try await client.discoverStorage(url(root)) }) == "protocolError")
        server.on("HEAD", root) { _ in Respond.status(403) }
        #expect(kind(await error { try await client.discoverStorage(url(root)) }) == "forbidden")
        server.on("GET", base + "/") { _ in Respond.text(200, "<html/>", contentType: "text/html") }
        #expect(kind(await error { try await client.getStorageDescription(url(base + "/")) }) == "protocolError")
        server.on("GET", base + "/") { _ in Respond.json(200, #"{"id":"/","type":"Thing"}"#) }
        #expect(kind(await error { try await client.getStorageDescription(url(base + "/")) }) == "protocolError")
        server.on("GET", base + "/") { _ in Respond.json(200, "{not json") }
        #expect(kind(await error { try await client.getStorageDescription(url(base + "/")) }) == "protocolError")
    }

    // MARK: - Reading

    @Test func headParsesTheMetadata() async throws {
        let u = root + "notes/a.txt"
        server.on("HEAD", u) { _ in
            Self.make(200, Data(), "text/plain; charset=utf-8", [
                ("ETag", "W/\"v1\""), ("Last-Modified", "Tue, 06 Oct 2026 12:00:00 GMT"), ("Content-Length", "11"),
                ("Allow", "GET, HEAD, PUT"), ("Allow", "DELETE"), ("Accept-Patch", "application/json-patch+json"),
            ] + Self.dataLinks(u, Self.root + "notes/"))
        }
        let m = try await client.head(url(u))
        #expect(m.url.absoluteString == u)
        #expect(m.status == 200)
        #expect(m.etag == "W/\"v1\"")
        #expect(m.lastModified == Date(timeIntervalSince1970: 1_791_288_000))
        #expect(m.lastModifiedRaw == "Tue, 06 Oct 2026 12:00:00 GMT")
        #expect(m.contentType == "text/plain; charset=utf-8")
        #expect(m.contentLength == 11)
        #expect(m.linkset?.absoluteString == u + ".meta")
        #expect(m.parent?.absoluteString == root + "notes/")
        #expect(m.storage?.absoluteString == base + "/")
        #expect(m.types == [ResourceType.dataResource])
        #expect(m.isDataResource)
        #expect(!m.isContainer)
        #expect(m.allow == ["GET", "HEAD", "PUT", "DELETE"])
        #expect(m.acceptPatch == ["application/json-patch+json"])
        #expect(m.links.count == 4)
        #expect(m.link("linkset")?.type == "application/linkset+json")
        #expect(m.links("up").count == 1)
    }

    @Test func readSendsTheOptionsAndDecodesTheCharset() async throws {
        let u = root + "latin1.txt"
        server.on("GET", u) { _ in Self.make(200, "café".data(using: .isoLatin1)!, "text/plain; charset=ISO-8859-1", [("ETag", "\"1\"")]) }
        let r = try await client.read(url(u), options: ReadOptions(accept: "text/plain", range: .bytes(0...99), ifNoneMatch: "\"0\"",
                                                                   ifModifiedSince: Date(timeIntervalSince1970: 1_790_841_600),
                                                                   prefer: "return=minimal", headers: ["X-Trace": "abc"]))
        #expect(r.text == "café")
        #expect(!r.notModified)
        #expect(r.etag == "\"1\"")
        let req = try #require(server.requests.first)
        #expect(req.header("Accept") == "text/plain")
        #expect(req.header("Range") == "bytes=0-99")
        #expect(req.header("If-None-Match") == "\"0\"")
        #expect(req.header("If-Modified-Since") == "Thu, 01 Oct 2026 08:00:00 GMT")
        #expect(req.header("Prefer") == "return=minimal")
        #expect(req.header("X-Trace") == "abc")
        #expect(ByteRange.from(5).headerValue == "bytes=5-")
        #expect(ByteRange.suffix(100).headerValue == "bytes=-100")
    }

    @Test func conditionalAndPartialReads() async throws {
        let u = root + "a.json"
        server.on("GET", u) { r in
            if r.header("If-None-Match") == "\"7\"" { return Respond.status(304, ("ETag", "\"7\"")) }
            if r.header("Range") != nil { return Respond.text(206, "{\"a\"", contentType: "application/json", ("Content-Range", "bytes 0-3/9")) }
            return Respond.json(200, #"{"a":[1]}"#, contentType: "application/json", ("ETag", "\"7\""))
        }
        let full = try await client.read(url(u))
        #expect(try full.json()["a"]?[0] == 1)
        #expect(try full.decode([String: [Int]].self)["a"] == [1])
        let notModified = try await client.read(url(u), options: ReadOptions(ifNoneMatch: full.etag))
        #expect(notModified.notModified)
        #expect(notModified.status == 304)
        #expect(notModified.body.isEmpty)
        let partial = try await client.read(url(u), options: ReadOptions(range: .bytes(0...3)))
        #expect(partial.status == 206)
        #expect(partial.contentRange == "bytes 0-3/9")
        #expect(partial.text == "{\"a\"")
        #expect(kind(syncError { try partial.json() }) == "protocolError")
    }

    @Test func readContainerChecksTheRepresentation() async throws {
        server.on("GET", root) { _ in Respond.json(200, Self.page("/root/", "/root/a", "b"), contentType: "application/lws+json", ("ETag", "\"c1\"")) }
        let page = try await client.readContainer(url(root))
        #expect(page.id.absoluteString == root)
        #expect(page.items.map(\.id.absoluteString) == [root + "a", root + "b"])
        #expect(page.totalItems == 7)
        #expect(page.etag == "\"c1\"")
        #expect(server.requests.first?.header("Accept") == "application/lws+json")

        server.on("GET", root) { _ in Respond.text(200, "<html/>", contentType: "text/html") }
        #expect(kind(await error { try await client.readContainer(url(root)) }) == "protocolError")
        server.on("GET", root) { _ in Respond.json(200, #"{"id":"/root/","type":"DataResource"}"#, contentType: "application/ld+json") }
        #expect(kind(await error { try await client.readContainer(url(root)) }) == "protocolError")
        // A container identified by its rel="type" link and served as application/json is fine.
        server.on("GET", root) { _ in
            Respond.json(200, #"{"items":[]}"#, contentType: "application/json; charset=utf-8", ("Link", "<https://www.w3.org/ns/lws#Container>; rel=\"type\""))
        }
        #expect(try await client.readContainer(url(root)).isContainer)
    }

    @Test func listContainerFollowsThreePagesLazily() async throws {
        server.on("GET", root) { _ in Respond.json(200, Self.page("/root/", "a", "b"), contentType: "application/lws+json", ("Link", "</root/?page=2>; rel=\"next\"")) }
        server.on("GET", root + "?page=2") { _ in Respond.json(200, Self.page("/root/", "c", "d"), contentType: "application/lws+json", ("Link", "<?page=3>; rel=\"next\"")) }
        server.on("GET", root + "?page=3") { _ in Respond.json(200, Self.page("/root/", "e"), contentType: "application/lws+json", ("Link", "</root/>; rel=\"first\"")) }
        let all = client.listContainer(url(root))
        #expect(server.requests.isEmpty)
        var ids: [String] = []
        for try await item in all { ids.append(String(item.id.absoluteString.dropFirst(root.count))) }
        #expect(ids == ["a", "b", "c", "d", "e"])
        #expect(server.requests.map(\.url.absoluteString) == [root, root + "?page=2", root + "?page=3"])

        // Pulling only two items reads only the first page.
        let before = server.requests.count
        var it = client.listContainer(url(root)).makeAsyncIterator()
        _ = try await it.next()
        _ = try await it.next()
        #expect(server.requests.count == before + 1)
    }

    @Test func listContainerStopsOnALoop() async throws {
        server.on("GET", root) { _ in Respond.json(200, Self.page("/root/", "a"), contentType: "application/lws+json", ("Link", "</root/?page=2>; rel=\"next\"")) }
        server.on("GET", root + "?page=2") { _ in Respond.json(200, Self.page("/root/", "b"), contentType: "application/lws+json", ("Link", "</root/>; rel=\"next\"")) }
        #expect(try await client.listContainer(url(root)).collect().count == 2)
    }

    // MARK: - Creating

    @Test func createSendsSlugTypesAndLinks() async throws {
        server.on("POST", root) { _ in
            Respond.status(201, ("Location", "/root/caf%C3%A9.txt"), ("ETag", "\"1\""), ("Link", "</root/caf%C3%A9.txt.meta>; rel=\"linkset\""))
        }
        let r = try await client.createText(in: url(root), text: "Hello, LWS!", options: CreateOptions(
            slug: "café 100%.txt", links: [Link(href: url("https://example.org/shape"), rel: "describedby")], types: ["https://schema.org/Note"]))
        #expect(r.location.absoluteString == root + "caf%C3%A9.txt")
        #expect(r.etag == "\"1\"")
        #expect(r.linkset?.absoluteString == root + "caf%C3%A9.txt.meta")
        let req = try #require(server.requests.first)
        #expect(req.header("Content-Type") == "text/plain")
        #expect(req.text == "Hello, LWS!")
        #expect(req.header("Slug") == "caf%C3%A9 100%25.txt")
        #expect(linkValues(req) == ["<https://schema.org/Note>; rel=\"type\"", "<https://example.org/shape>; rel=\"describedby\""])
    }

    private struct Person: Encodable {
        let name: String
        let age: Int
    }

    @Test func createJSONAndBinary() async throws {
        server.on("POST", root) { _ in Respond.status(201, ("Location", Self.root + "x")) }
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        _ = try await client.createJSON(in: url(root), value: Person(name: "Alice", age: 30), encoder: encoder)
        #expect(server.requests.last?.header("Content-Type") == "application/json")
        #expect(server.requests.last?.text == #"{"age":30,"name":"Alice"}"#)
        _ = try await client.createJSON(in: url(root), json: ["name": "Alice", "age": 30])
        #expect(server.requests.last?.text == #"{"name":"Alice","age":30}"#)
        _ = try await client.create(in: url(root), body: Data([0, 1, 250]), contentType: "application/octet-stream")
        #expect(server.requests.last?.body == Data([0, 1, 250]))
    }

    @Test func createContainerAndMissingLocation() async throws {
        server.on("POST", root) { _ in Respond.status(201, ("Location", "notes/")) }
        let r = try await client.createContainer(in: url(root), options: CreateOptions(slug: "notes"))
        #expect(r.location.absoluteString == root + "notes/")
        let req = try #require(server.requests.first)
        #expect(linkValues(req) == ["<https://www.w3.org/ns/lws#Container>; rel=\"type\""])
        #expect(req.header("Content-Type") == nil)
        #expect(req.body.isEmpty)
        server.on("POST", root) { _ in Respond.status(201) }
        #expect(kind(await error { try await client.createContainer(in: url(root)) }) == "protocolError")
    }

    // MARK: - Updating

    @Test func updateIsConditional() async throws {
        let u = root + "a.txt"
        server.on("PUT", u) { r in
            r.header("If-Match") == "\"1\"" ? Respond.status(204, ("ETag", "\"2\"")) : Respond.json(412, #"{"title":"stale"}"#, contentType: "application/problem+json")
        }
        let ok = try await client.update(url(u), body: Data("Hello again".utf8), contentType: "text/plain", options: UpdateOptions(ifMatch: "\"1\""))
        #expect(ok.status == 204)
        #expect(ok.etag == "\"2\"")
        let e = await error { try await client.update(url(u), body: Data("x".utf8), contentType: "text/plain", options: UpdateOptions(ifMatch: "\"0\"")) }
        guard case .preconditionFailed(let h)? = e as? LWSError else {
            Issue.record("expected preconditionFailed, got \(String(describing: e))")
            return
        }
        #expect(h.status == 412)
        #expect(h.problem?.title == "stale")
        #expect(h.method == "PUT")
        #expect(h.url.absoluteString == u)
    }

    @Test func updateWithLinksetAndIfNoneMatch() async throws {
        let u = root + "b.txt"
        server.on("PUT", u) { _ in Respond.status(201) }
        _ = try await client.update(url(u), body: Data("data".utf8), contentType: "text/plain",
                                    options: UpdateOptions(ifNoneMatch: "*", links: [Link(href: url("https://example.org/l"), rel: "license")], setLinkset: true))
        let req = try #require(server.requests.first)
        #expect(req.header("If-None-Match") == "*")
        #expect(req.header("Prefer") == "set-linkset")
        #expect(linkValues(req) == ["<https://example.org/l>; rel=\"license\""])
        #expect(req.text == "data")
    }

    @Test func patchSendsJSONPatchOrARawFormat() async throws {
        let u = root + "p.json"
        server.on("PATCH", u) { r in
            r.header("Content-Type") == "application/json-patch+json"
                ? Respond.status(204, ("ETag", "\"3\""))
                : Respond.status(415, ("Accept-Patch", "application/json-patch+json, application/merge-patch+json"))
        }
        let r = try await client.patch(url(u), patch: JSONPatch().replace("/age", 31).add("/city", "Boston"), options: UpdateOptions(ifMatch: "\"2\""))
        #expect(r.etag == "\"3\"")
        let req = try #require(server.requests.first)
        #expect(req.text == #"[{"op":"replace","path":"/age","value":31},{"op":"add","path":"/city","value":"Boston"}]"#)
        #expect(req.header("If-Match") == "\"2\"")
        let e = await error { try await client.patch(url(u), body: Data("INSERT DATA {}".utf8), contentType: "application/sparql-update") }
        #expect((e as? LWSError).flatMap { if case .unsupportedMediaType(let h) = $0 { h.acceptPatch } else { nil } }
            == ["application/json-patch+json", "application/merge-patch+json"])
        #expect(server.requests.last?.header("Content-Type") == "application/sparql-update")
    }

    @Test func deleteRecursiveAndConflict() async throws {
        server.on("DELETE", root + "c/") { r in
            r.header("Depth") == "infinity"
                ? Respond.status(204)
                : Respond.json(409, Fixtures.load("responses/problem-details.json")["body"]!.serialized(), contentType: "application/problem+json")
        }
        let e = await error { try await client.delete(url(root + "c/")) }
        #expect(kind(e) == "conflict")
        #expect((e as? LWSError)?.httpError?.problem?.title == "Container not empty")
        try await client.delete(url(root + "c/"), options: DeleteOptions(ifMatch: "\"9\"", recursive: true))
        #expect(server.requests.last?.header("If-Match") == "\"9\"")
    }

    // MARK: - Linksets

    @Test func linksetOperations() async throws {
        let u = root + "p.json"
        let fixture = Fixtures.load("responses/linkset.json")
        server.on("HEAD", u) { _ in Respond.status(200, ("Link", "<p.json.meta>; rel=\"linkset\"")) }
        server.on("HEAD", root + "bare") { _ in Respond.status(200) }
        server.on("GET", u + ".meta") { _ in
            Respond.json(200, fixture["body"]!.serialized(), contentType: "application/linkset+json",
                         ("ETag", "\"ls-7\""), ("Allow", "GET, HEAD, PATCH"), ("Accept-Patch", "application/json-patch+json"))
        }
        server.on("PUT", u + ".meta") { _ in Respond.status(405, ("Allow", "GET, HEAD, PATCH")) }
        server.on("PATCH", u + ".meta") { _ in Respond.status(204) }

        #expect(try await client.linksetURL(url(u)).absoluteString == u + ".meta")
        #expect(kind(await error { try await client.linksetURL(url(root + "bare")) }) == "protocolError")
        let doc = try await client.readLinkset(url(u))
        #expect(doc.url.absoluteString == u + ".meta")
        #expect(doc.etag == "\"ls-7\"")
        #expect(!doc.supportsPut)
        #expect(server.requests("GET", u + ".meta").first?.header("Accept") == "application/linkset+json, application/json;q=0.5")

        let e = await error {
            try await client.updateLinkset(doc.url, linkset: doc.linkset.adding(anchor: doc.linkset.contexts[0].anchor, rel: "license", href: "https://example.org/l2"),
                                           options: UpdateOptions(ifMatch: doc.etag))
        }
        #expect((e as? LWSError).flatMap { if case .methodNotAllowed(let h) = $0 { h.allow } else { nil } } == ["GET", "HEAD", "PATCH"])
        let put = try #require(server.requests("PUT", u + ".meta").first)
        #expect(put.header("Content-Type") == "application/linkset+json")
        #expect(try Linkset.parse(put.text).targets("license").count == 2)

        let pointer = JSONPointer.from("linkset", "0", "https://example.org/rel/reviewer", "-")
        _ = try await client.patchLinkset(doc.url, patch: JSONPatch().add(pointer, ["href": "https://id.example/dan"]), options: UpdateOptions(ifMatch: doc.etag))
        let patch = try #require(server.requests("PATCH", u + ".meta").first)
        #expect(patch.header("Content-Type") == "application/json-patch+json")
        #expect(patch.text.contains("/linkset/0/https:~1~1example.org~1rel~1reviewer/-"))
    }

    // MARK: - Notifications

    @Test func subscriptionLifecycle() async throws {
        let service = base + "/notifications/"
        let fixture = Fixtures.load("responses/subscription.json")
        let response = fixture["response"]!
        server.on("POST", service) { _ in
            Respond.json(200, response["body"]!.serialized(), contentType: "application/lws+json", ("Location", response["headers"]!["location"]!.str))
        }
        let input = fixture["input"]!
        let expires = ISO8601DateFormatter().date(from: input["expires"]!.str)!
        let request = try WebhookSubscriptionRequest(topics: input["topics"]!.strings.map(url), inbox: url(input["inbox"]!.str), expires: expires)
        let s = try await client.subscribe(url(service), request: request)
        #expect(s.url.absoluteString == "https://notification.example/subscriptions/9e8d7c6b5a4f")
        #expect(s.type == "WebhookSubscription")
        let post = try #require(server.requests.first)
        #expect(post.header("Content-Type") == "application/lws+json")
        #expect(try JSONValue(parsing: post.text) == fixture["expectedRequestBody"]!)

        // A response without a body falls back to Location.
        server.on("POST", service) { _ in Respond.status(201, ("Location", "s/2")) }
        #expect(try await client.subscribe(url(service), request: request).url.absoluteString == service + "s/2")
        server.on("POST", service) { _ in Respond.status(201) }
        #expect(kind(await error { try await client.subscribe(url(service), request: request) }) == "protocolError")

        // Through the storage description: the service must offer webhooks.
        let sd = try StorageDescription.parse(try JSONValue(parsing:
            #"{"id":"https://storage.example/","type":"Storage","service":[{"type":"NotificationService","serviceEndpoint":"/n/","subscriptionType":["StreamingSubscription"]}]}"#),
            base: nil)
        #expect(kind(await error { try await client.subscribe(sd.notificationService!, request: request) }) == "protocolError")

        server.on("GET", service) { _ in Respond.json(200, Self.page("/notifications/", "s/1", "s/2"), contentType: "application/lws+json") }
        #expect(try await client.listSubscriptions(url(service)).collect().map(\.id.absoluteString) == [service + "s/1", service + "s/2"])
        server.on("GET", service + "s/2") { _ in
            Respond.json(200, #"{"type":"WebhookSubscription","expires":"2026-11-01T00:00:00Z"}"#, contentType: "application/lws+json")
        }
        let got = try await client.getSubscription(url(service + "s/2"))
        #expect(got.url.absoluteString == service + "s/2")
        #expect(got.expiresRaw == "2026-11-01T00:00:00Z")
        server.on("DELETE", service + "s/2") { _ in Respond.status(204) }
        try await client.unsubscribe(url(service + "s/2"))
        #expect(server.requests.last?.method == "DELETE")
    }

    // MARK: - Access

    @Test func accessRequestsAndGrants() async throws {
        let fixture = Fixtures.load("responses/access.json")
        let requests = base + "/access/requests/"
        let grants = base + "/access/grants/"
        server.on("POST", requests) { _ in Respond.status(201, ("Location", "r1")) }
        server.on("GET", requests + "r1") { _ in Respond.json(200, fixture["request"]!.serialized(), contentType: "application/lws+json") }
        server.on("GET", requests) { _ in Respond.json(200, Self.page("/access/requests/", "r1"), contentType: "application/lws+json") }
        server.on("DELETE", requests + "r1") { _ in Respond.status(204) }
        server.on("POST", grants) { _ in Respond.status(201, ("Location", grants + "g1")) }
        server.on("GET", grants + "g1") { _ in Respond.json(200, fixture["grant"]!.serialized(), contentType: "application/lws+json") }
        server.on("GET", grants) { _ in Respond.json(200, Self.page("/access/grants/", "g1"), contentType: "application/lws+json") }
        server.on("DELETE", grants + "g1") { _ in Respond.status(204) }

        let request = try AccessRequest.parse(fixture["request"]!)
        let r1 = try await client.requestAccess(url(requests), request: request)
        #expect(r1.absoluteString == requests + "r1")
        let post = try #require(server.requests.last)
        #expect(post.header("Content-Type") == "application/lws+json")
        #expect(try JSONValue(parsing: post.text) == fixture["request"]!)
        let got = try await client.getAccessRequest(r1)
        #expect(got.access[0].assignee == request.access[0].assignee)
        #expect(try await client.listAccessRequests(url(requests)).collect().map(\.id.absoluteString) == [requests + "r1"])

        let g1 = try await client.grantAccess(url(grants), grant: .approving(got))
        #expect(g1.absoluteString == grants + "g1")
        #expect(try JSONValue(parsing: server.requests.last!.text)["type"]?[0] == "AccessGrant")
        let grant = try await client.getAccessGrant(g1)
        #expect(grant.access[0].actions == ["read"])
        #expect(try await client.listAccessGrants(url(grants)).collect().count == 1)
        try await client.revokeAccessGrant(g1)
        try await client.cancelAccessRequest(r1)
        #expect(server.requests.suffix(2).map(\.method) == ["DELETE", "DELETE"])

        server.on("GET", grants + "g1") { _ in Respond.json(200, #"{"type":"Other"}"#, contentType: "application/lws+json") }
        #expect(kind(await error { try await client.getAccessGrant(g1) }) == "protocolError")
    }

    // MARK: - Type index and search

    @Test func typeIndexPages() async throws {
        let index = base + "/types/index"
        server.on("GET", index) { _ in
            Respond.json(200, #"{"type":"TypeIndex","totalItems":3,"items":[{"id":"https://schema.org/Person"}]}"#, contentType: "application/lws+json",
                         ("Link", "<?page=2>; rel=\"next\""))
        }
        server.on("GET", index + "?page=2") { _ in
            Respond.json(200, #"{"type":"TypeIndex","items":["https://schema.org/Event"]}"#, contentType: "application/lws+json", ("Link", "<?page=3>; rel=\"next\""))
        }
        server.on("GET", index + "?page=3") { _ in
            Respond.json(200, #"{"type":"TypeIndex","items":[{"id":"https://schema.org/Note"}]}"#, contentType: "application/lws+json")
        }
        let first = try await client.readTypeIndex(url(index))
        #expect(first.totalItems == 3)
        #expect(first.next?.absoluteString == index + "?page=2")
        #expect(try await client.listTypes(url(index)).collect() == ["https://schema.org/Person", "https://schema.org/Event", "https://schema.org/Note"])
        #expect(server.requests.allSatisfy { $0.header("Accept") == "application/lws+json" })
    }

    @Test func searchUsesQueryThenGetsTheNextPages() async throws {
        let search = base + "/types/search"
        server.on("QUERY", search) { _ in
            Respond.json(200, #"{"type":"ContainerPage","totalItems":3,"items":[{"id":"/data/1","type":["DataResource","https://schema.org/Person"]}]}"#,
                         contentType: "application/lws+json", ("Link", "</types/search?cursor=b>; rel=\"next\""))
        }
        server.on("GET", search + "?cursor=b") { _ in
            Respond.json(200, #"{"type":"ContainerPage","items":[{"id":"/data/2"}]}"#, contentType: "application/lws+json",
                         ("Link", "</types/search?cursor=c>; rel=\"next\""))
        }
        server.on("GET", search + "?cursor=c") { _ in Respond.json(200, #"{"type":"ContainerPage","items":[{"id":"/data/3"}]}"#, contentType: "application/lws+json") }
        server.on("OPTIONS", search) { _ in Respond.status(204, ("Allow", "OPTIONS, QUERY"), ("Accept-Query", "application/lws-query+json, \"application/jsonpath\"")) }

        let query = try TypeQuery().allOf("https://schema.org/Person")
        let page = try await client.searchTypes(url(search), query: query)
        #expect(page.id.absoluteString == search)
        #expect(page.items.map(\.id.absoluteString) == [base + "/data/1"])
        let q = try #require(server.requests.first)
        #expect(q.method == "QUERY")
        #expect(q.header("Content-Type") == "application/lws-query+json")
        #expect(q.header("Accept") == "application/lws+json")
        #expect(q.text == #"{"type":["https://schema.org/Person"]}"#)

        let all = try await client.searchAll(url(search), query: query).collect().map(\.id.absoluteString)
        #expect(all == [base + "/data/1", base + "/data/2", base + "/data/3"])
        #expect(server.requests.map(\.method) == ["QUERY", "QUERY", "GET", "GET"])

        #expect(try await client.acceptedQueryFormats(url(search)) == ["application/lws-query+json", "application/jsonpath"])
    }

    // MARK: - Errors and transport

    @Test(arguments: [
        (400, "badRequest"), (401, "unauthorized"), (403, "forbidden"), (404, "notFound"), (405, "methodNotAllowed"), (406, "notAcceptable"),
        (409, "conflict"), (410, "gone"), (412, "preconditionFailed"), (415, "unsupportedMediaType"), (422, "unprocessableContent"),
        (501, "notImplemented"), (507, "insufficientStorage"), (418, "http"), (500, "http"), (503, "http"),
    ])
    func errorStatusesMapToErrors(status: Int, expected: String) async throws {
        server.on("GET", root + "x") { _ in Respond.text(status, String(repeating: "e", count: 5000)) }
        let e = await error { try await client.read(url(root + "x")) }
        #expect(kind(e) == expected)
        let h = try #require((e as? LWSError)?.httpError)
        #expect(h.status == status)
        #expect((e as? LWSError)?.status == status)
        #expect(h.body.count == HTTPError.maxBodyLength)
        #expect(h.method == "GET")
    }

    @Test func unauthorizedCarriesTheChallenges() async throws {
        server.on("GET", root) { _ in Respond.status(401, ("WWW-Authenticate", "Bearer as_uri=\"https://as.example\", realm=\"https://storage.example/\"")) }
        let e = await error { try await client.read(url(root)) }
        #expect((e as? LWSError)?.httpError?.challenges.first?.asURI == "https://as.example")
        #expect(kind(e) == "unauthorized")
        server.on("QUERY", base + "/s") { _ in Respond.status(415, ("Accept-Query", "application/lws-query+json")) }
        let u = await error { try await client.searchTypes(url(base + "/s"), query: .empty) }
        #expect((u as? LWSError)?.httpError?.acceptQuery == ["application/lws-query+json"])
    }

    private struct ConnectionRefused: Error {}

    @Test func transportFailuresTimeoutsAndCancellation() async throws {
        server.beforeRespond = { r in
            if r.url.path == "/down" { throw ConnectionRefused() }
            if r.url.path == "/slow" { try await Task.sleep(nanoseconds: 10_000_000_000) }
        }
        let down = await error { try await client.read(url(base + "/down")) }
        guard case .transport(let t)? = down as? LWSError else {
            Issue.record("expected a transport error, got \(String(describing: down))")
            return
        }
        #expect(t.underlying is ConnectionRefused)
        #expect(!t.isTimeout)
        let slow = await error { try await client.read(url(base + "/slow"), options: ReadOptions(timeout: 0.1)) }
        guard case .transport(let timeout)? = slow as? LWSError else {
            Issue.record("expected a timeout, got \(String(describing: slow))")
            return
        }
        #expect(timeout.isTimeout)
        let reader = client
        let slowURL = url(base + "/slow")
        let task = Task { try await reader.read(slowURL) }
        try await Task.sleep(nanoseconds: 100_000_000)
        task.cancel()
        let cancelled = await error { try await task.value }
        #expect(cancelled is CancellationError)
    }

    @Test func argumentsMustBeAbsoluteHTTPURLs() async throws {
        #expect(kind(await error { try await client.read(URL(string: "/root/")!) }) == "invalidArgument")
        #expect(kind(await error { try await client.head(url("ftp://storage.example/")) }) == "invalidArgument")
        #expect(kind(await error { try await client.listContainer(URL(fileURLWithPath: "/tmp/")).collect() }) == "invalidArgument")
        #expect(server.requests.isEmpty)
    }

    @Test func defaultHeadersUserAgentAndPerCallHeaders() async throws {
        let custom = LWSClient(options: LWSClientOptions(transport: server, userAgent: "custom/1", defaultHeaders: ["X-Default": "d", "X-Both": "default"]))
        server.on("HEAD", root) { _ in Respond.status(200) }
        _ = try await custom.head(url(root), options: RequestOptions(headers: ["X-Both": "call"]))
        let r = try #require(server.requests.first)
        #expect(r.header("User-Agent") == "custom/1")
        #expect(r.header("X-Default") == "d")
        #expect(r.headerValues("X-Both") == ["call"])
        let anonymous = LWSClient(options: LWSClientOptions(transport: server, userAgent: nil))
        _ = try await anonymous.head(url(root))
        #expect(server.requests.last?.header("User-Agent") == nil)
    }

    @Test func redirectsAreFollowedByTheClient() async throws {
        server.on("GET", root + "old") { _ in Respond.status(301, ("Location", "/root/new")) }
        server.on("GET", root + "new") { _ in Respond.text(200, "moved") }
        let r = try await client.read(url(root + "old"))
        #expect(r.text == "moved")
        #expect(r.url.absoluteString == root + "new")

        // 303 turns a QUERY into a GET of the result; 307 keeps a POST and its body; 302 does not redirect a POST.
        server.on("QUERY", base + "/q") { _ in Respond.status(303, ("Location", "/q/result")) }
        server.on("GET", base + "/q/result") { _ in Respond.json(200, #"{"type":"ContainerPage","items":[]}"#, contentType: "application/lws+json") }
        #expect(try await client.searchTypes(url(base + "/q"), query: .empty).items.isEmpty)
        let result = try #require(server.requests("GET", base + "/q/result").first)
        #expect(result.header("Content-Type") == nil)
        #expect(result.body.isEmpty)

        server.on("POST", root + "c1/") { _ in Respond.status(307, ("Location", "/root/c2/")) }
        server.on("POST", root + "c2/") { _ in Respond.status(201, ("Location", "/root/c2/x")) }
        let created = try await client.createText(in: url(root + "c1/"), text: "body")
        #expect(created.location.absoluteString == root + "c2/x")
        #expect(server.requests("POST", root + "c2/").first?.text == "body")

        server.on("POST", root + "c3/") { _ in Respond.status(302, ("Location", "/root/c2/")) }
        let e = await error { try await client.createText(in: url(root + "c3/"), text: "body") }
        #expect(kind(e) == "http")
        #expect((e as? LWSError)?.status == 302)
        #expect(server.requests("POST", root + "c2/").count == 1)
    }

    @Test func redirectLoopsAreBounded() async throws {
        server.on("GET", root + "loop") { _ in Respond.status(302, ("Location", "/root/loop")) }
        #expect(kind(await error { try await client.read(url(root + "loop")) }) == "protocolError")
        #expect(server.requests.count == 11)
    }

    @Test func postIsNeverRetried() async throws {
        server.on("POST", root) { _ in Respond.status(503) }
        #expect(kind(await error { try await client.createText(in: url(root), text: "once") }) == "http")
        server.beforeRespond = { r in if r.method == "POST", r.url.path(percentEncoded: true) == "/root/broken/" { throw ConnectionRefused() } }
        #expect(kind(await error { try await client.createText(in: url(root + "broken/"), text: "once") }) == "transport")
        #expect(server.requests.filter { $0.method == "POST" }.count == 2)
    }

    @Test func requestSendsAnything() async throws {
        server.on("PROPFIND", root) { _ in Respond.text(207, "<multistatus/>", contentType: "application/xml") }
        let r = try await client.request("PROPFIND", url(root), body: Data("<x/>".utf8), contentType: "application/xml")
        #expect(r.status == 207)
        #expect(server.requests.first?.header("Content-Type") == "application/xml")
    }

    @Test func withAuthenticatorSharesTheTransport() async throws {
        let bearer = client.withAuthenticator(BearerTokenAuthenticator(token: "t0k", realm: url(base + "/")))
        server.on("HEAD", root) { _ in Respond.status(200) }
        server.on("HEAD", "https://other.example/") { _ in Respond.status(200) }
        _ = try await bearer.head(url(root))
        _ = try await bearer.head(url("https://other.example/"))
        _ = try await client.head(url(root))
        #expect(server.requests.map { $0.header("Authorization") } == ["Bearer t0k", nil, nil])
    }
}
