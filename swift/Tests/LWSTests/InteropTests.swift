// SPDX-License-Identifier: MIT
import Foundation
import Testing
@testable import LWS

#if canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Darwin)
import Darwin
#endif

private let mockServer = ProcessInfo.processInfo.environment["LWS_TEST_SERVER"]

/// The cross-language interop scenario (`conformance/scenario.md`) against the mock server of `testing/mock-server`.
/// Skipped unless `LWS_TEST_SERVER` is set to its base URL.
@Suite struct InteropTests {
    private static let person = "https://schema.org/Person"

    @Test(.enabled(if: mockServer != nil, "LWS_TEST_SERVER is not set"))
    func scenario() async throws {
        let base = mockServer!.hasSuffix("/") ? String(mockServer!.dropLast()) : mockServer!
        let root = url(base + "/root/")
        let storageID = url(base + "/")

        // 1. Authenticate + discover.
        let credentials = try SelfSignedCredentials.didKey(.generateP256())
        let client = LWSClient(authenticator: TokenExchangeAuthenticator(credentials: credentials))
        let storage = try await client.discoverStorage(root)
        #expect(try storage.storageRoot() == root)
        let notifications = try #require(storage.notificationService)
        let requests = try #require(storage.accessRequestService)
        let grants = try #require(storage.accessGrantService)
        let typeIndex = try #require(storage.typeIndexService)
        let typeSearch = try #require(storage.typeSearchService)

        // 2. Create a container.
        let slug = "interop-swift-\(Int64(Date().timeIntervalSince1970 * 1000))"
        let c = try await client.createContainer(in: root, options: CreateOptions(slug: slug)).location
        #expect(c.absoluteString.hasPrefix(root.absoluteString))

        // 3. Create text.
        let h = try await client.create(in: c, body: Data("Hello, LWS!".utf8), contentType: "text/plain", options: CreateOptions(slug: "hello.txt")).location

        // 4. Read.
        let hello = try await client.read(h)
        #expect(hello.text == "Hello, LWS!")
        let etag = try #require(hello.etag)
        #expect(hello.metadata.isDataResource)
        #expect(hello.metadata.parent == c)
        #expect(hello.metadata.linkset != nil)
        #expect(hello.metadata.storage == storageID)

        // 5. Conditional read.
        #expect(try await client.read(h, options: ReadOptions(ifNoneMatch: etag)).notModified)

        // 6. Update with If-Match; a stale ETag is a precondition failure.
        _ = try await client.update(h, body: Data("Hello again".utf8), contentType: "text/plain", options: UpdateOptions(ifMatch: etag))
        #expect(kind(await error { try await client.update(h, body: Data("stale".utf8), contentType: "text/plain", options: UpdateOptions(ifMatch: etag)) })
            == "preconditionFailed")
        #expect(try await client.read(h).text == "Hello again")

        // 7. Create JSON with an extra type, and patch it.
        let p = try await client.createJSON(in: c, json: ["name": "Alice", "age": 30], options: CreateOptions(slug: "profile.json", types: [Self.person])).location
        _ = try await client.patch(p, patch: JSONPatch().replace("/age", 31).add("/city", "Boston"))
        let profile = try await client.read(p).json()
        #expect(profile["name"] == "Alice")
        #expect(profile["age"] == 31)
        #expect(profile["city"] == "Boston")

        // 8. Linkset.
        let linkset = try await client.readLinkset(p)
        _ = try await client.patchLinkset(linkset.url, patch: JSONPatch().add(JSONPointer.from("linkset", "0", "describedby"),
                                                                              [["href": "https://example.org/shapes/person"]]),
                                          options: UpdateOptions(ifMatch: linkset.etag))
        let after = try await client.readLinkset(p)
        #expect(after.linkset.targets("describedby").contains { $0.href == "https://example.org/shapes/person" })

        // 9. Pagination: 8 members.
        for i in 0..<6 { _ = try await client.createText(in: c, text: "item \(i)", options: CreateOptions(slug: "item-\(i).txt")) }
        let first = try await client.readContainer(c)
        #expect(first.totalItems == 8)
        #expect(first.next != nil)
        let members = try await client.listContainer(c).collect().map(\.id)
        #expect(members.count == 8)
        #expect(members.contains(h))
        #expect(members.contains(p))

        // 10. Type index and search.
        #expect(try await client.listTypes(typeIndex.serviceEndpoint).collect().contains(Self.person))
        #expect(try await client.searchAll(typeSearch.serviceEndpoint, query: TypeQuery().allOf(Self.person)).collect().map(\.id).contains(p))
        #expect(try await client.acceptedQueryFormats(typeSearch.serviceEndpoint).contains(MediaType.lwsQueryJSON))

        // 11. Notifications: a signed delivery to a local inbox, verified.
        let inbox = try Inbox(verifier: WebhookVerifier(options: WebhookVerifierOptions(client: client, trustedStorages: [storageID])))
        defer { inbox.stop() }
        let subscription = try await client.subscribe(notifications, request: WebhookSubscriptionRequest(topics: [c], inbox: inbox.url))
        _ = try await client.update(h, body: Data("Hello, notifications".utf8), contentType: "text/plain")
        let verified = try await inbox.wait(timeout: 5) { v in v.notification.activities.contains { $0.isUpdate && $0.object.id == h } }
        #expect(verified.storage == storageID)
        #expect(try await client.listSubscriptions(notifications.serviceEndpoint).collect().map(\.id).contains(subscription.url))
        try await client.unsubscribe(subscription.url)

        // 12. Access requests and grants.
        let policy = try AccessPolicy(actions: [AccessAction.read], assignee: credentials.agent, target: .storageResources(c),
                                      constraints: [.purpose(url("https://purpose.example/interop"))])
        let request = try await client.requestAccess(requests.serviceEndpoint, request: AccessRequest(storage: storage.id, access: [policy]))
        let gotRequest = try await client.getAccessRequest(request)
        #expect(gotRequest.access[0].assignee == credentials.agent)
        #expect(gotRequest.access[0].target?.values == [c.absoluteString])
        #expect(try await client.listAccessRequests(requests.serviceEndpoint).collect().map(\.id).contains(request))
        let grant = try await client.grantAccess(grants.serviceEndpoint, grant: AccessGrant(storage: storage.id, access: [policy]))
        #expect(try await client.getAccessGrant(grant).access[0].actions == [AccessAction.read])
        try await client.revokeAccessGrant(grant)
        try await client.cancelAccessRequest(request)
        #expect(kind(await error { try await client.getAccessRequest(request) }) == "notFound")

        // 13. Delete.
        #expect(kind(await error { try await client.delete(c) }) == "conflict")
        try await client.delete(c, options: DeleteOptions(recursive: true))
        #expect(kind(await error { try await client.read(h) }) == "notFound")
    }
}

/// A local webhook inbox: a minimal HTTP/1.1 listener on 127.0.0.1 that verifies every delivery with a
/// `WebhookVerifier` and answers 202 (verified) or 400.
final class Inbox: @unchecked Sendable {
    let url: URL
    private let socket: Int32
    private let verifier: WebhookVerifier
    private let lock = NSLock()
    private var verified: [VerifiedNotification] = []
    private var stopped = false

    init(verifier: WebhookVerifier) throws {
        self.verifier = verifier
        #if canImport(Darwin)
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        #else
        let fd = Glibc.socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        #endif
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, length) } }
        guard bound == 0, listen(fd, 16) == 0 else { throw LWSError.invalidArgument("cannot listen on 127.0.0.1") }
        _ = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }
        socket = fd
        url = URL(string: "http://127.0.0.1:\(UInt16(bigEndian: address.sin_port))/inbox")!
        let thread = Thread { [self] in serve() }
        thread.start()
    }

    func stop() {
        lock.withLock { stopped = true }
        shutdown(socket, Int32(SHUT_RDWR))
        close(socket)
    }

    private func serve() {
        while !lock.withLock({ stopped }) {
            let connection = accept(socket, nil, nil)
            if connection < 0 { return }
            handle(connection)
        }
    }

    private func handle(_ connection: Int32) {
        defer { close(connection) }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 65536)
        var headerEnd: Range<Data.Index>?
        while headerEnd == nil {
            let n = recv(connection, &buffer, buffer.count, 0)
            if n <= 0 { return }
            data.append(contentsOf: buffer[0..<n])
            headerEnd = data.range(of: Data("\r\n\r\n".utf8))
        }
        let head = String(decoding: data[..<headerEnd!.lowerBound], as: UTF8.self).components(separatedBy: "\r\n")
        let method = head[0].split(separator: " ").first.map(String.init) ?? "GET"
        var headers = HTTPHeaders()
        for line in head.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            headers.add(String(line[..<colon]), line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces))
        }
        let length = Int(headers.first("content-length") ?? "0") ?? 0
        var body = data[headerEnd!.upperBound...]
        while body.count < length {
            let n = recv(connection, &buffer, buffer.count, 0)
            if n <= 0 { break }
            body.append(contentsOf: buffer[0..<n])
        }
        let semaphore = DispatchSemaphore(value: 0)
        let result = Box()
        let (verifier, inbox, payload) = (self.verifier, self.url, Data(body))
        Task {
            result.value = try? await verifier.verify(method: method, url: inbox, headers: headers, body: payload)
            semaphore.signal()
        }
        semaphore.wait()
        if let v = result.value { lock.withLock { verified.append(v) } }
        let status = result.value == nil ? "400 Bad Request" : "202 Accepted"
        let response = "HTTP/1.1 \(status)\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        _ = response.withCString { send(connection, $0, strlen($0), 0) }
    }

    private final class Box: @unchecked Sendable {
        var value: VerifiedNotification?
    }

    /// The first verified delivery matching `predicate`, waiting at most `timeout` seconds.
    func wait(timeout: TimeInterval, _ predicate: (VerifiedNotification) -> Bool) async throws -> VerifiedNotification {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let found = lock.withLock({ verified.first(where: predicate) }) { return found }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        throw LWSError.invalidArgument("No verified notification arrived in time")
    }
}
