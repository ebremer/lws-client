// SPDX-License-Identifier: MIT
import Foundation
@testable import LWS

/// Loads the shared fixtures of `conformance/fixtures` (the repository's language-neutral test vectors).
enum Fixtures {
    static let directory: URL = {
        if let configured = ProcessInfo.processInfo.environment["LWS_CONFORMANCE_DIR"] {
            return URL(fileURLWithPath: configured).appendingPathComponent("fixtures")
        }
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        while dir.path != "/" {
            let candidate = dir.appendingPathComponent("conformance/fixtures")
            if FileManager.default.fileExists(atPath: candidate.path) { return candidate }
            dir = dir.deletingLastPathComponent()
        }
        fatalError("Cannot find conformance/fixtures from \(#filePath)")
    }()

    /// Loads a fixture by its path relative to `conformance/fixtures`.
    static func load(_ relativePath: String) -> JSONValue {
        let data = try! Data(contentsOf: directory.appendingPathComponent(relativePath))
        return try! JSONValue(parsing: data)
    }

    /// The `cases` of a fixture file.
    static func cases(_ file: String, _ member: String = "cases") -> [JSONValue] {
        load(file)[member]!.arrayValue!
    }

    /// The case names of a fixture file, for parameterized tests. (A closure in a `@Test(arguments:)` crashes
    /// the Swift 6.0 compiler, so the tests take the names from here.)
    static func names(_ file: String, _ member: String = "cases") -> [String] {
        cases(file, member).map { $0["name"]!.stringValue! }
    }

    /// The strings of a member of a fixture file.
    static func strings(_ file: String, _ member: String) -> [String] {
        load(file)[member]!.arrayValue!.map { $0.stringValue! }
    }

    static func `case`(_ file: String, _ name: String) -> JSONValue {
        cases(file).first { $0["name"]?.stringValue == name }!
    }
}

extension JSONValue {
    var str: String { stringValue! }
    var strings: [String] { arrayValue!.map(\.str) }
    var array: [JSONValue] { arrayValue! }
    var object: JSONObject { objectValue! }
}

/// A request as the fake server received it.
struct Recorded: Sendable {
    let method: String
    let url: URL
    let headers: HTTPHeaders
    let body: Data

    var text: String { String(decoding: body, as: UTF8.self) }
    func header(_ name: String) -> String? { headers.first(name) }
    func headerValues(_ name: String) -> [String] { headers.all(name) }
}

/// An in-process HTTP test double: routes by method and absolute URL, records every request, and never follows
/// redirects.
final class FakeServer: HTTPTransport, @unchecked Sendable {
    typealias Responder = @Sendable (Recorded) -> HTTPResponse

    private let lock = NSLock()
    private var routes: [(method: String, url: String, respond: Responder)] = []
    private var recorded: [Recorded] = []
    var beforeRespond: (@Sendable (Recorded) async throws -> Void)?

    var requests: [Recorded] { lock.withLock { recorded } }

    /// Adds a route; a later route for the same method and URL wins.
    @discardableResult
    func on(_ method: String, _ url: String, _ respond: @escaping Responder) -> FakeServer {
        lock.withLock { routes.insert((method, URL(string: url)!.absoluteString, respond), at: 0) }
        return self
    }

    /// Answers the given responses in order, then repeats the last.
    @discardableResult
    func onSequence(_ method: String, _ url: String, _ responses: [Responder]) -> FakeServer {
        let counter = Counter()
        return on(method, url) { r in responses[min(counter.next(), responses.count - 1)](r) }
    }

    func requests(_ method: String, _ url: String) -> [Recorded] {
        requests.filter { $0.method == method && $0.url.absoluteString == URL(string: url)!.absoluteString }
    }

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        let r = Recorded(method: request.method, url: request.url, headers: request.headers, body: request.body ?? Data())
        lock.withLock { recorded.append(r) }
        if let beforeRespond { try await beforeRespond(r) }
        let respond = lock.withLock { routes.first { $0.method == r.method && $0.url == r.url.absoluteString }?.respond }
        var response = respond?(r) ?? Respond.status(404)
        response.url = request.url
        return response
    }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    func next() -> Int {
        lock.withLock {
            defer { value += 1 }
            return value
        }
    }
}

/// Response factories for the fake server.
enum Respond {
    static func status(_ status: Int, _ headers: (String, String)...) -> HTTPResponse {
        HTTPResponse(url: URL(string: "about:blank")!, status: status, headers: HTTPHeaders(headers))
    }

    static func json(_ status: Int, _ json: String, contentType: String = "application/json", _ headers: (String, String)...) -> HTTPResponse {
        HTTPResponse(url: URL(string: "about:blank")!, status: status, headers: HTTPHeaders([("Content-Type", contentType)] + headers),
                     body: Data(json.utf8))
    }

    static func text(_ status: Int, _ text: String, contentType: String = "text/plain", _ headers: (String, String)...) -> HTTPResponse {
        HTTPResponse(url: URL(string: "about:blank")!, status: status, headers: HTTPHeaders([("Content-Type", contentType)] + headers),
                     body: Data(text.utf8))
    }
}

/// A settable clock.
final class FakeClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date

    init(_ now: Date) {
        current = now
    }

    var now: Date { lock.withLock { current } }

    func advance(_ seconds: TimeInterval) {
        lock.withLock { current = current.addingTimeInterval(seconds) }
    }

    var function: @Sendable () -> Date { { self.now } }
}

func url(_ s: String) -> URL { URL(string: s)! }

/// The error a throwing call raised, for pattern checks.
func error(of operation: () async throws -> some Any) async -> (any Error)? {
    do {
        _ = try await operation()
        return nil
    } catch {
        return error
    }
}

/// The error a throwing call raised, for pattern checks.
func syncError(of operation: () throws -> some Any) -> (any Error)? {
    do {
        _ = try operation()
        return nil
    } catch {
        return error
    }
}

/// The case name of an `LWSError` (`"notFound"`, `"authentication"`, …), or the type name of another error.
func kind(_ error: (any Error)?) -> String {
    guard let error else { return "none" }
    guard let e = error as? LWSError else { return String(describing: type(of: error)) }
    switch e {
    case .badRequest: return "badRequest"
    case .unauthorized: return "unauthorized"
    case .forbidden: return "forbidden"
    case .notFound: return "notFound"
    case .methodNotAllowed: return "methodNotAllowed"
    case .notAcceptable: return "notAcceptable"
    case .conflict: return "conflict"
    case .gone: return "gone"
    case .preconditionFailed: return "preconditionFailed"
    case .unsupportedMediaType: return "unsupportedMediaType"
    case .unprocessableContent: return "unprocessableContent"
    case .notImplemented: return "notImplemented"
    case .insufficientStorage: return "insufficientStorage"
    case .http: return "http"
    case .authentication: return "authentication"
    case .protocolError: return "protocolError"
    case .signatureVerification: return "signatureVerification"
    case .transport: return "transport"
    case .invalidArgument: return "invalidArgument"
    }
}
