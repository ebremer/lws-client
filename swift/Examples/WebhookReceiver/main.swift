// SPDX-License-Identifier: MIT
// Receives and verifies webhook notifications (RFC 9421 signatures) for changes in a storage root.
//
//   swift run WebhookReceiver http://localhost:8787/root/ 9090
//
// Any HTTP server can host the inbox (Vapor, Hummingbird, SwiftNIO, …): hand the verifier the method, the inbox URL
// as registered, the headers and the body bytes. To need no dependency, this example accepts the deliveries with a
// few lines of sockets.
import Foundation
import LWS

#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

let start = URL(string: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "http://localhost:8787/root/")!
let port = CommandLine.arguments.count > 2 ? UInt16(CommandLine.arguments[2])! : 9090

let client = LWSClient(authenticator: TokenExchangeAuthenticator(credentials: try SelfSignedCredentials.didKey(.generateP256())))
let storage = try await client.discoverStorage(start)
guard let notifications = storage.notificationService else { fatalError("The storage has no notification service") }

// The verifier fetches the storage description to find the signing key the keyid names.
let verifier = WebhookVerifier(options: WebhookVerifierOptions(client: client, trustedStorages: [storage.id]))

let inbox = URL(string: "http://127.0.0.1:\(port)/inbox")!
let listener = try Listener(port: port)
let subscription = try await client.subscribe(notifications, request: WebhookSubscriptionRequest(topics: [try storage.storageRoot()], inbox: inbox))
print("Subscribed: \(subscription.url); change something in \(try storage.storageRoot()) (Ctrl+C to stop)")

while let delivery = listener.next() {
    do {
        // The URL to verify against is the inbox as registered, not necessarily the one the request arrived at.
        let v = try await verifier.verify(method: delivery.method, url: inbox, headers: delivery.headers, body: delivery.body)
        for a in v.notification.activities { print("\(a.types.joined(separator: ",")) \(a.object.id) (signed by \(v.keyID))") }
        delivery.respond(204)
    } catch {
        FileHandle.standardError.write(Data("Rejected delivery: \(error)\n".utf8))
        delivery.respond(401)
    }
}

/// A minimal HTTP/1.1 listener on 127.0.0.1: one request per connection, bodies by Content-Length.
final class Listener {
    struct Delivery {
        let method: String
        let headers: HTTPHeaders
        let body: Data
        let connection: Int32

        func respond(_ status: Int) {
            let line = "HTTP/1.1 \(status) \(status == 204 ? "No Content" : "Unauthorized")\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            _ = line.withCString { send(connection, $0, strlen($0), 0) }
            close(connection)
        }
    }

    private let socket: Int32

    init(port: UInt16) throws {
        #if canImport(Darwin)
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        #else
        let fd = Glibc.socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        #endif
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0, listen(fd, 16) == 0 else { throw LWSError.invalidArgument("cannot listen on 127.0.0.1:\(port)") }
        socket = fd
    }

    /// The next request (blocking), or nil when the socket closed.
    func next() -> Delivery? {
        while true {
            let connection = accept(socket, nil, nil)
            if connection < 0 { return nil }
            var data = Data()
            var buffer = [UInt8](repeating: 0, count: 65536)
            var headerEnd: Range<Data.Index>?
            while headerEnd == nil {
                let n = recv(connection, &buffer, buffer.count, 0)
                if n <= 0 { break }
                data.append(contentsOf: buffer[0..<n])
                headerEnd = data.range(of: Data("\r\n\r\n".utf8))
            }
            guard let end = headerEnd else {
                close(connection)
                continue
            }
            let lines = String(decoding: data[..<end.lowerBound], as: UTF8.self).components(separatedBy: "\r\n")
            var headers = HTTPHeaders()
            for line in lines.dropFirst() {
                guard let colon = line.firstIndex(of: ":") else { continue }
                headers.add(String(line[..<colon]), line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces))
            }
            var body = data[end.upperBound...]
            let length = Int(headers.first("content-length") ?? "0") ?? 0
            while body.count < length {
                let n = recv(connection, &buffer, buffer.count, 0)
                if n <= 0 { break }
                body.append(contentsOf: buffer[0..<n])
            }
            let method = lines[0].split(separator: " ").first.map(String.init) ?? "POST"
            return Delivery(method: method, headers: headers, body: Data(body), connection: connection)
        }
    }
}
