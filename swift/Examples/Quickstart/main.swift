// SPDX-License-Identifier: MIT
// Discover a storage, then create, read, update, patch, list and delete resources.
//
//   swift run Quickstart http://localhost:8787/root/
import Foundation
import LWS

let start = URL(string: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "http://localhost:8787/root/")!

// A did:key agent signs its own credential; the client exchanges it for access tokens on demand.
let me = try SelfSignedCredentials.didKey(.generateP256())
let client = LWSClient(authenticator: TokenExchangeAuthenticator(credentials: me))
print("Agent: \(me.agent)")

let storage = try await client.discoverStorage(start)
let root = try storage.storageRoot()
print("Storage \(storage.id), root \(root)")

let folder = try await client.createContainer(in: root, options: CreateOptions(slug: "quickstart"))
let note = try await client.createText(in: folder.location, text: "Hello, LWS!", options: CreateOptions(slug: "hello.txt"))
print("Created \(note.location)")

let r = try await client.read(note.location)
print("Read: \(r.text) (ETag \(r.etag ?? "none"))")

// Optimistic concurrency: only replace it if nobody changed it since we read it.
_ = try await client.update(note.location, body: Data("Hello again".utf8), contentType: "text/plain", options: UpdateOptions(ifMatch: r.etag))
do {
    _ = try await client.update(note.location, body: Data("lost update".utf8), contentType: "text/plain", options: UpdateOptions(ifMatch: r.etag))
} catch LWSError.preconditionFailed(let e) {
    print("Stale update rejected with HTTP \(e.status)")
}

let profile = try await client.createJSON(in: folder.location, json: ["name": "Alice", "age": 30], options: CreateOptions(slug: "profile.json")).location
_ = try await client.patch(profile, patch: JSONPatch().replace("/age", 31).add("/city", "Boston"))
print("Patched: \(try await client.read(profile).text)")

print("Members of \(folder.location):")
for try await item in client.listContainer(folder.location) {  // follows rel="next" pages lazily
    print("  \(item.id) \(item.format ?? "")")
}

try await client.delete(folder.location, options: DeleteOptions(recursive: true))  // Depth: infinity
print("Deleted \(folder.location)")
