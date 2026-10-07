// SPDX-License-Identifier: MIT
// The Swift adapter of the lws-client driver: runs the operations of driver/PROTOCOL.md (lws-driver/1) with
// lws-client for Swift. It reads one JSON request per line on stdin and writes one JSON response per line on stdout;
// everything else (logs, diagnostics) goes to stderr.
import Foundation
import LWS

/// Writes one protocol line to stdout, unbuffered.
func write(_ message: JSONValue) {
    FileHandle.standardOutput.write(Data((message.serialized() + "\n").utf8))
}

func failure(_ id: JSONValue, _ error: JSONValue) -> JSONValue {
    ["id": id, "ok": false, "error": error]
}

let adapter = Adapter()

write(["hello": [
    "protocol": .string(Adapter.protocol),
    "language": .string(Adapter.language),
    "library": .string(Adapter.library),
    "operations": .array(adapter.operations.map { .string($0.name) }),
]])

while let line = readLine(strippingNewline: true) {
    if line.trimmingCharacters(in: .whitespaces).isEmpty { continue }
    guard let request = try? JSONValue(parsing: line) else {
        write(failure(.null, Errors.make(Errors.invalidArguments, "the request is not JSON")))
        continue
    }
    guard let message = request.objectValue else {
        write(failure(.null, Errors.make(Errors.invalidArguments, "the request is not a JSON object")))
        continue
    }
    let id = message["id"] ?? .null
    guard let op = message["op"]?.stringValue, let operation = adapter.operation(op) else {
        write(failure(id, Errors.make(Errors.unsupported, "unknown operation '\(message["op"]?.stringValue ?? "")'")))
        continue
    }
    let response: JSONValue
    do {
        let args = message["args"]
        if let args, !args.isNull, args.objectValue == nil { throw AdapterError.invalid("args must be an object") }
        let result = try await operation(args?.objectValue ?? [:])
        response = ["id": id, "ok": true, "result": result]
    } catch {
        response = failure(id, Errors.of(error))
    }
    write(response)
    if op == "shutdown" { break }
}
exit(0)
