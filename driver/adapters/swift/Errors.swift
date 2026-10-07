// SPDX-License-Identifier: MIT
import Foundation
import LWS

/// Maps what an operation threw to the protocol's `error` object (PROTOCOL.md section 3.2).
enum Errors {
    static let invalidArguments = "InvalidArguments"
    static let unsupported = "Unsupported"
    static let internalError = "InternalError"
    static let transport = "TransportError"

    /// The error object for `error`.
    static func of(_ error: any Error) -> JSONValue {
        if let a = error as? AdapterError { return make(a.kind, a.message) }
        guard let e = error as? LWSError else { return internalError(error) }
        if let h = e.httpError {
            var o = object(kind(e), e.description)
            o["status"] = .int(Int64(h.status))
            // RFC 9457 members are flat: the document as received.
            if let problem = h.problem { o["problem"] = .object(problem.raw) }
            if case .methodNotAllowed = e { o["allow"] = Results.strings(h.allow) }
            if case .unsupportedMediaType = e { o["acceptPatch"] = Results.strings(h.acceptPatch) }
            return .object(o)
        }
        switch e {
        case .authentication(let a):
            var o = object("AuthenticationError", e.description)
            if let status = a.status { o["status"] = .int(Int64(status)) }
            Results.put(&o, "oauthError", a.error)
            Results.put(&o, "oauthErrorDescription", a.errorDescription)
            return .object(o)
        case .transport(let t):
            var message = t.message
            if let cause = t.underlying, !message.contains(String(describing: cause)) { message += " (\(cause))" }
            return make(transport, message)
        case .protocolError(let m):
            return make("ProtocolError", m)
        case .signatureVerification(let m):
            return make("SignatureVerificationError", m)
        case .invalidArgument(let m):
            // The library's builders and parsers of caller input reject malformed values with this.
            return make(invalidArguments, m)
        default:
            return internalError(error)
        }
    }

    /// The protocol kind of an HTTP error.
    private static func kind(_ e: LWSError) -> String {
        switch e {
        case .badRequest: return "BadRequestError"
        case .unauthorized: return "UnauthorizedError"
        case .forbidden: return "ForbiddenError"
        case .notFound: return "NotFoundError"
        case .methodNotAllowed: return "MethodNotAllowedError"
        case .notAcceptable: return "NotAcceptableError"
        case .conflict: return "ConflictError"
        case .gone: return "GoneError"
        case .preconditionFailed: return "PreconditionFailedError"
        case .unsupportedMediaType: return "UnsupportedMediaTypeError"
        case .unprocessableContent: return "UnprocessableContentError"
        case .notImplemented: return "NotImplementedError"
        case .insufficientStorage: return "InsufficientStorageError"
        default: return "HttpError"
        }
    }

    /// An `InternalError`: a bug in the adapter or the library. The description goes to the log too.
    static func internalError(_ error: any Error) -> JSONValue {
        let text = "\(type(of: error)): \(error)"
        FileHandle.standardError.write(Data((text + "\n").utf8))
        return make(internalError, text)
    }

    static func make(_ kind: String, _ message: String) -> JSONValue {
        .object(object(kind, message))
    }

    private static func object(_ kind: String, _ message: String) -> JSONObject {
        ["kind": .string(kind), "message": .string(message)]
    }
}
