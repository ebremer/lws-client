// SPDX-License-Identifier: MIT
//! Errors: the adapter's own, the component's mapped to the protocol's error kinds
//! (driver/PROTOCOL.md section 3.2), and traps.

use std::any::Any;

use serde_json::{Map, Value, json};

use crate::lws::{Error, ErrorKind};

/// Why an operation did not produce a result.
#[derive(Debug)]
pub(crate) enum Failure {
    /// An error of the adapter's own: `InvalidArguments`, `Unsupported` or `InternalError`.
    Adapter { kind: &'static str, message: String },
    /// An error the component returned: the library's.
    Component(Box<Error>),
    /// The component trapped (a panic in it, or a failure of the runtime). The instance is gone:
    /// the adapter starts a fresh one.
    Trap(String),
}

impl Failure {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Failure::Adapter {
            kind: "InvalidArguments",
            message: message.into(),
        }
    }

    pub(crate) fn unsupported(message: impl Into<String>) -> Self {
        Failure::Adapter {
            kind: "Unsupported",
            message: message.into(),
        }
    }

    /// A panic in the adapter itself.
    pub(crate) fn panic(payload: &(dyn Any + Send)) -> Self {
        let what = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".to_owned());
        Failure::Trap(format!("panic: {what}"))
    }

    pub(crate) fn trap(e: &wasmtime::Error) -> Self {
        Failure::Trap(format!("the component trapped: {e:?}"))
    }
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        Failure::Component(Box::new(e))
    }
}

/// The `error` member of a failed response.
pub(crate) fn error_result(failure: &Failure) -> Value {
    match failure {
        Failure::Adapter { kind, message } => json!({"kind": kind, "message": message}),
        Failure::Trap(message) => json!({"kind": "InternalError", "message": message}),
        Failure::Component(e) => component_error(e),
    }
}

/// The protocol kind of a component error kind.
fn kind(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::BadRequest => "BadRequestError",
        ErrorKind::Unauthorized => "UnauthorizedError",
        ErrorKind::Forbidden => "ForbiddenError",
        ErrorKind::NotFound => "NotFoundError",
        ErrorKind::MethodNotAllowed => "MethodNotAllowedError",
        ErrorKind::NotAcceptable => "NotAcceptableError",
        ErrorKind::Conflict => "ConflictError",
        ErrorKind::Gone => "GoneError",
        ErrorKind::PreconditionFailed => "PreconditionFailedError",
        ErrorKind::UnsupportedMediaType => "UnsupportedMediaTypeError",
        ErrorKind::UnprocessableContent => "UnprocessableContentError",
        ErrorKind::NotImplemented => "NotImplementedError",
        ErrorKind::InsufficientStorage => "InsufficientStorageError",
        ErrorKind::Http => "HttpError",
        ErrorKind::Authentication => "AuthenticationError",
        ErrorKind::Protocol => "ProtocolError",
        ErrorKind::SignatureVerification => "SignatureVerificationError",
        ErrorKind::InvalidInput => "InvalidArguments",
        ErrorKind::Transport => "TransportError",
        // Key handling failures outside of `configure`'s key import (which the component reports
        // as invalid-input) are failures of the library's own: random numbers, signing.
        ErrorKind::Crypto | ErrorKind::Internal => "InternalError",
    }
}

fn component_error(e: &Error) -> Value {
    let mut o = Map::new();
    o.insert("kind".into(), kind(e.kind).into());
    if let Some(h) = &e.http {
        o.insert("status".into(), h.status.into());
    }
    o.insert("message".into(), e.message.clone().into());
    if let Some(h) = &e.http {
        if let Some(problem) = h
            .problem
            .as_deref()
            .and_then(|p| serde_json::from_str(p).ok())
        {
            o.insert("problem".into(), problem);
        }
        if e.kind == ErrorKind::MethodNotAllowed {
            o.insert("allow".into(), h.allow.clone().into());
        }
        if e.kind == ErrorKind::UnsupportedMediaType {
            o.insert("acceptPatch".into(), h.accept_patch.clone().into());
        }
    }
    if e.kind == ErrorKind::Authentication {
        if let Some(code) = &e.oauth_error {
            o.insert("oauthError".into(), code.clone().into());
        }
        if let Some(description) = &e.oauth_error_description {
            o.insert("oauthErrorDescription".into(), description.clone().into());
        }
    }
    Value::Object(o)
}
