// SPDX-License-Identifier: MIT
//! Errors: the adapter's own, and the library's mapped to the protocol's error kinds
//! (driver/PROTOCOL.md section 3.2).

use std::any::Any;
use std::error::Error as _;

use lws_client::Error;
use lws_client::headers::ProblemDetails;
use serde_json::{Map, Value, json};

/// Why an operation did not produce a result.
#[derive(Debug)]
pub(crate) enum Failure {
    /// An error of the adapter's own: `InvalidArguments`, `Unsupported` or `InternalError`.
    Adapter { kind: &'static str, message: String },
    /// An error the library raised.
    Library(Error),
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

    /// A panic while running an operation: a bug in the adapter or the library.
    pub(crate) fn panic(payload: &(dyn Any + Send)) -> Self {
        let what = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".to_owned());
        Failure::Adapter {
            kind: "InternalError",
            message: format!("panic: {what}"),
        }
    }
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        Failure::Library(e)
    }
}

/// The `error` member of a failed response.
pub(crate) fn error_result(failure: &Failure) -> Value {
    match failure {
        Failure::Adapter { kind, message } => json!({"kind": kind, "message": message}),
        Failure::Library(e) => library_error(e),
    }
}

/// The protocol kind of an HTTP status variant.
fn http_kind(e: &Error) -> &'static str {
    match e {
        Error::BadRequest(_) => "BadRequestError",
        Error::Unauthorized(_) => "UnauthorizedError",
        Error::Forbidden(_) => "ForbiddenError",
        Error::NotFound(_) => "NotFoundError",
        Error::MethodNotAllowed(_) => "MethodNotAllowedError",
        Error::NotAcceptable(_) => "NotAcceptableError",
        Error::Conflict(_) => "ConflictError",
        Error::Gone(_) => "GoneError",
        Error::PreconditionFailed(_) => "PreconditionFailedError",
        Error::UnsupportedMediaType(_) => "UnsupportedMediaTypeError",
        Error::UnprocessableContent(_) => "UnprocessableContentError",
        Error::NotImplemented(_) => "NotImplementedError",
        Error::InsufficientStorage(_) => "InsufficientStorageError",
        _ => "HttpError",
    }
}

fn problem_json(p: &ProblemDetails) -> Value {
    let mut o = Map::new();
    let mut put = |name: &str, value: Option<Value>| {
        if let Some(v) = value {
            o.insert(name.to_owned(), v);
        }
    };
    put("type", p.problem_type.clone().map(Value::String));
    put("title", p.title.clone().map(Value::String));
    put("status", p.status.map(Value::from));
    put("detail", p.detail.clone().map(Value::String));
    put("instance", p.instance.clone().map(Value::String));
    for (k, v) in &p.extensions {
        o.insert(k.clone(), v.clone());
    }
    Value::Object(o)
}

/// An error's message with the chain of its causes (reqwest's own message is terse:
/// "error sending request for url (…)").
fn message_with_causes(e: &Error) -> String {
    let mut message = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        let text = c.to_string();
        if !message.contains(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
        cause = c.source();
    }
    message
}

fn library_error(e: &Error) -> Value {
    if let Some(h) = e.http_error() {
        let mut o = Map::new();
        o.insert("kind".into(), http_kind(e).into());
        o.insert("status".into(), h.status.as_u16().into());
        o.insert("message".into(), e.to_string().into());
        if let Some(p) = &h.problem {
            o.insert("problem".into(), problem_json(p));
        }
        if matches!(e, Error::MethodNotAllowed(_)) {
            o.insert("allow".into(), h.allow().into());
        }
        if matches!(e, Error::UnsupportedMediaType(_)) {
            o.insert("acceptPatch".into(), h.accept_patch().into());
        }
        return Value::Object(o);
    }
    let kind = match e {
        Error::Authentication {
            error,
            error_description,
            ..
        } => {
            let mut o = Map::new();
            o.insert("kind".into(), "AuthenticationError".into());
            o.insert("message".into(), e.to_string().into());
            if let Some(code) = error {
                o.insert("oauthError".into(), code.clone().into());
            }
            if let Some(description) = error_description {
                o.insert("oauthErrorDescription".into(), description.clone().into());
            }
            return Value::Object(o);
        }
        Error::Protocol(_) => "ProtocolError",
        Error::SignatureVerification(_) => "SignatureVerificationError",
        Error::InvalidInput(_) => "InvalidArguments",
        Error::Transport(_) => "TransportError",
        // Key handling failures outside of `configure`'s key import (which reports them as
        // InvalidArguments) are failures of the library's own: random numbers, signing.
        Error::Crypto(_) => "InternalError",
        _ => "InternalError",
    };
    json!({"kind": kind, "message": message_with_causes(e)})
}
