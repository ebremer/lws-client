// SPDX-License-Identifier: MIT
//! Error types.

use std::fmt;

use http::{HeaderMap, Method, StatusCode};
use url::Url;

use crate::headers::{
    AuthChallenge, Link, ParseError, ProblemDetails, parse_link_headers, parse_list,
};

/// `Result` alias with [`Error`] as the default error type.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Details of a non-success HTTP response.
#[derive(Debug, Clone)]
pub struct HttpError {
    /// Response status.
    pub status: StatusCode,
    /// Request method.
    pub method: Method,
    /// Final request URL.
    pub url: Url,
    /// Response headers.
    pub headers: HeaderMap,
    /// Parsed RFC 9457 problem details, when the body carried them.
    pub problem: Option<ProblemDetails>,
    /// Response body text (truncated to 4 KiB).
    pub body: String,
    /// Parsed `WWW-Authenticate` challenges (for 401 responses).
    pub challenges: Vec<AuthChallenge>,
}

impl HttpError {
    fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
    }
    /// Methods from the `Allow` header (useful for 405).
    pub fn allow(&self) -> Vec<String> {
        parse_list(self.header_values("allow"))
    }
    /// Media types from `Accept-Patch` (useful for 415).
    pub fn accept_patch(&self) -> Vec<String> {
        parse_list(self.header_values("accept-patch"))
    }
    /// Media types from `Accept-Query` (useful for 415 from a Type Search Service).
    pub fn accept_query(&self) -> Vec<String> {
        parse_list(self.header_values("accept-query"))
    }
    /// Links from the response (e.g. the storage link on a 401).
    pub fn links(&self) -> Vec<Link> {
        parse_link_headers(self.header_values("link"), &self.url)
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} returned {}", self.method, self.url, self.status)?;
        if let Some(p) = &self.problem {
            if let Some(t) = &p.title {
                write!(f, ": {t}")?;
            }
            if let Some(d) = &p.detail {
                write!(f, " ({d})")?;
            }
        } else if !self.body.is_empty() {
            let snippet: String = self.body.chars().take(200).collect();
            write!(f, ": {}", snippet.trim())?;
        }
        Ok(())
    }
}

/// All errors returned by this crate.
///
/// HTTP failures map to one variant per LWS abstract response (`NotFound`, `Conflict`,
/// `PreconditionFailed`, …), each carrying the full [`HttpError`]; other statuses use
/// [`Error::Http`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// 400 Bad Request.
    #[error("bad request: {0}")]
    BadRequest(Box<HttpError>),
    /// 401 Unauthorized ("unknown requester"), after any authentication handling.
    #[error("unauthorized: {0}")]
    Unauthorized(Box<HttpError>),
    /// 403 Forbidden ("not permitted").
    #[error("forbidden: {0}")]
    Forbidden(Box<HttpError>),
    /// 404 Not Found ("target not found").
    #[error("not found: {0}")]
    NotFound(Box<HttpError>),
    /// 405 Method Not Allowed (see [`HttpError::allow`]).
    #[error("method not allowed: {0}")]
    MethodNotAllowed(Box<HttpError>),
    /// 406 Not Acceptable.
    #[error("not acceptable: {0}")]
    NotAcceptable(Box<HttpError>),
    /// 409 Conflict ("conflict").
    #[error("conflict: {0}")]
    Conflict(Box<HttpError>),
    /// 410 Gone.
    #[error("gone: {0}")]
    Gone(Box<HttpError>),
    /// 412 Precondition Failed (stale `If-Match`).
    #[error("precondition failed: {0}")]
    PreconditionFailed(Box<HttpError>),
    /// 415 Unsupported Media Type (see [`HttpError::accept_patch`], [`HttpError::accept_query`]).
    #[error("unsupported media type: {0}")]
    UnsupportedMediaType(Box<HttpError>),
    /// 422 Unprocessable Content.
    #[error("unprocessable content: {0}")]
    UnprocessableContent(Box<HttpError>),
    /// 501 Not Implemented.
    #[error("not implemented: {0}")]
    NotImplemented(Box<HttpError>),
    /// 507 Insufficient Storage ("quota exceeded").
    #[error("insufficient storage: {0}")]
    InsufficientStorage(Box<HttpError>),
    /// Any other non-success status (5xx: "unknown error").
    #[error("HTTP error: {0}")]
    Http(Box<HttpError>),
    /// Token exchange, realm check or authorization-server metadata failure.
    #[error("authentication failed: {message}")]
    Authentication {
        /// Human-readable description.
        message: String,
        /// OAuth `error` code, when the authorization server returned one.
        error: Option<String>,
        /// OAuth `error_description`, when present.
        error_description: Option<String>,
    },
    /// The server's response violates the LWS protocol (missing `Location`, wrong media type,
    /// malformed JSON, …).
    #[error("protocol error: {0}")]
    Protocol(String),
    /// Webhook signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerification(String),
    /// Invalid input supplied by the caller (bad URL, invalid query, incomplete builder, …).
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// Key or signature handling failure.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// Network / transport failure.
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
}

impl Error {
    /// Maps an HTTP error to the variant for its status.
    pub fn from_http(error: HttpError) -> Self {
        let e = Box::new(error);
        match e.status.as_u16() {
            400 => Error::BadRequest(e),
            401 => Error::Unauthorized(e),
            403 => Error::Forbidden(e),
            404 => Error::NotFound(e),
            405 => Error::MethodNotAllowed(e),
            406 => Error::NotAcceptable(e),
            409 => Error::Conflict(e),
            410 => Error::Gone(e),
            412 => Error::PreconditionFailed(e),
            415 => Error::UnsupportedMediaType(e),
            422 => Error::UnprocessableContent(e),
            501 => Error::NotImplemented(e),
            507 => Error::InsufficientStorage(e),
            _ => Error::Http(e),
        }
    }

    pub(crate) fn authentication(message: impl Into<String>) -> Self {
        Error::Authentication {
            message: message.into(),
            error: None,
            error_description: None,
        }
    }

    /// The HTTP error details, for HTTP status variants.
    pub fn http_error(&self) -> Option<&HttpError> {
        match self {
            Error::BadRequest(e)
            | Error::Unauthorized(e)
            | Error::Forbidden(e)
            | Error::NotFound(e)
            | Error::MethodNotAllowed(e)
            | Error::NotAcceptable(e)
            | Error::Conflict(e)
            | Error::Gone(e)
            | Error::PreconditionFailed(e)
            | Error::UnsupportedMediaType(e)
            | Error::UnprocessableContent(e)
            | Error::NotImplemented(e)
            | Error::InsufficientStorage(e)
            | Error::Http(e) => Some(e),
            _ => None,
        }
    }

    /// The HTTP status, for HTTP status variants (and transport errors that carry one).
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Error::Transport(e) => e.status(),
            _ => self.http_error().map(|e| e.status),
        }
    }

    /// The RFC 9457 problem details, when the error response carried them.
    pub fn problem(&self) -> Option<&ProblemDetails> {
        self.http_error().and_then(|e| e.problem.as_ref())
    }

    /// `true` for 404 Not Found.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Error::NotFound(_))
    }
    /// `true` for 410 Gone.
    pub fn is_gone(&self) -> bool {
        matches!(self, Error::Gone(_))
    }
    /// `true` for 409 Conflict.
    pub fn is_conflict(&self) -> bool {
        matches!(self, Error::Conflict(_))
    }
    /// `true` for 412 Precondition Failed.
    pub fn is_precondition_failed(&self) -> bool {
        matches!(self, Error::PreconditionFailed(_))
    }
    /// `true` for 401 Unauthorized.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Error::Unauthorized(_))
    }
    /// `true` for 403 Forbidden.
    pub fn is_forbidden(&self) -> bool {
        matches!(self, Error::Forbidden(_))
    }
    /// `true` for authentication failures.
    pub fn is_authentication(&self) -> bool {
        matches!(self, Error::Authentication { .. })
    }
    /// `true` for protocol violations.
    pub fn is_protocol(&self) -> bool {
        matches!(self, Error::Protocol(_))
    }
    /// `true` for webhook signature verification failures.
    pub fn is_signature_verification(&self) -> bool {
        matches!(self, Error::SignatureVerification(_))
    }
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        Error::Protocol(e.0)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Protocol(format!("invalid JSON: {e}"))
    }
}

/// Lets callers use `Url::parse(..)?` in functions returning [`Result`]; a malformed URL is
/// caller input, so it maps to [`Error::InvalidInput`].
impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Self {
        Error::InvalidInput(format!("invalid URL: {e}"))
    }
}
