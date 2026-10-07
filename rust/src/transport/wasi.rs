// SPDX-License-Identifier: MIT
//! The transport on WASI: the host's `wasi:http/outgoing-handler` (WASI 0.2).
//!
//! A request blocks the component until the host has the answer. WASI 0.2 exports are
//! synchronous and a component runs one call at a time, so `send`, `bytes` and `chunk` are
//! `async` for the client's sake only: their futures never return `Pending`.
//!
//! The host does TLS, and decides which hosts a component may reach. A timeout becomes the
//! host's connect, first-byte and between-bytes timeouts (reqwest's covers the whole request).

use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, USER_AGENT};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use url::{Position, Url};
use wasip2::http::outgoing_handler;
use wasip2::http::types::{
    ErrorCode, Fields, HeaderError, IncomingBody, IncomingResponse, Method as WasiMethod,
    OutgoingBody, OutgoingRequest, RequestOptions, Scheme, http_error_code,
};
use wasip2::io::error::Error as IoError;
use wasip2::io::streams::{InputStream, StreamError};

use crate::error::TransportError;

/// A request body: its bytes (a request body is never streamed on WASI).
pub(crate) type Body = Bytes;

/// A request body of bytes.
pub(crate) fn body(bytes: Bytes) -> Body {
    bytes
}

/// The most read from a response body at once.
const READ_CHUNK: u64 = 64 * 1024;
/// The most `blocking-write-and-flush` takes at once.
const WRITE_CHUNK: usize = 4096;

/// The HTTP client: the defaults of its requests.
#[derive(Clone, Debug, Default)]
pub(crate) struct HttpClient {
    timeout: Option<Duration>,
    user_agent: Option<HeaderValue>,
}

/// A client with a timeout per request and a `User-Agent`, when given. (`wasi:http` never
/// follows a redirect.)
pub(crate) fn client(
    timeout: Option<Duration>,
    user_agent: Option<&str>,
) -> Result<HttpClient, TransportError> {
    let user_agent = user_agent
        .map(HeaderValue::from_str)
        .transpose()
        .map_err(|_| TransportError::new("invalid User-Agent"))?;
    Ok(HttpClient {
        timeout,
        user_agent,
    })
}

impl HttpClient {
    pub(crate) fn request(&self, method: Method, url: Url) -> RequestBuilder {
        RequestBuilder {
            user_agent: self.user_agent.clone(),
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
            timeout: self.timeout,
            error: None,
        }
    }

    pub(crate) fn get(&self, url: Url) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    pub(crate) fn post(&self, url: Url) -> RequestBuilder {
        self.request(Method::POST, url)
    }
}

/// A request under construction.
pub(crate) struct RequestBuilder {
    user_agent: Option<HeaderValue>,
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Option<Bytes>,
    timeout: Option<Duration>,
    error: Option<TransportError>,
}

impl RequestBuilder {
    pub(crate) fn header(mut self, name: HeaderName, value: &str) -> Self {
        match HeaderValue::from_str(value) {
            Ok(value) => {
                self.headers.append(name, value);
            }
            Err(_) => {
                self.error = Some(TransportError::new(format!("invalid {name} header value")))
            }
        }
        self
    }

    pub(crate) fn headers(mut self, headers: HeaderMap) -> Self {
        for (name, value) in &headers {
            self.headers.append(name.clone(), value.clone());
        }
        self
    }

    pub(crate) fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub(crate) fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub(crate) async fn send(self) -> Result<Response, TransportError> {
        self.send_blocking()
    }

    fn send_blocking(self) -> Result<Response, TransportError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let Self {
            user_agent,
            method,
            url,
            mut headers,
            body,
            timeout,
            ..
        } = self;
        if let Some(user_agent) = user_agent {
            if !headers.contains_key(USER_AGENT) {
                headers.insert(USER_AGENT, user_agent);
            }
        }
        // A body of known length goes with its Content-Length, as with reqwest, rather than
        // chunked.
        if let Some(body) = &body {
            if !headers.contains_key(CONTENT_LENGTH) {
                headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
            }
        }
        let fields = Fields::new();
        for (name, value) in &headers {
            fields
                .append(name.as_str(), value.as_bytes())
                .map_err(|e| header_error(name, &e))?;
        }
        let request = OutgoingRequest::new(fields);
        let refused = |what: &str| TransportError::new(format!("the host refuses the {what}"));
        request
            .set_method(&wasi_method(&method))
            .map_err(|()| refused(&format!("method {method}")))?;
        let scheme = match url.scheme() {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            other => Scheme::Other(other.to_owned()),
        };
        request
            .set_scheme(Some(&scheme))
            .map_err(|()| refused(&format!("scheme of {url}")))?;
        let host = url
            .host_str()
            .ok_or_else(|| TransportError::new(format!("{url} has no host")))?;
        let authority = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        request
            .set_authority(Some(&authority))
            .map_err(|()| refused(&format!("authority of {url}")))?;
        request
            .set_path_with_query(Some(&url[Position::BeforePath..Position::AfterQuery]))
            .map_err(|()| refused(&format!("path of {url}")))?;
        let options = RequestOptions::new();
        if let Some(timeout) = timeout {
            let nanos = u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX);
            // A host may not support a timeout: the request then runs without it.
            let _ = options.set_connect_timeout(Some(nanos));
            let _ = options.set_first_byte_timeout(Some(nanos));
            let _ = options.set_between_bytes_timeout(Some(nanos));
        }
        let outgoing = request
            .body()
            .map_err(|()| TransportError::new("the request body is not available"))?;
        let future =
            outgoing_handler::handle(request, Some(options)).map_err(|e| code_error(&e))?;
        if let Some(body) = &body {
            write_body(&outgoing, body)?;
        }
        OutgoingBody::finish(outgoing, None).map_err(|e| code_error(&e))?;
        future.subscribe().block();
        let incoming = match future.get() {
            Some(Ok(Ok(response))) => response,
            Some(Ok(Err(e))) => return Err(code_error(&e)),
            Some(Err(())) | None => return Err(TransportError::new("the host gave no response")),
        };
        let status = StatusCode::from_u16(incoming.status())
            .map_err(|_| TransportError::new(format!("invalid status {}", incoming.status())))?;
        let mut response_headers = HeaderMap::new();
        for (name, value) in incoming.headers().entries() {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_bytes(&value),
            ) {
                response_headers.append(name, value);
            }
        }
        let body = incoming
            .consume()
            .map_err(|()| TransportError::new("the response body is not available"))?;
        let stream = body
            .stream()
            .map_err(|()| TransportError::new("the response body is not available"))?;
        Ok(Response {
            url,
            status,
            headers: response_headers,
            body: BodyReader {
                stream: Some(stream),
                body: Some(body),
                _response: incoming,
            },
        })
    }
}

/// A response: its status and headers, and its body, read on demand.
pub(crate) struct Response {
    url: Url,
    status: StatusCode,
    headers: HeaderMap,
    body: BodyReader,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("url", &self.url.as_str())
            .field("status", &self.status)
            .field("headers", &self.headers)
            .finish_non_exhaustive()
    }
}

impl Response {
    /// The request's URL (`wasi:http` follows no redirect).
    pub(crate) fn url(&self) -> &Url {
        &self.url
    }

    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The rest of the body.
    pub(crate) async fn bytes(mut self) -> Result<Bytes, TransportError> {
        let mut all = Vec::new();
        while let Some(chunk) = self.body.read()? {
            all.extend_from_slice(&chunk);
        }
        Ok(all.into())
    }

    /// The next part of the body, or `None` at its end.
    pub(crate) async fn chunk(&mut self) -> Result<Option<Bytes>, TransportError> {
        self.body.read()
    }
}

/// A response body being read. The fields drop in order: the stream before its body, the body
/// before its response, as `wasi:http` requires of child resources.
struct BodyReader {
    stream: Option<InputStream>,
    body: Option<IncomingBody>,
    _response: IncomingResponse,
}

impl BodyReader {
    fn read(&mut self) -> Result<Option<Bytes>, TransportError> {
        loop {
            let Some(stream) = &self.stream else {
                return Ok(None);
            };
            match stream.blocking_read(READ_CHUNK) {
                Ok(chunk) if chunk.is_empty() => {}
                Ok(chunk) => return Ok(Some(chunk.into())),
                Err(StreamError::Closed) => {
                    self.stream = None;
                    if let Some(body) = self.body.take() {
                        // The trailers, which nothing reads.
                        drop(IncomingBody::finish(body));
                    }
                    return Ok(None);
                }
                Err(StreamError::LastOperationFailed(e)) => {
                    self.stream = None;
                    self.body = None;
                    return Err(io_error(&e));
                }
            }
        }
    }
}

fn write_body(body: &OutgoingBody, bytes: &[u8]) -> Result<(), TransportError> {
    let stream = body
        .write()
        .map_err(|()| TransportError::new("the request body is not writable"))?;
    for chunk in bytes.chunks(WRITE_CHUNK) {
        stream
            .blocking_write_and_flush(chunk)
            .map_err(|e| match e {
                StreamError::Closed => TransportError::new("the request body closed early"),
                StreamError::LastOperationFailed(e) => io_error(&e),
            })?;
    }
    Ok(())
}

fn wasi_method(method: &Method) -> WasiMethod {
    match method.as_str() {
        "GET" => WasiMethod::Get,
        "HEAD" => WasiMethod::Head,
        "POST" => WasiMethod::Post,
        "PUT" => WasiMethod::Put,
        "DELETE" => WasiMethod::Delete,
        "CONNECT" => WasiMethod::Connect,
        "OPTIONS" => WasiMethod::Options,
        "TRACE" => WasiMethod::Trace,
        "PATCH" => WasiMethod::Patch,
        other => WasiMethod::Other(other.to_owned()),
    }
}

fn header_error(name: &HeaderName, e: &HeaderError) -> TransportError {
    let why = match e {
        HeaderError::InvalidSyntax => "its syntax",
        HeaderError::Forbidden => "it is forbidden",
        HeaderError::Immutable => "the headers are immutable",
    };
    TransportError::new(format!("the host refuses the {name} header: {why}"))
}

fn io_error(e: &IoError) -> TransportError {
    match http_error_code(e) {
        Some(code) => code_error(&code),
        None => TransportError::new(e.to_debug_string()),
    }
}

/// A `wasi:http` error code as a message.
fn code_error(code: &ErrorCode) -> TransportError {
    let message = match code {
        ErrorCode::DnsTimeout => "DNS timeout".to_owned(),
        ErrorCode::DnsError(e) => format!(
            "DNS error{}",
            e.rcode
                .as_deref()
                .map(|r| format!(" ({r})"))
                .unwrap_or_default()
        ),
        ErrorCode::DestinationNotFound => "destination not found".to_owned(),
        ErrorCode::DestinationUnavailable => "destination unavailable".to_owned(),
        ErrorCode::ConnectionRefused => "connection refused".to_owned(),
        ErrorCode::ConnectionTerminated => "connection terminated".to_owned(),
        ErrorCode::ConnectionTimeout => "connection timeout".to_owned(),
        ErrorCode::ConnectionReadTimeout => "read timeout".to_owned(),
        ErrorCode::ConnectionWriteTimeout => "write timeout".to_owned(),
        ErrorCode::TlsProtocolError => "TLS protocol error".to_owned(),
        ErrorCode::TlsCertificateError => "TLS certificate error".to_owned(),
        ErrorCode::TlsAlertReceived(e) => format!(
            "TLS alert{}",
            e.alert_message
                .as_deref()
                .map(|m| format!(": {m}"))
                .unwrap_or_default()
        ),
        ErrorCode::HttpRequestDenied => "the host denied the request".to_owned(),
        ErrorCode::HttpResponseIncomplete => "incomplete response".to_owned(),
        ErrorCode::HttpResponseTimeout => "response timeout".to_owned(),
        ErrorCode::HttpProtocolError => "HTTP protocol error".to_owned(),
        ErrorCode::InternalError(Some(m)) => format!("host error: {m}"),
        other => format!("{other:?}"),
    };
    TransportError::new(message)
}
