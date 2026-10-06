// SPDX-License-Identifier: MIT
//! The LWS client.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::future::{Future, IntoFuture};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use futures_util::Stream;
use futures_util::stream;
use http::header::{
    ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, IF_MATCH, IF_MODIFIED_SINCE,
    IF_NONE_MATCH, LINK, LOCATION, RANGE, USER_AGENT,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use serde::Serialize;
use serde_json::Value;
use url::Url;

use crate::access::{AccessGrant, AccessRequest};
use crate::auth::{Authenticator, BoxFuture, RequestParts, ResponseParts};
use crate::constants::{self, media_type, prefer, rel, service, types as lws_types};
use crate::error::{Error, HttpError, Result};
use crate::headers::{Link, ProblemDetails, encode_slug, parse_list, parse_www_authenticate};
use crate::index::{SearchPage, TypeIndexPage, TypeQuery};
use crate::model::{
    ContainedResource, ContainerPage, CreateResult, Linkset, LinksetDocument, Resource,
    ResourceMetadata, StorageDescription, StreamingResource, UpdateResult,
};
use crate::notification::{Subscription, WebhookSubscriptionRequest};
use crate::patch::JsonPatch;

/// A boxed stream of results, as returned by the lazy listing operations
/// ([`Client::list_container`], [`Client::list_types`], [`Client::search_all`], …).
///
/// Consume it with [`futures_util::TryStreamExt`] (`try_next`, `try_collect`, …).
pub type LwsStream<T> = Pin<Box<dyn Stream<Item = Result<T>> + Send + 'static>>;

const ACCEPT_JSON_LD: &str =
    "application/lws+json, application/ld+json;q=0.9, application/json;q=0.8";
const ACCEPT_CID: &str = "application/lws+cid, application/ld+json;q=0.9, application/json;q=0.8";
const QUERY: &str = "QUERY";
/// Maximum number of redirects followed for one request.
const MAX_REDIRECTS: usize = 5;

/// Conversion into a [`Url`] (implemented for `Url`, `&Url`, `&str`, `String`, `&String`).
pub trait IntoUrl {
    /// Converts into a URL.
    fn into_url(self) -> Result<Url>;
}

impl IntoUrl for Url {
    fn into_url(self) -> Result<Url> {
        Ok(self)
    }
}
impl IntoUrl for &Url {
    fn into_url(self) -> Result<Url> {
        Ok(self.clone())
    }
}
impl IntoUrl for &str {
    fn into_url(self) -> Result<Url> {
        Url::parse(self).map_err(|e| Error::InvalidInput(format!("invalid URL {self:?}: {e}")))
    }
}
impl IntoUrl for String {
    fn into_url(self) -> Result<Url> {
        self.as_str().into_url()
    }
}
impl IntoUrl for &String {
    fn into_url(self) -> Result<Url> {
        self.as_str().into_url()
    }
}

/// A request body. Byte and string bodies are replayable (needed for the authentication
/// retry); [`Body::from_reqwest`] wraps a streaming body.
pub struct Body(BodyKind);

enum BodyKind {
    Bytes(Bytes),
    Stream(reqwest::Body),
}

impl Body {
    /// An empty body.
    pub fn empty() -> Self {
        Body(BodyKind::Bytes(Bytes::new()))
    }
    /// Wraps a (possibly streaming, non-replayable) `reqwest` body.
    pub fn from_reqwest(body: reqwest::Body) -> Self {
        match body.as_bytes() {
            Some(b) => Body(BodyKind::Bytes(Bytes::copy_from_slice(b))),
            None => Body(BodyKind::Stream(body)),
        }
    }
    fn replayable(&self) -> bool {
        matches!(self.0, BodyKind::Bytes(_))
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            BodyKind::Bytes(b) => write!(f, "Body({} bytes)", b.len()),
            BodyKind::Stream(_) => f.write_str("Body(stream)"),
        }
    }
}

impl From<Bytes> for Body {
    fn from(b: Bytes) -> Self {
        Body(BodyKind::Bytes(b))
    }
}
impl From<Vec<u8>> for Body {
    fn from(b: Vec<u8>) -> Self {
        Body(BodyKind::Bytes(b.into()))
    }
}
impl From<String> for Body {
    fn from(s: String) -> Self {
        Body(BodyKind::Bytes(s.into()))
    }
}
impl From<&str> for Body {
    fn from(s: &str) -> Self {
        Body(BodyKind::Bytes(Bytes::copy_from_slice(s.as_bytes())))
    }
}
impl From<&[u8]> for Body {
    fn from(s: &[u8]) -> Self {
        Body(BodyKind::Bytes(Bytes::copy_from_slice(s)))
    }
}

struct Inner {
    http: reqwest::Client,
    authenticator: Option<Arc<dyn Authenticator>>,
    default_headers: HeaderMap,
    timeout: Option<Duration>,
    follow_redirects: bool,
}

/// An LWS client. Cheap to clone and safe to share between tasks.
///
/// ```no_run
/// use futures_util::TryStreamExt;
/// use lws_client::Client;
///
/// # async fn run() -> lws_client::Result<()> {
/// let client = Client::new();
/// let storage = client.discover_storage("https://storage.example/alice/notes/").await?;
/// let root = storage.storage_root()?.clone();
///
/// let created = client.create(&root, "milk\neggs\n", "text/plain").slug("shopping.txt").await?;
/// let doc = client.read(&created.location).await?;
/// println!("{} (etag {:?})", doc.text()?, doc.metadata.etag);
///
/// let items: Vec<_> = client.list_container(&root).try_collect().await?;
/// client.delete(&created.location).if_match(doc.metadata.etag.unwrap_or_default()).await?;
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("authenticated", &self.inner.authenticator.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for [`Client`].
#[derive(Default)]
pub struct ClientBuilder {
    http: Option<reqwest::Client>,
    authenticator: Option<Arc<dyn Authenticator>>,
    user_agent: Option<String>,
    default_headers: HeaderMap,
    timeout: Option<Duration>,
    error: Option<Error>,
}

impl ClientBuilder {
    /// Uses a preconfigured `reqwest` client (proxies, TLS roots, connection pools, …).
    ///
    /// The built-in client disables `reqwest`'s automatic redirects and follows redirects
    /// itself, re-running the [`Authenticator`] for every hop so that a token is only ever
    /// sent to URLs inside its realm. With your own client, **its** redirect policy applies
    /// instead (note that `reqwest`'s default policy strips `Authorization` only when the host
    /// or port changes); build it with `reqwest::redirect::Policy::none()` to disable
    /// redirects entirely.
    #[must_use]
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http = Some(client);
        self
    }
    /// Sets the authenticator.
    #[must_use]
    pub fn authenticator(mut self, authenticator: impl Authenticator + 'static) -> Self {
        self.authenticator = Some(Arc::new(authenticator));
        self
    }
    /// Sets a shared authenticator.
    #[must_use]
    pub fn authenticator_arc(mut self, authenticator: Arc<dyn Authenticator>) -> Self {
        self.authenticator = Some(authenticator);
        self
    }
    /// Sets the `User-Agent` (default `lws-client-rust/<version>`).
    #[must_use]
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }
    /// Adds a header sent with every request.
    #[must_use]
    pub fn default_header(mut self, name: &str, value: &str) -> Self {
        match (HeaderName::try_from(name), HeaderValue::try_from(value)) {
            (Ok(n), Ok(v)) => {
                self.default_headers.append(n, v);
            }
            _ => {
                self.error = Some(Error::InvalidInput(format!(
                    "invalid header {name}: {value}"
                )))
            }
        }
        self
    }
    /// Per-request timeout (default 30 s when this builder creates the HTTP client).
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
    /// Builds the client.
    pub fn build(self) -> Result<Client> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let user_agent = self
            .user_agent
            .unwrap_or_else(|| constants::USER_AGENT.to_owned());
        let mut default_headers = self.default_headers;
        default_headers.insert(
            USER_AGENT,
            HeaderValue::try_from(user_agent)
                .map_err(|_| Error::InvalidInput("invalid user agent".into()))?,
        );
        let follow_redirects = self.http.is_none();
        let (http, timeout) = match self.http {
            Some(h) => (h, self.timeout),
            None => (
                reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?,
                Some(self.timeout.unwrap_or(Duration::from_secs(30))),
            ),
        };
        Ok(Client {
            inner: Arc::new(Inner {
                http,
                authenticator: self.authenticator,
                default_headers,
                timeout,
                follow_redirects,
            }),
        })
    }
}

/// A prepared request.
struct Prepared {
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Option<Body>,
}

impl Prepared {
    fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
        }
    }
    fn header(mut self, name: HeaderName, value: &str) -> Result<Self> {
        let v = HeaderValue::from_str(value)
            .map_err(|_| Error::InvalidInput(format!("invalid {name} header value")))?;
        self.headers.append(name, v);
        Ok(self)
    }
}

/// Common per-request options shared by the request builders.
struct Options {
    url: Result<Url>,
    headers: HeaderMap,
    error: Option<Error>,
}

impl Options {
    fn new(url: impl IntoUrl) -> Self {
        Self {
            url: url.into_url(),
            headers: HeaderMap::new(),
            error: None,
        }
    }
    fn set(&mut self, name: HeaderName, value: &str) {
        match HeaderValue::from_str(value) {
            Ok(v) => {
                self.headers.insert(name, v);
            }
            Err(_) => {
                self.error = Some(Error::InvalidInput(format!("invalid {name} header value")))
            }
        }
    }
    fn append(&mut self, name: &str, value: &str) {
        match (HeaderName::try_from(name), HeaderValue::from_str(value)) {
            (Ok(n), Ok(v)) => {
                self.headers.append(n, v);
            }
            _ => self.error = Some(Error::InvalidInput(format!("invalid header {name}"))),
        }
    }
    fn into_prepared(self, method: Method) -> Result<Prepared> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let mut p = Prepared::new(method, self.url?);
        p.headers = self.headers;
        Ok(p)
    }
}

macro_rules! request_builder {
    ($name:ident, $output:ty) => {
        impl<'a> $name<'a> {
            /// Adds an extra request header.
            pub fn header(mut self, name: &str, value: &str) -> Self {
                self.opts.append(name, value);
                self
            }
        }
        impl<'a> IntoFuture for $name<'a> {
            type Output = Result<$output>;
            type IntoFuture = BoxFuture<'a, Result<$output>>;
            fn into_future(self) -> Self::IntoFuture {
                Box::pin(self.send())
            }
        }
    };
}

/// `HEAD` request builder; see [`Client::head`].
#[must_use = "requests do nothing unless awaited"]
pub struct HeadRequest<'a> {
    client: &'a Client,
    opts: Options,
}
request_builder!(HeadRequest, ResourceMetadata);

impl HeadRequest<'_> {
    /// Sends the request.
    pub async fn send(self) -> Result<ResourceMetadata> {
        let req = self.opts.into_prepared(Method::HEAD)?;
        let resp = self.client.execute(req).await?;
        Ok(metadata_of(&resp))
    }
}

/// `GET` request builder; see [`Client::read`].
#[must_use = "requests do nothing unless awaited"]
pub struct ReadRequest<'a> {
    client: &'a Client,
    opts: Options,
}
request_builder!(ReadRequest, Resource);

impl ReadRequest<'_> {
    /// Sets `Accept`.
    pub fn accept(mut self, media_types: &str) -> Self {
        self.opts.set(ACCEPT, media_types);
        self
    }
    /// Requests a byte range (`Range: bytes=start-end`, `end` inclusive; `None` = to the end).
    pub fn range(mut self, start: u64, end: Option<u64>) -> Self {
        let v = match end {
            Some(e) => format!("bytes={start}-{e}"),
            None => format!("bytes={start}-"),
        };
        self.opts.set(RANGE, &v);
        self
    }
    /// Conditional read: `If-None-Match` (a `304` yields [`Resource::not_modified`]).
    pub fn if_none_match(mut self, etag: impl AsRef<str>) -> Self {
        self.opts.set(IF_NONE_MATCH, etag.as_ref());
        self
    }
    /// Conditional read: `If-Modified-Since`.
    pub fn if_modified_since(mut self, time: SystemTime) -> Self {
        self.opts
            .set(IF_MODIFIED_SINCE, &httpdate::fmt_http_date(time));
        self
    }
    /// Sets `Prefer` (e.g. link-relation preferences).
    pub fn prefer(mut self, preference: &str) -> Self {
        self.opts.set(HeaderName::from_static("prefer"), preference);
        self
    }
    /// Sends the request and buffers the body.
    pub async fn send(self) -> Result<Resource> {
        let req = self.opts.into_prepared(Method::GET)?;
        let resp = self.client.execute(req).await?;
        let metadata = metadata_of(&resp);
        let not_modified = metadata.status == StatusCode::NOT_MODIFIED;
        let body = if not_modified {
            Bytes::new()
        } else {
            resp.bytes().await?
        };
        Ok(Resource {
            metadata,
            body,
            not_modified,
        })
    }
    /// Sends the request and returns before reading the body.
    pub async fn send_streaming(self) -> Result<StreamingResource> {
        let req = self.opts.into_prepared(Method::GET)?;
        let resp = self.client.execute(req).await?;
        Ok(StreamingResource::new(metadata_of(&resp), resp))
    }
}

/// `POST` (create) request builder; see [`Client::create`] and [`Client::create_container`].
#[must_use = "requests do nothing unless awaited"]
pub struct CreateRequest<'a> {
    client: &'a Client,
    opts: Options,
    body: Body,
    links: Vec<Link>,
}
request_builder!(CreateRequest, CreateResult);

impl CreateRequest<'_> {
    /// Identity hint for the new resource (sent as `Slug`).
    pub fn slug(mut self, slug: &str) -> Self {
        self.opts
            .set(HeaderName::from_static("slug"), &encode_slug(slug));
        self
    }
    /// Initial user-managed metadata link.
    pub fn link(mut self, link: Link) -> Self {
        self.links.push(link);
        self
    }
    /// An additional type for the new resource (`Link: <type>; rel="type"`).
    pub fn resource_type(mut self, type_iri: &str) -> Self {
        match Url::parse(type_iri) {
            Ok(u) => self.links.push(Link::new(u, rel::TYPE)),
            Err(e) => {
                self.opts.error = Some(Error::InvalidInput(format!(
                    "invalid type IRI {type_iri:?}: {e}"
                )))
            }
        }
        self
    }
    /// Sends the request.
    pub async fn send(self) -> Result<CreateResult> {
        let mut req = self.opts.into_prepared(Method::POST)?;
        for l in &self.links {
            req = req.header(LINK, &l.to_header_value())?;
        }
        if let BodyKind::Bytes(b) = &self.body.0 {
            if b.is_empty() {
                req = req.header(CONTENT_LENGTH, "0")?;
            }
        }
        req.body = Some(self.body);
        let resp = self.client.execute(req).await?;
        let metadata = metadata_of(&resp);
        let location = metadata.header("location").ok_or_else(|| {
            Error::Protocol(format!(
                "{} response to POST has no Location",
                metadata.status
            ))
        })?;
        let location = metadata
            .url
            .join(location)
            .map_err(|e| Error::Protocol(format!("invalid Location: {e}")))?;
        let body = resp.bytes().await?;
        Ok(CreateResult {
            location,
            metadata,
            body,
        })
    }
}

/// `PUT` (update) request builder; see [`Client::update`] and [`Client::update_linkset`].
#[must_use = "requests do nothing unless awaited"]
pub struct UpdateRequest<'a> {
    client: &'a Client,
    opts: Options,
    method: Method,
    body: Body,
    links: Vec<Link>,
    set_linkset: bool,
}
request_builder!(UpdateRequest, UpdateResult);

/// `PATCH` request builder; see [`Client::patch`] and [`Client::patch_linkset`].
pub type PatchRequest<'a> = UpdateRequest<'a>;

impl UpdateRequest<'_> {
    /// Only update if the current entity tag matches (`If-Match`); a mismatch yields
    /// [`Error::PreconditionFailed`].
    pub fn if_match(mut self, etag: impl AsRef<str>) -> Self {
        self.opts.set(IF_MATCH, etag.as_ref());
        self
    }
    /// `If-None-Match` (e.g. `*` to refuse overwriting).
    pub fn if_none_match(mut self, etag: impl AsRef<str>) -> Self {
        self.opts.set(IF_NONE_MATCH, etag.as_ref());
        self
    }
    /// A link sent with the request (applied to the linkset only with [`set_linkset`](Self::set_linkset)).
    pub fn link(mut self, link: Link) -> Self {
        self.links.push(link);
        self
    }
    /// Also replace (PUT) / patch (PATCH) the linkset with the given links, atomically
    /// (`Prefer: set-linkset`; optional server feature).
    pub fn set_linkset(mut self, enabled: bool) -> Self {
        self.set_linkset = enabled;
        self
    }
    /// Sends the request.
    pub async fn send(self) -> Result<UpdateResult> {
        let mut req = self.opts.into_prepared(self.method)?;
        for l in &self.links {
            req = req.header(LINK, &l.to_header_value())?;
        }
        if self.set_linkset {
            req = req.header(HeaderName::from_static("prefer"), prefer::SET_LINKSET)?;
        }
        req.body = Some(self.body);
        let resp = self.client.execute(req).await?;
        let metadata = metadata_of(&resp);
        let body = resp.bytes().await?;
        Ok(UpdateResult {
            status: metadata.status,
            etag: metadata.etag.clone(),
            metadata,
            body,
        })
    }
}

/// `DELETE` request builder; see [`Client::delete`].
#[must_use = "requests do nothing unless awaited"]
pub struct DeleteRequest<'a> {
    client: &'a Client,
    opts: Options,
}
request_builder!(DeleteRequest, ());

impl DeleteRequest<'_> {
    /// Only delete if the entity tag matches.
    pub fn if_match(mut self, etag: impl AsRef<str>) -> Self {
        self.opts.set(IF_MATCH, etag.as_ref());
        self
    }
    /// Recursively delete a non-empty container (`Depth: infinity`).
    pub fn recursive(mut self, recursive: bool) -> Self {
        if recursive {
            self.opts.set(HeaderName::from_static("depth"), "infinity");
        } else {
            self.opts.headers.remove("depth");
        }
        self
    }
    /// Sends the request.
    pub async fn send(self) -> Result<()> {
        let req = self.opts.into_prepared(Method::DELETE)?;
        self.client.execute(req).await?;
        Ok(())
    }
}

fn metadata_of(resp: &reqwest::Response) -> ResourceMetadata {
    ResourceMetadata::from_parts(resp.url().clone(), resp.status(), resp.headers().clone())
}

async fn json_body(resp: reqwest::Response) -> Result<(ResourceMetadata, Value)> {
    let metadata = metadata_of(&resp);
    let bytes = resp.bytes().await?;
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((metadata, value))
}

impl Client {
    /// A client with default settings (anonymous).
    pub fn new() -> Self {
        Self::builder()
            .build()
            .expect("default client configuration is valid")
    }

    /// A [`ClientBuilder`].
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    // ------------------------------------------------------------------ execution

    async fn dispatch(
        &self,
        parts: &RequestParts,
        body: Option<reqwest::Body>,
    ) -> Result<reqwest::Response> {
        let mut rb = self
            .inner
            .http
            .request(parts.method.clone(), parts.url.clone())
            .headers(parts.headers.clone());
        if let Some(t) = self.inner.timeout {
            rb = rb.timeout(t);
        }
        if let Some(b) = body {
            rb = rb.body(b);
        }
        Ok(rb.send().await?)
    }

    /// Sends one hop: authorizes, dispatches and, on `401`, lets the authenticator handle the
    /// challenge and retries once (replayable bodies only).
    async fn send_hop(
        &self,
        parts: &mut RequestParts,
        bytes: Option<Bytes>,
        stream: Option<reqwest::Body>,
        user_auth: bool,
    ) -> Result<reqwest::Response> {
        let auth = self.inner.authenticator.clone();
        if let Some(auth) = &auth {
            auth.authorize(parts).await?;
        }
        let replayable = stream.is_none();
        let body = match stream {
            Some(s) => Some(s),
            None => bytes.clone().map(reqwest::Body::from),
        };
        let resp = self.dispatch(parts, body).await?;
        if resp.status() == StatusCode::UNAUTHORIZED && replayable {
            if let Some(auth) = &auth {
                let rp = ResponseParts {
                    status: resp.status(),
                    url: resp.url().clone(),
                    headers: resp.headers().clone(),
                };
                if auth.handle_challenge(parts, &rp).await? {
                    if !user_auth {
                        parts.headers.remove(AUTHORIZATION);
                    }
                    auth.authorize(parts).await?;
                    return self.dispatch(parts, bytes.map(reqwest::Body::from)).await;
                }
            }
        }
        Ok(resp)
    }

    /// Sends a request through the authenticator (with the single 401 retry), follows
    /// redirects hop by hop (re-authorizing for every new URL, so tokens never leave their
    /// realm) and maps error statuses to [`Error`].
    async fn execute(&self, req: Prepared) -> Result<reqwest::Response> {
        let mut headers = self.inner.default_headers.clone();
        for (name, value) in req.headers.iter() {
            headers.append(name.clone(), value.clone());
        }
        let mut user_auth = req.headers.contains_key(AUTHORIZATION);
        let mut parts = RequestParts {
            method: req.method,
            url: req.url,
            headers,
        };
        let replayable = req.body.as_ref().is_none_or(Body::replayable);
        let (mut bytes, mut stream) = match req.body.map(|b| b.0) {
            Some(BodyKind::Bytes(b)) => (Some(b), None),
            Some(BodyKind::Stream(s)) => (None, Some(s)),
            None => (None, None),
        };
        if let Some(auth) = &self.inner.authenticator {
            if !replayable {
                // Establish a token before streaming a non-replayable body.
                let mut probe = parts.clone();
                auth.authorize(&mut probe).await?;
                if !probe.headers.contains_key(AUTHORIZATION) {
                    let mut head = RequestParts {
                        method: Method::HEAD,
                        url: parts.url.clone(),
                        headers: self.inner.default_headers.clone(),
                    };
                    auth.authorize(&mut head).await?;
                    if let Ok(resp) = self.dispatch(&head, None).await {
                        if resp.status() == StatusCode::UNAUTHORIZED {
                            let rp = ResponseParts {
                                status: resp.status(),
                                url: resp.url().clone(),
                                headers: resp.headers().clone(),
                            };
                            let _ = auth.handle_challenge(&head, &rp).await;
                        }
                    }
                }
            }
        }
        let mut hops = 0;
        loop {
            let resp = self
                .send_hop(&mut parts, bytes.clone(), stream.take(), user_auth)
                .await?;
            let status = resp.status().as_u16();
            if !self.inner.follow_redirects || !matches!(status, 301 | 302 | 303 | 307 | 308) {
                return check(&parts.method, resp).await;
            }
            let Some(location) = resp
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|l| parts.url.join(l).ok())
            else {
                return check(&parts.method, resp).await;
            };
            let safe = matches!(parts.method.as_str(), "GET" | "HEAD" | "OPTIONS" | QUERY);
            match status {
                // See Other: retrieve the result with GET (HEAD stays HEAD), without a body.
                303 if safe => {
                    if parts.method != Method::HEAD {
                        parts.method = Method::GET;
                    }
                    bytes = None;
                    parts.headers.remove(CONTENT_TYPE);
                    parts.headers.remove(CONTENT_LENGTH);
                }
                // 301/302 keep the method for safe requests only; 307/308 always keep method
                // and body. Either way the body must be replayable.
                301 | 302 if safe && replayable => {}
                307 | 308 if replayable => {}
                _ => return check(&parts.method, resp).await,
            }
            hops += 1;
            if hops > MAX_REDIRECTS {
                return Err(Error::Protocol(format!(
                    "too many redirects (more than {MAX_REDIRECTS}) at {}",
                    parts.url
                )));
            }
            // Credentials are re-evaluated for every hop: the authenticator only attaches a
            // token when the new URL lies inside a cached realm. An explicitly supplied
            // `Authorization` header survives same-origin redirects only.
            let same_origin = location.origin() == parts.url.origin();
            if !(user_auth && same_origin) {
                parts.headers.remove(AUTHORIZATION);
                user_auth = false;
            }
            parts.url = location;
        }
    }

    // ------------------------------------------------------------------ discovery

    /// Discovers the storage a resource belongs to: `HEAD` the resource (falling back to `GET`
    /// on 405/501), follow its `rel="https://www.w3.org/ns/lws#storage"` link and fetch the
    /// storage description.
    pub async fn discover_storage(&self, resource_url: impl IntoUrl) -> Result<StorageDescription> {
        let url = resource_url.into_url()?;
        let storage = match self.head(url.clone()).send().await {
            Ok(m) => m.storage().cloned(),
            Err(e) if matches!(e.status().map(|s| s.as_u16()), Some(405 | 501)) => {
                let r = self.read(url.clone()).send_streaming().await?;
                r.metadata.storage().cloned()
            }
            Err(e) => {
                // A 401 SHOULD still carry the storage link; the description is public.
                let link = e
                    .http_error()
                    .and_then(|h| h.links().into_iter().find(|l| l.has_rel(rel::STORAGE)));
                match link {
                    Some(l) => Some(l.href),
                    None => return Err(e),
                }
            }
        };
        let storage =
            storage.ok_or_else(|| Error::Protocol(format!("{url} has no storage link")))?;
        self.get_storage_description(storage).await
    }

    /// Fetches and parses a storage description.
    pub async fn get_storage_description(
        &self,
        storage_url: impl IntoUrl,
    ) -> Result<StorageDescription> {
        let req = Prepared::new(Method::GET, storage_url.into_url()?).header(ACCEPT, ACCEPT_CID)?;
        let resp = self.execute(req).await?;
        let url = resp.url().clone();
        let body = resp.bytes().await?;
        StorageDescription::parse(&url, &body)
    }

    // ------------------------------------------------------------------ reading

    /// `HEAD` a resource for its metadata.
    pub fn head(&self, url: impl IntoUrl) -> HeadRequest<'_> {
        HeadRequest {
            client: self,
            opts: Options::new(url),
        }
    }

    /// `GET` a resource. Await it directly or configure it first:
    /// `client.read(url).if_none_match(etag).await?`.
    pub fn read(&self, url: impl IntoUrl) -> ReadRequest<'_> {
        ReadRequest {
            client: self,
            opts: Options::new(url),
        }
    }

    /// Reads one page of a container listing (`Accept: application/lws+json`).
    pub async fn read_container(&self, url: impl IntoUrl) -> Result<ContainerPage> {
        let req =
            Prepared::new(Method::GET, url.into_url()?).header(ACCEPT, media_type::LWS_JSON)?;
        let resp = self.execute(req).await?;
        let metadata = metadata_of(&resp);
        let body = resp.bytes().await?;
        ContainerPage::parse(metadata, &body)
    }

    /// Lazily lists all members of a container, following `rel="next"` pages.
    pub fn list_container(&self, url: impl IntoUrl) -> LwsStream<ContainedResource> {
        let first = url.into_url();
        paginate(self.clone(), first, |client, url, _first| async move {
            let page = client.read_container(url).await?;
            Ok((page.items, page.next))
        })
    }

    // ------------------------------------------------------------------ writing

    /// `POST` a new data resource into a container.
    pub fn create(
        &self,
        container_url: impl IntoUrl,
        body: impl Into<Body>,
        content_type: &str,
    ) -> CreateRequest<'_> {
        let mut opts = Options::new(container_url);
        opts.set(CONTENT_TYPE, content_type);
        CreateRequest {
            client: self,
            opts,
            body: body.into(),
            links: Vec::new(),
        }
    }

    /// `POST` a JSON document (`application/json`) into a container.
    pub fn create_json<T: Serialize + ?Sized>(
        &self,
        container_url: impl IntoUrl,
        value: &T,
    ) -> CreateRequest<'_> {
        let mut req = self.create(container_url, Body::empty(), media_type::JSON);
        match serde_json::to_vec(value) {
            Ok(v) => req.body = v.into(),
            Err(e) => {
                req.opts.error = Some(Error::InvalidInput(format!("cannot serialize JSON: {e}")))
            }
        }
        req
    }

    /// `POST` a new sub-container (`Link: <https://www.w3.org/ns/lws#Container>; rel="type"`).
    pub fn create_container(&self, parent_url: impl IntoUrl) -> CreateRequest<'_> {
        let container = Link::new(
            Url::parse(lws_types::CONTAINER).expect("valid constant"),
            rel::TYPE,
        );
        CreateRequest {
            client: self,
            opts: Options::new(parent_url),
            body: Body::empty(),
            links: vec![container],
        }
    }

    /// `PUT` a full replacement of a resource's content.
    pub fn update(
        &self,
        url: impl IntoUrl,
        body: impl Into<Body>,
        content_type: &str,
    ) -> UpdateRequest<'_> {
        let mut opts = Options::new(url);
        opts.set(CONTENT_TYPE, content_type);
        UpdateRequest {
            client: self,
            opts,
            method: Method::PUT,
            body: body.into(),
            links: Vec::new(),
            set_linkset: false,
        }
    }

    /// `PATCH` a resource with JSON Patch (`application/json-patch+json`).
    pub fn patch(&self, url: impl IntoUrl, patch: &JsonPatch) -> PatchRequest<'_> {
        self.patch_with(url, patch.to_vec(), media_type::JSON_PATCH)
    }

    /// `PATCH` with any patch format the server advertises in `Accept-Patch`.
    pub fn patch_with(
        &self,
        url: impl IntoUrl,
        body: impl Into<Body>,
        content_type: &str,
    ) -> PatchRequest<'_> {
        let mut opts = Options::new(url);
        opts.set(CONTENT_TYPE, content_type);
        UpdateRequest {
            client: self,
            opts,
            method: Method::PATCH,
            body: body.into(),
            links: Vec::new(),
            set_linkset: false,
        }
    }

    /// `DELETE` a resource (see [`DeleteRequest::recursive`] for non-empty containers).
    pub fn delete(&self, url: impl IntoUrl) -> DeleteRequest<'_> {
        DeleteRequest {
            client: self,
            opts: Options::new(url),
        }
    }

    // ------------------------------------------------------------------ metadata

    /// The URL of a resource's linkset (from `rel="linkset"` on `HEAD`).
    pub async fn linkset_url(&self, resource_url: impl IntoUrl) -> Result<Url> {
        let m = self.head(resource_url).send().await?;
        m.linkset()
            .cloned()
            .ok_or_else(|| Error::Protocol(format!("{} has no linkset link", m.url)))
    }

    /// Discovers and reads a resource's linkset.
    pub async fn read_linkset(&self, resource_url: impl IntoUrl) -> Result<LinksetDocument> {
        let url = self.linkset_url(resource_url).await?;
        self.read_linkset_document(url).await
    }

    /// Reads a linkset resource by its own URL.
    pub async fn read_linkset_document(
        &self,
        linkset_url: impl IntoUrl,
    ) -> Result<LinksetDocument> {
        let req = Prepared::new(Method::GET, linkset_url.into_url()?)
            .header(ACCEPT, media_type::LINKSET_JSON)?;
        let resp = self.execute(req).await?;
        let metadata = metadata_of(&resp);
        let body = resp.bytes().await?;
        let linkset = Linkset::parse(&body)?;
        Ok(LinksetDocument {
            url: metadata.url.clone(),
            etag: metadata.etag.clone(),
            allow: metadata.allow.clone(),
            accept_patch: metadata.accept_patch.clone(),
            linkset,
            metadata,
        })
    }

    /// `PUT` a complete linkset (only if the server lists PUT in `Allow`; otherwise
    /// [`Error::MethodNotAllowed`]).
    pub fn update_linkset(
        &self,
        linkset_url: impl IntoUrl,
        linkset: &Linkset,
    ) -> UpdateRequest<'_> {
        let body = serde_json::to_vec(&linkset.to_json()).unwrap_or_default();
        self.update(linkset_url, body, media_type::LINKSET_JSON)
    }

    /// `PATCH` a linkset with JSON Patch.
    pub fn patch_linkset(&self, linkset_url: impl IntoUrl, patch: &JsonPatch) -> PatchRequest<'_> {
        self.patch(linkset_url, patch)
    }

    // ------------------------------------------------------------------ JSON helpers

    async fn post_json(&self, url: Url, body: &Value) -> Result<(ResourceMetadata, Value)> {
        let mut req = Prepared::new(Method::POST, url)
            .header(CONTENT_TYPE, media_type::LWS_JSON)?
            .header(ACCEPT, ACCEPT_JSON_LD)?;
        req.body = Some(serde_json::to_vec(body)?.into());
        json_body(self.execute(req).await?).await
    }

    async fn get_json(&self, url: Url) -> Result<(ResourceMetadata, Value)> {
        let req = Prepared::new(Method::GET, url).header(ACCEPT, ACCEPT_JSON_LD)?;
        json_body(self.execute(req).await?).await
    }

    async fn create_document(&self, service_url: impl IntoUrl, body: &Value) -> Result<Url> {
        let (metadata, _) = self.post_json(service_url.into_url()?, body).await?;
        let location = metadata
            .header("location")
            .ok_or_else(|| Error::Protocol("POST response has no Location".into()))?;
        metadata
            .url
            .join(location)
            .map_err(|e| Error::Protocol(format!("invalid Location: {e}")))
    }

    // ------------------------------------------------------------------ notifications

    /// Creates a webhook subscription at a `NotificationService` endpoint.
    pub async fn subscribe(
        &self,
        service_url: impl IntoUrl,
        request: &WebhookSubscriptionRequest,
    ) -> Result<Subscription> {
        let (metadata, body) = self
            .post_json(service_url.into_url()?, &request.to_json())
            .await?;
        let location = metadata
            .header("location")
            .and_then(|l| metadata.url.join(l).ok());
        Subscription::from_json(
            body,
            &metadata.url,
            location.as_ref(),
            service::SUBSCRIPTION_WEBHOOK,
        )
    }

    /// Creates a webhook subscription using the storage's `NotificationService`, checking that it
    /// supports `WebhookSubscription`.
    pub async fn subscribe_storage(
        &self,
        storage: &StorageDescription,
        request: &WebhookSubscriptionRequest,
    ) -> Result<Subscription> {
        let svc = storage
            .notification_service()
            .ok_or_else(|| Error::Protocol("storage has no NotificationService".into()))?;
        if !svc.supports_subscription_type(service::SUBSCRIPTION_WEBHOOK) {
            return Err(Error::Protocol(
                "NotificationService does not support WebhookSubscription".into(),
            ));
        }
        self.subscribe(&svc.service_endpoint, request).await
    }

    /// Lists the subscriber's subscriptions (a container listing).
    pub fn list_subscriptions(&self, service_url: impl IntoUrl) -> LwsStream<ContainedResource> {
        self.list_container(service_url)
    }

    /// Reads a subscription.
    pub async fn get_subscription(&self, subscription_url: impl IntoUrl) -> Result<Subscription> {
        let url = subscription_url.into_url()?;
        let (metadata, body) = self.get_json(url.clone()).await?;
        Subscription::from_json(
            body,
            &metadata.url,
            Some(&url),
            service::SUBSCRIPTION_WEBHOOK,
        )
    }

    /// Cancels a subscription.
    pub async fn unsubscribe(&self, subscription_url: impl IntoUrl) -> Result<()> {
        self.delete(subscription_url).send().await
    }

    // ------------------------------------------------------------------ access requests / grants

    /// Submits an access request; returns its URL.
    pub async fn request_access(
        &self,
        service_url: impl IntoUrl,
        request: &AccessRequest,
    ) -> Result<Url> {
        self.create_document(service_url, &request.to_json()).await
    }
    /// Lists access requests.
    pub fn list_access_requests(&self, service_url: impl IntoUrl) -> LwsStream<ContainedResource> {
        self.list_container(service_url)
    }
    /// Reads an access request.
    pub async fn get_access_request(&self, url: impl IntoUrl) -> Result<AccessRequest> {
        AccessRequest::from_json(self.get_json(url.into_url()?).await?.1)
    }
    /// Cancels (deletes) an access request.
    pub async fn cancel_access_request(&self, url: impl IntoUrl) -> Result<()> {
        self.delete(url).send().await
    }
    /// Creates an access grant; returns its URL.
    pub async fn grant_access(
        &self,
        service_url: impl IntoUrl,
        grant: &AccessGrant,
    ) -> Result<Url> {
        self.create_document(service_url, &grant.to_json()).await
    }
    /// Lists access grants.
    pub fn list_access_grants(&self, service_url: impl IntoUrl) -> LwsStream<ContainedResource> {
        self.list_container(service_url)
    }
    /// Reads an access grant.
    pub async fn get_access_grant(&self, url: impl IntoUrl) -> Result<AccessGrant> {
        AccessGrant::from_json(self.get_json(url.into_url()?).await?.1)
    }
    /// Revokes (deletes) an access grant.
    pub async fn revoke_access_grant(&self, url: impl IntoUrl) -> Result<()> {
        self.delete(url).send().await
    }

    // ------------------------------------------------------------------ type index / search

    /// Reads one Type Index page (the service endpoint or an opaque page URL).
    pub async fn read_type_index(&self, url: impl IntoUrl) -> Result<TypeIndexPage> {
        let req =
            Prepared::new(Method::GET, url.into_url()?).header(ACCEPT, media_type::LWS_JSON)?;
        let resp = self.execute(req).await?;
        let metadata = metadata_of(&resp);
        let body = resp.bytes().await?;
        TypeIndexPage::parse(metadata, &body)
    }

    /// Lazily lists every type IRI in the Type Index.
    pub fn list_types(&self, service_url: impl IntoUrl) -> LwsStream<String> {
        paginate(
            self.clone(),
            service_url.into_url(),
            |client, url, _| async move {
                let page = client.read_type_index(url).await?;
                Ok((page.types, page.next))
            },
        )
    }

    async fn query_page(&self, url: Url, body: Bytes) -> Result<SearchPage> {
        let method = Method::from_bytes(QUERY.as_bytes()).expect("valid method");
        let mut req = Prepared::new(method, url)
            .header(CONTENT_TYPE, media_type::LWS_QUERY_JSON)?
            .header(ACCEPT, media_type::LWS_JSON)?;
        req.body = Some(body.into());
        let resp = self.execute(req).await?;
        let metadata = metadata_of(&resp);
        let bytes = resp.bytes().await?;
        SearchPage::parse(metadata, &bytes)
    }

    /// Searches with HTTP `QUERY` (`application/lws-query+json`) and returns the first page.
    pub async fn search_types(
        &self,
        service_url: impl IntoUrl,
        query: &TypeQuery,
    ) -> Result<SearchPage> {
        let body = serde_json::to_vec(&query.to_json()?)?;
        self.query_page(service_url.into_url()?, body.into()).await
    }

    /// Reads a subsequent search result page (an opaque `next` URL) with `GET`.
    pub async fn read_search_page(&self, page_url: impl IntoUrl) -> Result<SearchPage> {
        let req = Prepared::new(Method::GET, page_url.into_url()?)
            .header(ACCEPT, media_type::LWS_JSON)?;
        let resp = self.execute(req).await?;
        let metadata = metadata_of(&resp);
        let bytes = resp.bytes().await?;
        SearchPage::parse(metadata, &bytes)
    }

    /// Lazily yields every search result: `QUERY` for the first page, then `GET` on each `next`.
    pub fn search_all(
        &self,
        service_url: impl IntoUrl,
        query: &TypeQuery,
    ) -> LwsStream<ContainedResource> {
        let body = match query
            .to_json()
            .and_then(|v| Ok(Bytes::from(serde_json::to_vec(&v)?)))
        {
            Ok(b) => b,
            Err(e) => return Box::pin(stream::once(async move { Err(e) })),
        };
        paginate(
            self.clone(),
            service_url.into_url(),
            move |client, url, first| {
                let body = body.clone();
                async move {
                    let page = if first {
                        client.query_page(url, body).await?
                    } else {
                        client.read_search_page(url).await?
                    };
                    Ok((page.items, page.next))
                }
            },
        )
    }

    /// The query formats a search endpoint accepts (`OPTIONS` → `Accept-Query`).
    pub async fn accepted_query_formats(&self, service_url: impl IntoUrl) -> Result<Vec<String>> {
        let req = Prepared::new(Method::OPTIONS, service_url.into_url()?);
        let resp = self.execute(req).await?;
        Ok(parse_list(
            resp.headers()
                .get_all("accept-query")
                .iter()
                .filter_map(|v| v.to_str().ok()),
        ))
    }
}

/// Maps non-success responses (other than 304) to errors.
async fn check(method: &Method, resp: reqwest::Response) -> Result<reqwest::Response> {
    let status = resp.status();
    if status.is_success() || status == StatusCode::NOT_MODIFIED {
        return Ok(resp);
    }
    let url = resp.url().clone();
    let headers = resp.headers().clone();
    let bytes = resp.bytes().await.unwrap_or_default();
    let is_json = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(crate::headers::essence)
        .is_some_and(|ct| ct.ends_with("json"));
    let problem = if is_json {
        ProblemDetails::parse(&bytes)
    } else {
        None
    };
    let mut body = String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]).into_owned();
    body.truncate(4096);
    let challenges = parse_www_authenticate(
        headers
            .get_all(http::header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|v| v.to_str().ok()),
    );
    Err(Error::from_http(HttpError {
        status,
        method: method.clone(),
        url,
        headers,
        problem,
        body,
        challenges,
    }))
}

/// A lazy stream over paginated results. `fetch(client, url, is_first_page)` returns the page
/// items and the next page URL.
fn paginate<T, F, Fut>(client: Client, first: Result<Url>, fetch: F) -> LwsStream<T>
where
    T: Send + 'static,
    F: Fn(Client, Url, bool) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(Vec<T>, Option<Url>)>> + Send + 'static,
{
    struct State<T, F> {
        client: Client,
        fetch: Arc<F>,
        next: Option<Url>,
        first: bool,
        buffer: VecDeque<T>,
        seen: HashSet<Url>,
    }
    let first = match first {
        Ok(u) => u,
        Err(e) => return Box::pin(stream::once(async move { Err(e) })),
    };
    let state = State {
        client,
        fetch: Arc::new(fetch),
        next: Some(first),
        first: true,
        buffer: VecDeque::new(),
        seen: HashSet::new(),
    };
    Box::pin(stream::try_unfold(state, |mut st| async move {
        loop {
            if let Some(item) = st.buffer.pop_front() {
                return Ok(Some((item, st)));
            }
            let Some(url) = st.next.take() else {
                return Ok(None);
            };
            if !st.seen.insert(url.clone()) {
                return Err(Error::Protocol(format!("pagination loop at {url}")));
            }
            let (items, next) = (st.fetch)(st.client.clone(), url, st.first).await?;
            st.first = false;
            st.buffer.extend(items);
            st.next = next;
        }
    }))
}
