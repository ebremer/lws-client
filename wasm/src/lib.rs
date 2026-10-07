// SPDX-License-Identifier: MIT
//! The lws-client as a WebAssembly component: the Rust client of ../rust behind the interface
//! of wit/lws.wit.
//!
//! On `wasm32-wasip2` the client sends its requests through the host's `wasi:http`, which
//! blocks the component until the answer is in. So every future of the client is ready at its
//! first poll, and each export runs its operation to completion with [`block_on`].

// The errors are the interface's own record (wit/lws.wit), returned as they are.
#![allow(clippy::result_large_err)]

mod convert;

use std::cell::RefCell;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use futures_util::TryStreamExt as _;
use lws_client::auth::CredentialContext;
use lws_client::crypto::{Jwk, KeyAlgorithm as LwsKeyAlgorithm, SigningKey};
use lws_client::{
    BearerTokenAuthenticator, ContainedResource, CredentialProvider, Error as LwsError, LwsStream,
    OpenIdCredentials, SamlCredentials, SelfSignedCredentials, TokenExchangeAuthenticator,
    WebhookSubscriptionRequest, WebhookVerifier,
};
use serde_json::Value;

use crate::bindings::ebremer::lws::token_source::{self, TokenKind};
use crate::bindings::ebremer::lws::types::{
    Created, Error, Header, Item, Json, LinksetDocument, Metadata, Page, PatchOperation,
    ReadResult, StorageDescription, Subscription, SubscriptionRequest, TypeIndexPage, TypeQuery,
    Updated,
};
use crate::bindings::exports::ebremer::lws::client::{
    Auth, Client, CreateOptions, DeleteOptions, Guest as ClientGuest, GuestClient, GuestItems,
    GuestTypeIris, Identity, Items, KeyAlgorithm, Options, ReadOptions, SubjectToken, TypeIris,
    UpdateOptions,
};
use crate::bindings::exports::ebremer::lws::webhook::{
    Activity, ClientBorrow, Guest as WebhookGuest, GuestVerifier, VerifiedNotification, Verifier,
};
use crate::convert::{error, invalid};

mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "lws-client",
    });
}

/// Runs a future of the client to completion. Its futures wait on nothing but the host's
/// `wasi:http`, which blocks, so they are ready at once; the bound guards against one that
/// yields, which nothing would wake.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..1000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("an operation of the client did not complete");
}

/// Runs an operation of the library and converts its result.
fn run<T, U>(
    future: impl Future<Output = lws_client::Result<T>>,
    convert: impl FnOnce(T) -> U,
) -> Result<U, Error> {
    block_on(future).map(convert).map_err(error)
}

struct Component;

impl ClientGuest for Component {
    type Client = LwsClient;
    type Items = LwsItems;
    type TypeIris = LwsTypeIris;

    fn library() -> String {
        lws_client::constants::USER_AGENT.to_owned()
    }
}

impl WebhookGuest for Component {
    type Verifier = LwsVerifier;
}

bindings::export!(Component with_types_in bindings);

// ---------------------------------------------------------------------------------------------
// The client

struct LwsClient {
    client: lws_client::Client,
    identity: Option<Identity>,
}

/// A subject token from the host's `token-source`.
async fn host_token(kind: TokenKind, context: CredentialContext) -> lws_client::Result<String> {
    token_source::subject_token(kind, &context.issuer, &context.realm).map_err(|message| {
        LwsError::Authentication {
            message: format!("the host has no subject token: {message}"),
            error: None,
            error_description: None,
        }
    })
}

fn exchange(
    provider: impl CredentialProvider + 'static,
    allow_insecure_http: bool,
) -> TokenExchangeAuthenticator {
    TokenExchangeAuthenticator::builder(provider)
        .allow_insecure_http(allow_insecure_http)
        .build()
}

/// The library's signing key for a private JWK.
fn signing_key(jwk: &Value) -> Result<SigningKey, Error> {
    Jwk::from_json(jwk)
        .and_then(|jwk| SigningKey::from_jwk(&jwk))
        .map_err(|e| invalid(format!("private-jwk is not a usable key: {e}")))
}

fn new_client(options: Options) -> Result<LwsClient, Error> {
    let insecure = options.allow_insecure_http;
    let mut builder = lws_client::Client::builder();
    let mut identity = None;
    match options.auth {
        Auth::None => {}
        Auth::Bearer(bearer) => {
            let mut authenticator = BearerTokenAuthenticator::new(bearer.token);
            if let Some(realm) = bearer.realm {
                authenticator = authenticator.with_realm(convert::url("realm", &realm)?);
            }
            builder = builder.authenticator(authenticator);
        }
        Auth::Openid(SubjectToken::Fixed(token)) => {
            builder = builder.authenticator(exchange(OpenIdCredentials::new(token), insecure));
        }
        Auth::Openid(SubjectToken::Host) => {
            let credentials =
                OpenIdCredentials::from_fn(|context| host_token(TokenKind::Openid, context));
            builder = builder.authenticator(exchange(credentials, insecure));
        }
        Auth::Saml(SubjectToken::Fixed(assertion)) => {
            builder = builder.authenticator(exchange(SamlCredentials::new(assertion), insecure));
        }
        Auth::Saml(SubjectToken::Host) => {
            let credentials =
                SamlCredentials::from_fn(|context| host_token(TokenKind::Saml, context));
            builder = builder.authenticator(exchange(credentials, insecure));
        }
        Auth::SelfSigned(key) => {
            let jwk = convert::json("private-jwk", &key.private_jwk)?;
            let kid = match key.kid {
                Some(kid) => kid,
                None => jwk
                    .get("kid")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| invalid("a self-signed key needs a kid, or a kid in its JWK"))?,
            };
            let credentials =
                SelfSignedCredentials::for_agent(key.agent.as_str(), signing_key(&jwk)?, &kid);
            identity = Some(Identity {
                agent: key.agent,
                kid,
            });
            builder = builder.authenticator(exchange(credentials, insecure));
        }
        Auth::DidKey(algorithm) => {
            let algorithm = match algorithm {
                KeyAlgorithm::Es256 => LwsKeyAlgorithm::P256,
                KeyAlgorithm::Eddsa => LwsKeyAlgorithm::Ed25519,
            };
            let credentials =
                SelfSignedCredentials::did_key(SigningKey::generate(algorithm).map_err(error)?);
            identity = Some(Identity {
                agent: credentials.agent().to_owned(),
                kid: credentials.kid().to_owned(),
            });
            builder = builder.authenticator(exchange(credentials, insecure));
        }
    }
    if let Some(user_agent) = options.user_agent {
        builder = builder.user_agent(user_agent);
    }
    if let Some(ms) = options.timeout_ms {
        builder = builder.timeout(Duration::from_millis(ms));
    }
    for (name, value) in &options.headers {
        builder = builder.default_header(name, value);
    }
    Ok(LwsClient {
        client: builder.build().map_err(error)?,
        identity,
    })
}

fn with_headers<R>(mut request: R, headers: &[Header], add: impl Fn(R, &str, &str) -> R) -> R {
    for (name, value) in headers {
        request = add(request, name, value);
    }
    request
}

fn items(stream: LwsStream<ContainedResource>) -> Items {
    Items::new(LwsItems {
        stream: RefCell::new(stream),
    })
}

impl LwsClient {
    fn update_request<'a>(
        &self,
        mut request: lws_client::UpdateRequest<'a>,
        options: &UpdateOptions,
    ) -> Result<lws_client::UpdateRequest<'a>, Error> {
        if let Some(etag) = &options.if_match {
            request = request.if_match(etag);
        }
        if let Some(etag) = &options.if_none_match {
            request = request.if_none_match(etag);
        }
        for link in &options.links {
            request = request.link(convert::link(link)?);
        }
        if options.set_linkset {
            request = request.set_linkset(true);
        }
        Ok(with_headers(request, &options.headers, |r, n, v| {
            r.header(n, v)
        }))
    }

    fn create_request<'a>(
        &self,
        mut request: lws_client::CreateRequest<'a>,
        options: &CreateOptions,
    ) -> Result<lws_client::CreateRequest<'a>, Error> {
        if let Some(slug) = &options.slug {
            request = request.slug(slug);
        }
        for type_iri in &options.types {
            request = request.resource_type(type_iri);
        }
        for link in &options.links {
            request = request.link(convert::link(link)?);
        }
        Ok(with_headers(request, &options.headers, |r, n, v| {
            r.header(n, v)
        }))
    }
}

impl GuestClient for LwsClient {
    fn new(options: Options) -> Result<Client, Error> {
        Ok(Client::new(new_client(options)?))
    }

    fn identity(&self) -> Option<Identity> {
        self.identity.clone()
    }

    fn discover_storage(&self, url: String) -> Result<StorageDescription, Error> {
        run(self.client.discover_storage(url.as_str()), |s| {
            convert::storage(&s)
        })
    }

    fn get_storage_description(&self, url: String) -> Result<StorageDescription, Error> {
        run(self.client.get_storage_description(url.as_str()), |s| {
            convert::storage(&s)
        })
    }

    fn head(&self, url: String) -> Result<Metadata, Error> {
        run(self.client.head(url.as_str()).send(), |m| {
            convert::metadata(&m)
        })
    }

    fn read(&self, url: String, options: ReadOptions) -> Result<ReadResult, Error> {
        let mut request = self.client.read(url.as_str());
        if let Some(accept) = &options.accept {
            request = request.accept(accept);
        }
        match (options.range_start, options.range_end) {
            (Some(start), end) => request = request.range(start, end),
            (None, Some(_)) => return Err(invalid("range-end needs range-start")),
            (None, None) => {}
        }
        if let Some(etag) = &options.if_none_match {
            request = request.if_none_match(etag);
        }
        if let Some(preference) = &options.prefer {
            request = request.prefer(preference);
        }
        let request = with_headers(request, &options.headers, |r, n, v| r.header(n, v));
        run(request.send(), |r| ReadResult {
            metadata: convert::metadata(&r.metadata),
            content_range: r.metadata.content_range().map(str::to_owned),
            body: r.body.to_vec(),
            not_modified: r.not_modified,
        })
    }

    fn read_container(&self, url: String) -> Result<Page, Error> {
        run(self.client.read_container(url.as_str()), |p| {
            convert::container_page(&p)
        })
    }

    fn list_container(&self, url: String) -> Items {
        items(self.client.list_container(url.as_str()))
    }

    fn create(
        &self,
        container: String,
        body: Vec<u8>,
        content_type: String,
        options: CreateOptions,
    ) -> Result<Created, Error> {
        let request = self.create_request(
            self.client.create(container.as_str(), body, &content_type),
            &options,
        )?;
        run(request.send(), |c| convert::created(&c))
    }

    fn create_container(&self, parent: String, options: CreateOptions) -> Result<Created, Error> {
        let request =
            self.create_request(self.client.create_container(parent.as_str()), &options)?;
        run(request.send(), |c| convert::created(&c))
    }

    fn update(
        &self,
        url: String,
        body: Vec<u8>,
        content_type: String,
        options: UpdateOptions,
    ) -> Result<Updated, Error> {
        let request = self.update_request(
            self.client.update(url.as_str(), body, &content_type),
            &options,
        )?;
        run(request.send(), |u| convert::updated(&u))
    }

    fn patch(
        &self,
        url: String,
        patch: Vec<PatchOperation>,
        options: UpdateOptions,
    ) -> Result<Updated, Error> {
        let patch = convert::patch(&patch)?;
        let request = self.update_request(self.client.patch(url.as_str(), &patch), &options)?;
        run(request.send(), |u| convert::updated(&u))
    }

    fn delete(&self, url: String, options: DeleteOptions) -> Result<(), Error> {
        let mut request = self.client.delete(url.as_str());
        if let Some(etag) = &options.if_match {
            request = request.if_match(etag);
        }
        if options.recursive {
            request = request.recursive(true);
        }
        let request = with_headers(request, &options.headers, |r, n, v| r.header(n, v));
        run(request.send(), |()| ())
    }

    fn linkset_url(&self, url: String) -> Result<String, Error> {
        run(self.client.linkset_url(url.as_str()), |u| u.to_string())
    }

    fn read_linkset(&self, url: String) -> Result<LinksetDocument, Error> {
        run(self.client.read_linkset(url.as_str()), |d| {
            convert::linkset_document(&d)
        })
    }

    fn read_linkset_document(&self, linkset_url: String) -> Result<LinksetDocument, Error> {
        run(
            self.client.read_linkset_document(linkset_url.as_str()),
            |d| convert::linkset_document(&d),
        )
    }

    fn update_linkset(
        &self,
        linkset_url: String,
        linkset: Json,
        options: UpdateOptions,
    ) -> Result<Updated, Error> {
        let linkset = lws_client::Linkset::from_json(&convert::json("linkset", &linkset)?)
            .map_err(|e| invalid(format!("linkset is not a linkset: {e}")))?;
        let request = self.update_request(
            self.client.update_linkset(linkset_url.as_str(), &linkset),
            &options,
        )?;
        run(request.send(), |u| convert::updated(&u))
    }

    fn patch_linkset(
        &self,
        linkset_url: String,
        patch: Vec<PatchOperation>,
        options: UpdateOptions,
    ) -> Result<Updated, Error> {
        let patch = convert::patch(&patch)?;
        let request = self.update_request(
            self.client.patch_linkset(linkset_url.as_str(), &patch),
            &options,
        )?;
        run(request.send(), |u| convert::updated(&u))
    }

    fn subscribe(
        &self,
        service_url: String,
        request: SubscriptionRequest,
    ) -> Result<Subscription, Error> {
        let topics = convert::urls("topics", &request.topics)?;
        let inbox = convert::url("inbox", &request.inbox)?;
        let mut subscription = WebhookSubscriptionRequest::new(topics, inbox);
        if let Some(expires) = request.expires {
            subscription = subscription.expires_raw(expires);
        }
        run(
            self.client.subscribe(service_url.as_str(), &subscription),
            |s| convert::subscription(&s),
        )
    }

    fn list_subscriptions(&self, service_url: String) -> Items {
        items(self.client.list_subscriptions(service_url.as_str()))
    }

    fn get_subscription(&self, url: String) -> Result<Subscription, Error> {
        run(self.client.get_subscription(url.as_str()), |s| {
            convert::subscription(&s)
        })
    }

    fn unsubscribe(&self, url: String) -> Result<(), Error> {
        run(self.client.unsubscribe(url.as_str()), |()| ())
    }

    fn request_access(&self, service_url: String, request: Json) -> Result<String, Error> {
        let request = lws_client::AccessRequest::from_json(convert::json("request", &request)?)
            .map_err(|e| invalid(format!("request is not an access request: {e}")))?;
        run(
            self.client.request_access(service_url.as_str(), &request),
            |u| u.to_string(),
        )
    }

    fn get_access_request(&self, url: String) -> Result<Json, Error> {
        run(self.client.get_access_request(url.as_str()), |r| {
            r.to_json().to_string()
        })
    }

    fn list_access_requests(&self, service_url: String) -> Items {
        items(self.client.list_access_requests(service_url.as_str()))
    }

    fn cancel_access_request(&self, url: String) -> Result<(), Error> {
        run(self.client.cancel_access_request(url.as_str()), |()| ())
    }

    fn grant_access(&self, service_url: String, grant: Json) -> Result<String, Error> {
        let grant = lws_client::AccessGrant::from_json(convert::json("grant", &grant)?)
            .map_err(|e| invalid(format!("grant is not an access grant: {e}")))?;
        run(
            self.client.grant_access(service_url.as_str(), &grant),
            |u| u.to_string(),
        )
    }

    fn get_access_grant(&self, url: String) -> Result<Json, Error> {
        run(self.client.get_access_grant(url.as_str()), |g| {
            g.to_json().to_string()
        })
    }

    fn list_access_grants(&self, service_url: String) -> Items {
        items(self.client.list_access_grants(service_url.as_str()))
    }

    fn revoke_access_grant(&self, url: String) -> Result<(), Error> {
        run(self.client.revoke_access_grant(url.as_str()), |()| ())
    }

    fn read_type_index(&self, url: String) -> Result<TypeIndexPage, Error> {
        run(self.client.read_type_index(url.as_str()), |p| {
            convert::type_index_page(&p)
        })
    }

    fn list_types(&self, service_url: String) -> TypeIris {
        TypeIris::new(LwsTypeIris {
            stream: RefCell::new(self.client.list_types(service_url.as_str())),
        })
    }

    fn search_types(&self, service_url: String, query: TypeQuery) -> Result<Page, Error> {
        let query = convert::type_query(&query);
        run(
            self.client.search_types(service_url.as_str(), &query),
            |p| convert::search_page(&p),
        )
    }

    fn read_search_page(&self, page_url: String) -> Result<Page, Error> {
        run(self.client.read_search_page(page_url.as_str()), |p| {
            convert::search_page(&p)
        })
    }

    fn search_all(&self, service_url: String, query: TypeQuery) -> Items {
        let query = convert::type_query(&query);
        items(self.client.search_all(service_url.as_str(), &query))
    }

    fn accepted_query_formats(&self, service_url: String) -> Result<Vec<String>, Error> {
        run(
            self.client.accepted_query_formats(service_url.as_str()),
            |f| f,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Listings

struct LwsItems {
    stream: RefCell<LwsStream<ContainedResource>>,
}

impl GuestItems for LwsItems {
    fn next(&self) -> Result<Option<Item>, Error> {
        let mut stream = self.stream.borrow_mut();
        run(stream.try_next(), |i| i.as_ref().map(convert::item))
    }
}

struct LwsTypeIris {
    stream: RefCell<LwsStream<String>>,
}

impl GuestTypeIris for LwsTypeIris {
    fn next(&self) -> Result<Option<String>, Error> {
        let mut stream = self.stream.borrow_mut();
        run(stream.try_next(), |t| t)
    }
}

// ---------------------------------------------------------------------------------------------
// Webhook notifications

struct LwsVerifier {
    verifier: WebhookVerifier,
}

impl GuestVerifier for LwsVerifier {
    fn new(
        client: ClientBorrow<'_>,
        trusted_storages: Option<Vec<String>>,
    ) -> Result<Verifier, Error> {
        let mut builder =
            WebhookVerifier::builder().client(client.get::<LwsClient>().client.clone());
        if let Some(trusted) = trusted_storages {
            builder = builder.trusted_storages(convert::urls("trusted-storages", &trusted)?);
        }
        Ok(Verifier::new(LwsVerifier {
            verifier: builder.build(),
        }))
    }

    fn verify(
        &self,
        method: String,
        url: String,
        headers: Vec<Header>,
        body: Vec<u8>,
    ) -> Result<VerifiedNotification, Error> {
        let inbox = convert::url("url", &url)?;
        let headers = convert::header_map(&headers)?;
        run(
            self.verifier.verify(&method, &inbox, &headers, &body),
            |verified| VerifiedNotification {
                storage: verified.storage.to_string(),
                key_id: verified.key_id,
                activities: verified
                    .notification
                    .activities
                    .iter()
                    .map(|a| Activity {
                        id: Some(a.id.clone()).filter(|id| !id.is_empty()),
                        types: a.types.clone(),
                        object: a.object.id.clone(),
                        object_types: a.object.types.clone(),
                        actor: a.actor.clone(),
                        target: a.target.clone(),
                        origin: a.origin.clone(),
                        published: a.published_raw.clone(),
                    })
                    .collect(),
                raw: verified.notification.raw.to_string(),
            },
        )
    }
}
