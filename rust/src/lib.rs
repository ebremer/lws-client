// SPDX-License-Identifier: MIT
//! # lws-client
//!
//! An async Rust client for the W3C **Linked Web Storage (LWS) Protocol 1.0** and its companion
//! specifications (authentication suites, webhook notifications, Search and Type Index
//! services), as of the Working Group drafts of 2026-10-05.
//!
//! | Area | Entry points |
//! |---|---|
//! | Discovery | [`Client::discover_storage`], [`Client::get_storage_description`], [`StorageDescription`] |
//! | Read | [`Client::head`], [`Client::read`], [`Client::read_container`], [`Client::list_container`] |
//! | Write | [`Client::create`], [`Client::create_container`], [`Client::update`], [`Client::patch`], [`Client::delete`] |
//! | Metadata | [`Client::read_linkset`], [`Client::patch_linkset`], [`Client::update_linkset`], [`Linkset`] |
//! | Auth | [`TokenExchangeAuthenticator`], [`SelfSignedCredentials`], [`OpenIdCredentials`], [`SamlCredentials`], [`BearerTokenAuthenticator`] |
//! | Notifications | [`Client::subscribe`], [`WebhookVerifier`], [`Notification`] |
//! | Access | [`Client::request_access`], [`Client::grant_access`], [`AccessRequest`], [`AccessGrant`] |
//! | Type search | [`Client::list_types`], [`Client::search_types`], [`Client::search_all`], [`TypeQuery`] |
//!
//! ## Quick start
//!
#![cfg_attr(feature = "crypto", doc = "```no_run")]
#![cfg_attr(not(feature = "crypto"), doc = "```ignore")]
//! use futures_util::TryStreamExt;
//! use lws_client::{Client, JsonPatch, SelfSignedCredentials, TokenExchangeAuthenticator, crypto::SigningKey};
//!
//! # async fn run() -> lws_client::Result<()> {
//! // A bot identity: a did:key derived from a fresh P-256 key.
//! let credentials = SelfSignedCredentials::did_key(SigningKey::generate_p256()?);
//! let client = Client::builder()
//!     .authenticator(TokenExchangeAuthenticator::new(credentials))
//!     .build()?;
//!
//! // 401 → authorization server metadata → token exchange → retry, all automatic.
//! let storage = client.discover_storage("https://storage.example/root/").await?;
//! let root = storage.storage_root()?.clone();
//!
//! let notes = client.create_container(&root).slug("notes").await?.location;
//! let profile = client
//!     .create_json(&notes, &serde_json::json!({"name": "Alice", "age": 30}))
//!     .slug("profile.json")
//!     .resource_type("https://schema.org/Person")
//!     .await?
//!     .location;
//!
//! let current = client.read(&profile).await?;
//! client
//!     .patch(&profile, &JsonPatch::new().replace("/age", 31))
//!     .if_match(current.metadata.etag.as_deref().unwrap_or("*"))
//!     .await?;
//!
//! let mut members = client.list_container(&notes);
//! while let Some(item) = members.try_next().await? {
//!     println!("{} {:?}", item.id, item.types);
//! }
//! client.delete(&notes).recursive(true).await?;
//! # Ok(()) }
//! ```
//!
//! Every request builder can be awaited directly (it implements [`std::future::IntoFuture`])
//! or via `.send()`.
//!
//! ## Errors
//!
//! HTTP failures map to one [`Error`] variant per LWS response (`NotFound`, `Conflict`,
//! `PreconditionFailed`, …) carrying the full [`HttpError`] and any RFC 9457
//! [`ProblemDetails`](headers::ProblemDetails).
//!
//! ## Features
//!
//! * `rustls` (default) / `native-tls` — TLS backend.
//! * `crypto` (default) — self-signed credentials, did:key/JWK helpers and the webhook verifier.
//!
//! ## WebAssembly
//!
//! For `wasm32-wasip2` (WASI 0.2) the crate sends its requests through the host's `wasi:http`
//! instead of `reqwest`: the host does TLS, the TLS features have no effect, request bodies are
//! bytes, and [`Error::Transport`] carries a `TransportError`. The `wasm` directory of the
//! repository builds the client into a WebAssembly component.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod access;
pub mod auth;
mod client;
pub mod constants;
#[cfg(feature = "crypto")]
pub mod crypto;
pub mod datetime;
mod error;
pub mod headers;
pub mod index;
pub mod model;
pub mod notification;
mod patch;
mod transport;
pub mod types;
#[cfg(feature = "crypto")]
pub mod webhook;

pub use access::{AccessGrant, AccessPolicy, AccessRequest, AccessTarget, Constraint};
#[cfg(feature = "crypto")]
pub use auth::SelfSignedCredentials;
pub use auth::{
    Authenticator, BearerTokenAuthenticator, CredentialContext, CredentialProvider,
    OpenIdCredentials, SamlCredentials, TokenExchangeAuthenticator,
};
pub use client::{
    Body, Client, ClientBuilder, CreateRequest, DeleteRequest, HeadRequest, IntoUrl, LwsStream,
    PatchRequest, ReadRequest, UpdateRequest,
};
#[cfg(target_os = "wasi")]
pub use error::TransportError;
pub use error::{Error, HttpError, Result};
pub use headers::Link;
pub use index::{SearchPage, TypeIndexPage, TypeQuery};
pub use model::{
    ContainedResource, ContainerPage, CreateResult, Linkset, LinksetDocument, Resource,
    ResourceMetadata, Service, StorageDescription, UpdateResult,
};
pub use notification::{
    Activity, Notification, Subscription, WebhookSubscriptionRequest, parse_notification,
};
pub use patch::{JsonPatch, JsonPointer, PatchOperation};
#[cfg(feature = "crypto")]
pub use webhook::{VerifiedNotification, WebhookVerifier};

pub use url::Url;
