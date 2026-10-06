// SPDX-License-Identifier: MIT
//! Authentication and authorization.
//!
//! * [`Authenticator`] — the pluggable hook the [`Client`](crate::Client) calls before each
//!   request and on `401` responses.
//! * [`BearerTokenAuthenticator`] — sends a known access token.
//! * [`TokenExchangeAuthenticator`] — the LWS flow: `401` challenge (`as_uri`, `realm`) →
//!   authorization server metadata → OAuth 2.0 token exchange with a subject token from a
//!   [`CredentialProvider`] → retry.
//! * Credential providers for the LWS authentication suites: [`OpenIdCredentials`],
//!   [`SamlCredentials`] and (feature `crypto`) [`SelfSignedCredentials`].

mod credentials;
mod exchange;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http::header::AUTHORIZATION;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use url::Url;

use crate::error::{Error, Result};

#[cfg(feature = "crypto")]
pub use credentials::SelfSignedCredentials;
pub use credentials::{
    CredentialContext, CredentialProvider, OpenIdCredentials, SamlCredentials,
    encode_saml_assertion,
};
pub use exchange::{
    AccessToken, AuthorizationServerMetadata, TokenExchangeAuthenticator,
    TokenExchangeAuthenticatorBuilder, TokenResponse, metadata_url, realm_contains,
};

/// A boxed, sendable future (used by the object-safe async traits in this module).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The parts of an outgoing request visible to an [`Authenticator`].
#[derive(Debug, Clone)]
pub struct RequestParts {
    /// Method.
    pub method: Method,
    /// Target URL.
    pub url: Url,
    /// Headers; an authenticator typically inserts `Authorization`.
    pub headers: HeaderMap,
}

/// The parts of a `401` response visible to an [`Authenticator`].
#[derive(Debug, Clone)]
pub struct ResponseParts {
    /// Status (401).
    pub status: StatusCode,
    /// Final response URL.
    pub url: Url,
    /// Response headers (`WWW-Authenticate`, `Link`, …).
    pub headers: HeaderMap,
}

/// Pluggable request authentication.
///
/// Implement this to support other schemes (cookies, DPoP, mTLS, …):
///
/// ```
/// use lws_client::auth::{Authenticator, BoxFuture, RequestParts, ResponseParts};
/// use lws_client::Result;
///
/// struct ApiKey(String);
///
/// impl Authenticator for ApiKey {
///     fn authorize<'a>(&'a self, request: &'a mut RequestParts) -> BoxFuture<'a, Result<()>> {
///         Box::pin(async move {
///             request.headers.insert("x-api-key", self.0.parse().unwrap());
///             Ok(())
///         })
///     }
///     fn handle_challenge<'a>(&'a self, _: &'a RequestParts, _: &'a ResponseParts) -> BoxFuture<'a, Result<bool>> {
///         Box::pin(async { Ok(false) })
///     }
/// }
/// ```
pub trait Authenticator: Send + Sync {
    /// Called before a request is sent; may add credentials to `request.headers`.
    fn authorize<'a>(&'a self, request: &'a mut RequestParts) -> BoxFuture<'a, Result<()>>;

    /// Called when a request returned `401`. Return `true` to retry the request once (after
    /// [`authorize`](Self::authorize) is called again), `false` to surface the `401`.
    fn handle_challenge<'a>(
        &'a self,
        request: &'a RequestParts,
        response: &'a ResponseParts,
    ) -> BoxFuture<'a, Result<bool>>;
}

type TokenSupplier = Arc<dyn Fn() -> BoxFuture<'static, Result<String>> + Send + Sync>;

/// Sends a known bearer access token.
///
/// The token is only attached to URLs inside the optional realm (see [`with_realm`](Self::with_realm)).
#[derive(Clone)]
pub struct BearerTokenAuthenticator {
    token: Option<String>,
    supplier: Option<TokenSupplier>,
    realm: Option<Url>,
}

impl std::fmt::Debug for BearerTokenAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerTokenAuthenticator")
            .field("realm", &self.realm)
            .finish_non_exhaustive()
    }
}

impl BearerTokenAuthenticator {
    /// Uses a fixed token.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: Some(token.into()),
            supplier: None,
            realm: None,
        }
    }

    /// Calls `supplier` for a token before each request (e.g. from your own token cache). On a
    /// `401` the supplier is asked again and the request retried once if the token changed.
    pub fn from_fn<F, Fut>(supplier: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String>> + Send + 'static,
    {
        Self {
            token: None,
            supplier: Some(Arc::new(move || Box::pin(supplier()))),
            realm: None,
        }
    }

    /// Restricts the token to URLs inside `realm` (same origin, path prefix).
    #[must_use]
    pub fn with_realm(mut self, realm: Url) -> Self {
        self.realm = Some(realm);
        self
    }

    async fn current(&self) -> Result<String> {
        match (&self.token, &self.supplier) {
            (Some(t), _) => Ok(t.clone()),
            (None, Some(s)) => s().await,
            (None, None) => Err(Error::authentication("no token")),
        }
    }

    fn applies(&self, url: &Url) -> bool {
        self.realm.as_ref().is_none_or(|r| realm_contains(r, url))
    }
}

pub(crate) fn bearer_header(token: &str) -> Result<HeaderValue> {
    let mut v = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| Error::authentication("token contains invalid characters"))?;
    v.set_sensitive(true);
    Ok(v)
}

impl Authenticator for BearerTokenAuthenticator {
    fn authorize<'a>(&'a self, request: &'a mut RequestParts) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.applies(&request.url) && !request.headers.contains_key(AUTHORIZATION) {
                let token = self.current().await?;
                request
                    .headers
                    .insert(AUTHORIZATION, bearer_header(&token)?);
            }
            Ok(())
        })
    }

    fn handle_challenge<'a>(
        &'a self,
        request: &'a RequestParts,
        _response: &'a ResponseParts,
    ) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move {
            if self.supplier.is_none() || !self.applies(&request.url) {
                return Ok(false);
            }
            let fresh = self.current().await?;
            let sent = request
                .headers
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            Ok(sent != format!("Bearer {fresh}"))
        })
    }
}
