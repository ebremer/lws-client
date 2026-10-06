// SPDX-License-Identifier: MIT
//! Credential providers for the LWS authentication suites.

use std::future::Future;
use std::sync::Arc;

use base64::Engine as _;

use super::{AuthorizationServerMetadata, BoxFuture};
use crate::constants::oauth;
use crate::error::Result;

/// What a [`CredentialProvider`] knows about the token exchange it is serving.
#[derive(Debug, Clone)]
pub struct CredentialContext {
    /// The authorization server's issuer identifier (use it as the token audience).
    pub issuer: String,
    /// The protection realm (the storage the access token will be valid for).
    pub realm: String,
    /// The authorization server metadata.
    pub metadata: Arc<AuthorizationServerMetadata>,
}

/// Supplies the subject token (an LWS authentication credential) for OAuth 2.0 token exchange.
pub trait CredentialProvider: Send + Sync {
    /// The RFC 8693 `subject_token_type`.
    fn token_type(&self) -> &str;

    /// Returns a subject token for the given authorization server.
    fn subject_token<'a>(&'a self, context: &'a CredentialContext)
    -> BoxFuture<'a, Result<String>>;
}

type TokenFn = Arc<dyn Fn(CredentialContext) -> BoxFuture<'static, Result<String>> + Send + Sync>;

fn fixed(token: String) -> TokenFn {
    Arc::new(move |_| {
        let t = token.clone();
        Box::pin(async move { Ok(t) })
    })
}

fn wrap<F, Fut>(f: F) -> TokenFn
where
    F: Fn(CredentialContext) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<String>> + Send + 'static,
{
    Arc::new(move |ctx| Box::pin(f(ctx)))
}

/// OpenID Connect authentication suite: an ID token used as the subject token
/// (`urn:ietf:params:oauth:token-type:id_token`).
///
/// Interactive login is out of scope — obtain the ID token with your OIDC library and pass it
/// here (or a callback returning a fresh one). The token's `aud` should include the
/// authorization server.
#[derive(Clone)]
pub struct OpenIdCredentials {
    source: TokenFn,
}

impl std::fmt::Debug for OpenIdCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpenIdCredentials")
    }
}

impl OpenIdCredentials {
    /// Uses a fixed ID token.
    pub fn new(id_token: impl Into<String>) -> Self {
        Self {
            source: fixed(id_token.into()),
        }
    }
    /// Calls `f` for a (fresh) ID token for each token exchange.
    pub fn from_fn<F, Fut>(f: F) -> Self
    where
        F: Fn(CredentialContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String>> + Send + 'static,
    {
        Self { source: wrap(f) }
    }
}

impl CredentialProvider for OpenIdCredentials {
    fn token_type(&self) -> &str {
        oauth::TOKEN_TYPE_ID_TOKEN
    }
    fn subject_token<'a>(
        &'a self,
        context: &'a CredentialContext,
    ) -> BoxFuture<'a, Result<String>> {
        (self.source)(context.clone())
    }
}

/// Base64url-encodes (no padding) a SAML 2.0 assertion for use as a subject token (RFC 8693 §3).
pub fn encode_saml_assertion(xml: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(xml)
}

/// SAML 2.0 authentication suite: a signed SAML assertion used as the subject token
/// (`urn:ietf:params:oauth:token-type:saml2`, base64url-encoded).
#[derive(Clone)]
pub struct SamlCredentials {
    source: TokenFn,
}

impl std::fmt::Debug for SamlCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SamlCredentials")
    }
}

impl SamlCredentials {
    /// Uses an already base64url-encoded assertion.
    pub fn new(encoded_assertion: impl Into<String>) -> Self {
        Self {
            source: fixed(encoded_assertion.into()),
        }
    }
    /// Uses a raw XML assertion (encoded for you).
    pub fn from_xml(xml: impl AsRef<[u8]>) -> Self {
        Self::new(encode_saml_assertion(xml.as_ref()))
    }
    /// Calls `f` for a (fresh, base64url-encoded) assertion for each token exchange.
    pub fn from_fn<F, Fut>(f: F) -> Self
    where
        F: Fn(CredentialContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String>> + Send + 'static,
    {
        Self { source: wrap(f) }
    }
}

impl CredentialProvider for SamlCredentials {
    fn token_type(&self) -> &str {
        oauth::TOKEN_TYPE_SAML2
    }
    fn subject_token<'a>(
        &'a self,
        context: &'a CredentialContext,
    ) -> BoxFuture<'a, Result<String>> {
        (self.source)(context.clone())
    }
}

#[cfg(feature = "crypto")]
pub use self_signed::SelfSignedCredentials;

#[cfg(feature = "crypto")]
mod self_signed {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    use serde_json::{Map, Value, json};

    use super::*;
    use crate::crypto::{SigningKey, jwt, uuid_v4};
    use crate::datetime::unix_seconds;

    /// Self-signed identity (`lws10-authn-ssi-cid`, and did:key subjects): the agent signs its
    /// own JWT (`urn:ietf:params:oauth:token-type:jwt`) with
    /// `sub = iss = client_id = <agent>`, `aud = [<authorization server>]`.
    ///
    /// ```
    /// use lws_client::{SelfSignedCredentials, crypto::SigningKey};
    /// let creds = SelfSignedCredentials::did_key(SigningKey::generate_p256()?);
    /// assert!(creds.agent().starts_with("did:key:zDn"));
    /// let jwt = creds.create_token("https://as.example")?;
    /// assert_eq!(jwt.split('.').count(), 3);
    /// # Ok::<(), lws_client::Error>(())
    /// ```
    pub struct SelfSignedCredentials {
        agent: String,
        kid: String,
        key: SigningKey,
        lifetime: Duration,
        cache: Mutex<HashMap<String, (String, SystemTime)>>,
    }

    impl std::fmt::Debug for SelfSignedCredentials {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SelfSignedCredentials")
                .field("agent", &self.agent)
                .field("kid", &self.kid)
                .finish_non_exhaustive()
        }
    }

    impl SelfSignedCredentials {
        /// An agent identified by `agent` (an HTTPS URI or DID) whose controlled identifier
        /// document lists the key under `kid`.
        pub fn for_agent(
            agent: impl Into<String>,
            key: SigningKey,
            kid: impl Into<String>,
        ) -> Self {
            Self {
                agent: agent.into(),
                kid: kid.into(),
                key,
                lifetime: Duration::from_secs(300),
                cache: Mutex::new(HashMap::new()),
            }
        }

        /// An agent identified by the `did:key` derived from `key` (kid `did:key:z…#z…`).
        pub fn did_key(key: SigningKey) -> Self {
            let d = key.did_key();
            Self::for_agent(d.did, key, d.kid)
        }

        /// Sets the token lifetime (default 300 s).
        #[must_use]
        pub fn with_lifetime(mut self, lifetime: Duration) -> Self {
            self.lifetime = lifetime;
            self
        }

        /// The agent identifier (`sub`, `iss`, `client_id`).
        pub fn agent(&self) -> &str {
            &self.agent
        }

        /// The key id placed in the JWT header.
        pub fn kid(&self) -> &str {
            &self.kid
        }

        /// The signing key.
        pub fn key(&self) -> &SigningKey {
            &self.key
        }

        /// Creates a fresh signed credential for `audience` (the authorization server).
        pub fn create_token(&self, audience: &str) -> Result<String> {
            let now = SystemTime::now();
            let iat = unix_seconds(now);
            let claims = json!({
                "sub": self.agent,
                "iss": self.agent,
                "client_id": self.agent,
                "aud": [audience],
                "iat": iat,
                "exp": iat + self.lifetime.as_secs() as i64,
                "jti": uuid_v4()?,
            });
            let mut header = Map::new();
            header.insert("kid".into(), Value::String(self.kid.clone()));
            jwt::sign(&header, &claims, &self.key)
        }

        fn cached_token(&self, audience: &str) -> Result<String> {
            let now = SystemTime::now();
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((token, expires)) = cache.get(audience) {
                if *expires > now + Duration::from_secs(60) {
                    return Ok(token.clone());
                }
            }
            let token = self.create_token(audience)?;
            cache.insert(audience.to_owned(), (token.clone(), now + self.lifetime));
            Ok(token)
        }
    }

    impl CredentialProvider for SelfSignedCredentials {
        fn token_type(&self) -> &str {
            oauth::TOKEN_TYPE_JWT
        }
        fn subject_token<'a>(
            &'a self,
            context: &'a CredentialContext,
        ) -> BoxFuture<'a, Result<String>> {
            Box::pin(async move { self.cached_token(&context.issuer) })
        }
    }
}
