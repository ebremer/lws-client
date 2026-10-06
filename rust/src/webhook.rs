// SPDX-License-Identifier: MIT
//! Verification of signed webhook deliveries (LWS webhook notification suite): RFC 9421 HTTP
//! Message Signatures and RFC 9530 `Content-Digest`, with the signing key discovered from the
//! storage description.
//!
//! Requires the `crypto` feature (enabled by default).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use http::HeaderMap;
use sha2::Digest as _;
use url::Url;

use crate::client::Client;
use crate::crypto::{Jwk, KeyAlgorithm, VerifyingKey};
use crate::datetime::from_unix_seconds;
use crate::error::{Error, Result};
use crate::headers::structured::{BareItem, Dictionary, InnerList, MemberValue, parse_dictionary};
use crate::model::StorageDescription;
use crate::notification::Notification;

/// Components every LWS webhook signature must cover.
pub const REQUIRED_COMPONENTS: [&str; 6] = [
    "@method",
    "@scheme",
    "@authority",
    "@path",
    "content-type",
    "content-digest",
];

fn fail<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::SignatureVerification(msg.into()))
}

/// A successfully verified delivery.
#[derive(Debug, Clone)]
pub struct VerifiedNotification {
    /// The notification.
    pub notification: Notification,
    /// The `keyid` that signed it.
    pub key_id: String,
    /// The storage identifier the key belongs to.
    pub storage: Url,
    /// The signature label (e.g. `sig1`).
    pub label: String,
}

type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

struct Cached {
    description: Arc<StorageDescription>,
    fetched: Instant,
}

/// Verifies webhook deliveries.
///
/// ```no_run
/// use lws_client::{Client, WebhookVerifier};
/// # async fn run(headers: http::HeaderMap, body: Vec<u8>) -> lws_client::Result<()> {
/// let verifier = WebhookVerifier::builder()
///     .client(Client::new())
///     .trusted_storage(url::Url::parse("https://storage.example/").unwrap())
///     .build();
/// let inbox = url::Url::parse("https://receiver.example/hooks/lws").unwrap();
/// let verified = verifier.verify("POST", &inbox, &headers, &body).await?;
/// for activity in &verified.notification.activities {
///     println!("{:?} {}", activity.types, activity.object.id);
/// }
/// # Ok(()) }
/// ```
pub struct WebhookVerifier {
    client: Client,
    max_age: Duration,
    clock_skew: Duration,
    trusted: Option<Vec<Url>>,
    cache_ttl: Duration,
    pinned: HashMap<Url, Arc<StorageDescription>>,
    cache: Mutex<HashMap<Url, Cached>>,
    clock: Clock,
}

impl fmt::Debug for WebhookVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookVerifier")
            .field("max_age", &self.max_age)
            .field("clock_skew", &self.clock_skew)
            .field("trusted", &self.trusted)
            .finish_non_exhaustive()
    }
}

/// Builder for [`WebhookVerifier`].
pub struct WebhookVerifierBuilder {
    client: Option<Client>,
    max_age: Duration,
    clock_skew: Duration,
    trusted: Option<Vec<Url>>,
    cache_ttl: Duration,
    pinned: HashMap<Url, Arc<StorageDescription>>,
    clock: Clock,
}

impl WebhookVerifierBuilder {
    /// Client used to fetch storage descriptions (default: an anonymous client).
    #[must_use]
    pub fn client(mut self, client: Client) -> Self {
        self.client = Some(client);
        self
    }
    /// Maximum age of the `created` parameter (default 300 s).
    #[must_use]
    pub fn max_age(mut self, d: Duration) -> Self {
        self.max_age = d;
        self
    }
    /// Tolerated clock skew for signatures created in the future (default 300 s).
    #[must_use]
    pub fn clock_skew(mut self, d: Duration) -> Self {
        self.clock_skew = d;
        self
    }
    /// Only accept deliveries signed by keys of this storage (may be called repeatedly).
    #[must_use]
    pub fn trusted_storage(mut self, storage: Url) -> Self {
        self.trusted.get_or_insert_with(Vec::new).push(storage);
        self
    }
    /// Only accept deliveries signed by keys of these storages.
    #[must_use]
    pub fn trusted_storages(mut self, storages: impl IntoIterator<Item = Url>) -> Self {
        self.trusted.get_or_insert_with(Vec::new).extend(storages);
        self
    }
    /// How long fetched storage descriptions are cached (default 10 min).
    #[must_use]
    pub fn key_cache_ttl(mut self, d: Duration) -> Self {
        self.cache_ttl = d;
        self
    }
    /// Uses a fixed storage description instead of fetching it (offline use, tests).
    #[must_use]
    pub fn storage_description(mut self, description: StorageDescription) -> Self {
        self.pinned
            .insert(description.id.clone(), Arc::new(description));
        self
    }
    /// Replaces the clock (tests).
    #[must_use]
    pub fn clock<F>(mut self, clock: F) -> Self
    where
        F: Fn() -> SystemTime + Send + Sync + 'static,
    {
        self.clock = Arc::new(clock);
        self
    }
    /// Builds the verifier.
    pub fn build(self) -> WebhookVerifier {
        WebhookVerifier {
            client: self.client.unwrap_or_default(),
            max_age: self.max_age,
            clock_skew: self.clock_skew,
            trusted: self.trusted,
            cache_ttl: self.cache_ttl,
            pinned: self.pinned,
            cache: Mutex::new(HashMap::new()),
            clock: self.clock,
        }
    }
}

/// The parsed, time-checked signature of a delivery.
struct Prepared {
    label: String,
    key_id: String,
    storage: Url,
    alg: Option<String>,
    base: String,
    signature: Vec<u8>,
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let values: Vec<&str> = headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::trim)
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(values.join(", "))
    }
}

/// Builds an RFC 9421 signature base for the covered components of `params`.
pub fn signature_base(
    method: &str,
    url: &Url,
    headers: &HeaderMap,
    params: &InnerList,
) -> Result<String> {
    let mut lines = Vec::with_capacity(params.items.len() + 1);
    for item in &params.items {
        let Some(name) = item.value.as_str() else {
            return fail("covered component is not a string");
        };
        if !item.params.is_empty() {
            return fail(format!("unsupported component parameters on {name:?}"));
        }
        let value = match name {
            "@method" => method.to_ascii_uppercase(),
            "@scheme" => url.scheme().to_ascii_lowercase(),
            "@authority" => {
                let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
                match url.port() {
                    Some(p) => format!("{host}:{p}"),
                    None => host,
                }
            }
            "@path" => {
                let p = url.path();
                if p.is_empty() {
                    "/".into()
                } else {
                    p.to_owned()
                }
            }
            "@query" => format!("?{}", url.query().unwrap_or("")),
            "@target-uri" => url.as_str().to_owned(),
            "@request-target" => match url.query() {
                Some(q) => format!("{}?{q}", url.path()),
                None => url.path().to_owned(),
            },
            n if n.starts_with('@') => return fail(format!("unsupported derived component {n}")),
            n => match header_value(headers, n) {
                Some(v) => v,
                None => return fail(format!("covered header {n} is missing")),
            },
        };
        lines.push(format!("\"{name}\": {value}"));
    }
    lines.push(format!("\"@signature-params\": {}", params.serialize()));
    Ok(lines.join("\n"))
}

fn check_content_digest(headers: &HeaderMap, body: &[u8]) -> Result<()> {
    let Some(raw) = header_value(headers, "content-digest") else {
        return fail("missing Content-Digest");
    };
    let dict = parse_dictionary(&raw)
        .map_err(|e| Error::SignatureVerification(format!("invalid Content-Digest: {e}")))?;
    let mut recognised = 0;
    for (alg, value) in dict.iter() {
        let expected: Vec<u8> = match alg {
            "sha-256" => sha2::Sha256::digest(body).to_vec(),
            "sha-512" => sha2::Sha512::digest(body).to_vec(),
            _ => continue,
        };
        recognised += 1;
        let MemberValue::Item(item) = value else {
            return fail("invalid Content-Digest value");
        };
        if item.value.as_bytes() != Some(expected.as_slice()) {
            return fail(format!("content-digest mismatch ({alg})"));
        }
    }
    if recognised == 0 {
        return fail("Content-Digest has no supported algorithm (sha-256, sha-512)");
    }
    Ok(())
}

impl WebhookVerifier {
    /// A verifier that fetches storage descriptions with `client`.
    pub fn new(client: Client) -> Self {
        Self::builder().client(client).build()
    }

    /// A builder.
    pub fn builder() -> WebhookVerifierBuilder {
        WebhookVerifierBuilder {
            client: None,
            max_age: Duration::from_secs(300),
            clock_skew: Duration::from_secs(300),
            trusted: None,
            cache_ttl: Duration::from_secs(600),
            pinned: HashMap::new(),
            clock: Arc::new(SystemTime::now),
        }
    }

    fn prepare(
        &self,
        method: &str,
        inbox_url: &Url,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Prepared> {
        check_content_digest(headers, body)?;
        let input = header_value(headers, "signature-input")
            .ok_or_else(|| Error::SignatureVerification("missing Signature-Input".into()))?;
        let sigs = header_value(headers, "signature")
            .ok_or_else(|| Error::SignatureVerification("missing Signature".into()))?;
        let input: Dictionary = parse_dictionary(&input)
            .map_err(|e| Error::SignatureVerification(format!("invalid Signature-Input: {e}")))?;
        let sigs: Dictionary = parse_dictionary(&sigs)
            .map_err(|e| Error::SignatureVerification(format!("invalid Signature: {e}")))?;
        let chosen = input.iter().find_map(|(label, member)| {
            let MemberValue::InnerList(list) = member else {
                return None;
            };
            list.params.get("keyid")?.as_str()?;
            let MemberValue::Item(sig) = sigs.get(label)? else {
                return None;
            };
            Some((
                label.to_owned(),
                list.clone(),
                sig.value.as_bytes()?.to_vec(),
            ))
        });
        let Some((label, params, signature)) = chosen else {
            return fail("no signature with a keyid");
        };
        let covered: Vec<&str> = params
            .items
            .iter()
            .filter_map(|i| i.value.as_str())
            .collect();
        for required in REQUIRED_COMPONENTS {
            if !covered.contains(&required) {
                return fail(format!("required component {required} not covered"));
            }
        }
        let Some(created) = params.params.get("created").and_then(BareItem::as_integer) else {
            return fail("signature has no created parameter");
        };
        let now = (self.clock)();
        let created_at = from_unix_seconds(created);
        if created_at + self.max_age < now {
            return fail("signature too old");
        }
        if created_at > now + self.clock_skew {
            return fail("signature created in the future");
        }
        if let Some(expires) = params.params.get("expires").and_then(BareItem::as_integer) {
            if from_unix_seconds(expires) < now {
                return fail("signature expired");
            }
        }
        let key_id = params
            .params
            .get("keyid")
            .and_then(BareItem::as_str)
            .unwrap_or_default()
            .to_owned();
        let Some((storage, fragment)) = key_id.split_once('#') else {
            return fail("keyid is not a URL with a fragment");
        };
        if fragment.is_empty() {
            return fail("keyid has an empty fragment");
        }
        let storage = Url::parse(storage)
            .map_err(|_| Error::SignatureVerification(format!("keyid {key_id:?} is not a URL")))?;
        if let Some(trusted) = &self.trusted {
            if !trusted.contains(&storage) {
                return fail(format!("storage {storage} is not trusted"));
            }
        }
        let alg = params
            .params
            .get("alg")
            .and_then(BareItem::as_str)
            .map(str::to_owned);
        let base = signature_base(method, inbox_url, headers, &params)?;
        Ok(Prepared {
            label,
            key_id,
            storage,
            alg,
            base,
            signature,
        })
    }

    fn check_with(
        &self,
        prepared: &Prepared,
        description: &StorageDescription,
        body: &[u8],
    ) -> Result<VerifiedNotification> {
        if description.id != prepared.storage {
            return fail(format!(
                "storage description id {} does not match {}",
                description.id, prepared.storage
            ));
        }
        let Some(vm) = description.verification_method(&prepared.key_id) else {
            return fail(format!("verification method {} not found", prepared.key_id));
        };
        if !description.is_authentication_method(vm) {
            return fail(format!(
                "key {} is not authorized for authentication",
                prepared.key_id
            ));
        }
        let Some(jwk) = &vm.public_key_jwk else {
            return fail("verification method has no publicKeyJwk");
        };
        let jwk = Jwk::from_json(&serde_json::Value::Object(jwk.clone()))
            .map_err(|e| Error::SignatureVerification(e.to_string()))?;
        let key = VerifyingKey::from_jwk(&jwk)
            .map_err(|e| Error::SignatureVerification(e.to_string()))?;
        if let Some(alg) = &prepared.alg {
            let expected = key.algorithm().http_signature_alg();
            if alg != expected {
                return fail(format!(
                    "alg {alg} does not match the {:?} key",
                    key.algorithm()
                ));
            }
        }
        if !matches!(key.algorithm(), KeyAlgorithm::P256 | KeyAlgorithm::Ed25519)
            || !key.verify(prepared.base.as_bytes(), &prepared.signature)
        {
            return fail("signature mismatch");
        }
        let notification = Notification::parse(body)
            .map_err(|e| Error::SignatureVerification(format!("invalid notification: {e}")))?;
        let claimed = Url::parse(&notification.storage).map_err(|_| {
            Error::SignatureVerification("notification storage is not a URL".into())
        })?;
        if claimed != prepared.storage {
            return fail(format!(
                "notification storage {claimed} does not match keyid storage {}",
                prepared.storage
            ));
        }
        Ok(VerifiedNotification {
            notification,
            key_id: prepared.key_id.clone(),
            storage: prepared.storage.clone(),
            label: prepared.label.clone(),
        })
    }

    /// Verifies a delivery against a known storage description (no network access).
    pub fn verify_with_description(
        &self,
        method: &str,
        inbox_url: &Url,
        headers: &HeaderMap,
        body: &[u8],
        description: &StorageDescription,
    ) -> Result<VerifiedNotification> {
        let prepared = self.prepare(method, inbox_url, headers, body)?;
        self.check_with(&prepared, description, body)
    }

    async fn description(
        &self,
        storage: &Url,
        refresh: bool,
    ) -> Result<(Arc<StorageDescription>, bool)> {
        if let Some(d) = self.pinned.get(storage) {
            return Ok((d.clone(), false));
        }
        if !refresh {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(c) = cache.get(storage) {
                if c.fetched.elapsed() < self.cache_ttl {
                    return Ok((c.description.clone(), true));
                }
            }
        }
        let d = Arc::new(
            self.client
                .get_storage_description(storage.clone())
                .await
                .map_err(|e| {
                    Error::SignatureVerification(format!("cannot fetch storage description: {e}"))
                })?,
        );
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).insert(
            storage.clone(),
            Cached {
                description: d.clone(),
                fetched: Instant::now(),
            },
        );
        Ok((d, false))
    }

    /// Verifies a delivery. `inbox_url` is the inbox URL as registered in the subscription (so
    /// verification works behind proxies); `body` is the raw request body.
    pub async fn verify(
        &self,
        method: &str,
        inbox_url: &Url,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<VerifiedNotification> {
        let prepared = self.prepare(method, inbox_url, headers, body)?;
        let (description, from_cache) = self.description(&prepared.storage, false).await?;
        match self.check_with(&prepared, &description, body) {
            Err(Error::SignatureVerification(msg))
                if from_cache
                    && (msg == "signature mismatch" || msg.starts_with("verification method")) =>
            {
                // Possibly a rotated key: refetch once.
                let (fresh, _) = self.description(&prepared.storage, true).await?;
                self.check_with(&prepared, &fresh, body)
            }
            other => other,
        }
    }

    /// Verifies an [`http::Request`] delivered to `inbox_url`.
    pub async fn verify_request<B: AsRef<[u8]>>(
        &self,
        inbox_url: &Url,
        request: &http::Request<B>,
    ) -> Result<VerifiedNotification> {
        self.verify(
            request.method().as_str(),
            inbox_url,
            request.headers(),
            request.body().as_ref(),
        )
        .await
    }
}
