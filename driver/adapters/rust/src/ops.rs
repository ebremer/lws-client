// SPDX-License-Identifier: MIT
//! The operations of driver/PROTOCOL.md section 4, each a call of the library's own operation
//! with the library's own options.

use std::time::Duration;

use futures_util::TryStreamExt as _;
use http::{HeaderMap, HeaderName, HeaderValue};
use lws_client::auth::TokenExchangeAuthenticatorBuilder;
use lws_client::crypto::{Jwk, KeyAlgorithm, SigningKey};
use lws_client::{
    AccessGrant, AccessRequest, BearerTokenAuthenticator, Client, Link, Linkset, LwsStream,
    OpenIdCredentials, SelfSignedCredentials, TokenExchangeAuthenticator,
    WebhookSubscriptionRequest, WebhookVerifier,
};
use serde_json::{Map, Value, json};

use crate::args::{
    self, limit, optional_array, optional_bool, optional_index, optional_object, optional_positive,
    optional_str, required_array, required_object, required_str,
};
use crate::errors::Failure;
use crate::results::{self, Object};
use crate::{Args, LIBRARY};

type Result<T> = std::result::Result<T, Failure>;

/// Every operation this adapter implements, in the order of PROTOCOL.md section 4.
pub(crate) const OPERATIONS: &[&str] = &[
    "configure",
    "discover_storage",
    "get_storage_description",
    "head",
    "read",
    "read_container",
    "list_container",
    "create",
    "create_container",
    "update",
    "patch",
    "delete",
    "linkset_url",
    "read_linkset",
    "update_linkset",
    "patch_linkset",
    "subscribe",
    "list_subscriptions",
    "get_subscription",
    "unsubscribe",
    "verify_notification",
    "request_access",
    "get_access_request",
    "list_access_requests",
    "cancel_access_request",
    "grant_access",
    "get_access_grant",
    "list_access_grants",
    "revoke_access_grant",
    "read_type_index",
    "list_types",
    "search_types",
    "search_all",
    "accepted_query_formats",
    "shutdown",
];

/// Pulls at most `limit + 1` items from a lazy sequence: the first `limit`, and whether there
/// was one more.
async fn take<T>(mut stream: LwsStream<T>, limit: usize) -> Result<(Vec<T>, bool)> {
    let mut items = Vec::new();
    while let Some(item) = stream.try_next().await? {
        if items.len() == limit {
            return Ok((items, true));
        }
        items.push(item);
    }
    Ok((items, false))
}

async fn take_items(
    stream: LwsStream<lws_client::ContainedResource>,
    args: &Args,
) -> Result<Value> {
    let (items, truncated) = take(stream, limit(args)?).await?;
    Ok(json!({"items": results::items(&items), "truncated": truncated}))
}

/// The adapter's state: the client every operation uses.
pub(crate) struct State {
    client: Client,
}

impl State {
    /// Before the first `configure`, a client with no authenticator.
    pub(crate) fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    /// Runs one operation of [`OPERATIONS`].
    pub(crate) async fn run(&mut self, op: &str, args: &Args) -> Result<Value> {
        let c = &self.client;
        match op {
            "configure" => {
                let (client, result) = configure(args).await?;
                self.client = client;
                Ok(result)
            }
            "discover_storage" => Ok(results::storage(
                &c.discover_storage(required_str(args, "url")?).await?,
            )),
            "get_storage_description" => Ok(results::storage(
                &c.get_storage_description(required_str(args, "url")?)
                    .await?,
            )),
            "head" => Ok(results::metadata(
                &c.head(required_str(args, "url")?).await?,
            )),
            "read" => read(c, args).await,
            "read_container" => Ok(results::container_page(
                &c.read_container(required_str(args, "url")?).await?,
            )),
            "list_container" => {
                take_items(c.list_container(required_str(args, "url")?), args).await
            }
            "create" => create(c, args).await,
            "create_container" => {
                let mut request = c.create_container(required_str(args, "parent")?);
                if let Some(slug) = optional_str(args, "slug")? {
                    request = request.slug(slug);
                }
                Ok(results::created(&request.await?))
            }
            "update" => update(c, args).await,
            "patch" => {
                let url = required_str(args, "url")?;
                let patch = args::patch(args.get("patch"))?;
                let mut request = c.patch(url, &patch);
                if let Some(etag) = optional_str(args, "ifMatch")? {
                    request = request.if_match(etag);
                }
                Ok(results::update(&request.await?))
            }
            "delete" => {
                let mut request = c.delete(required_str(args, "url")?);
                if let Some(etag) = optional_str(args, "ifMatch")? {
                    request = request.if_match(etag);
                }
                if optional_bool(args, "recursive")? == Some(true) {
                    request = request.recursive(true);
                }
                request.await?;
                Ok(json!({}))
            }
            "linkset_url" => Ok(
                json!({"linkset": results::url(&c.linkset_url(required_str(args, "url")?).await?)}),
            ),
            "read_linkset" => {
                let doc = c.read_linkset(required_str(args, "url")?).await?;
                Ok(Object::new()
                    .set("url", results::url(&doc.url))
                    .opt("etag", doc.etag.clone())
                    .set("linkset", doc.linkset.to_json())
                    .set("allow", doc.allow.clone())
                    .set("acceptPatch", doc.accept_patch.clone())
                    .into())
            }
            "update_linkset" => {
                let url = required_str(args, "linksetUrl")?;
                let linkset = args::document("linkset", required_object(args, "linkset")?, |v| {
                    Linkset::from_json(&v)
                })?;
                let mut request = c.update_linkset(url, &linkset);
                if let Some(etag) = optional_str(args, "ifMatch")? {
                    request = request.if_match(etag);
                }
                Ok(results::update(&request.await?))
            }
            "patch_linkset" => {
                let url = required_str(args, "linksetUrl")?;
                let patch = args::patch(args.get("patch"))?;
                let mut request = c.patch_linkset(url, &patch);
                if let Some(etag) = optional_str(args, "ifMatch")? {
                    request = request.if_match(etag);
                }
                Ok(results::update(&request.await?))
            }
            "subscribe" => {
                let service = required_str(args, "serviceUrl")?;
                let topics = args::urls("topics", required_array(args, "topics")?)?;
                let inbox = args::url("inbox", required_str(args, "inbox")?)?;
                let mut request = WebhookSubscriptionRequest::new(topics, inbox);
                if let Some(expires) = optional_str(args, "expires")? {
                    request = request.expires_raw(expires);
                }
                Ok(results::subscription(
                    &c.subscribe(service, &request).await?,
                ))
            }
            "list_subscriptions" => {
                take_items(
                    c.list_subscriptions(required_str(args, "serviceUrl")?),
                    args,
                )
                .await
            }
            "get_subscription" => Ok(results::subscription(
                &c.get_subscription(required_str(args, "url")?).await?,
            )),
            "unsubscribe" => {
                c.unsubscribe(required_str(args, "url")?).await?;
                Ok(json!({}))
            }
            "verify_notification" => verify_notification(c, args).await,
            "request_access" => {
                let service = required_str(args, "serviceUrl")?;
                let request = args::document(
                    "request",
                    required_object(args, "request")?,
                    AccessRequest::from_json,
                )?;
                let location = c.request_access(service, &request).await?;
                Ok(json!({"location": results::url(&location)}))
            }
            "get_access_request" => Ok(
                json!({"document": c.get_access_request(required_str(args, "url")?).await?.to_json()}),
            ),
            "list_access_requests" => {
                take_items(
                    c.list_access_requests(required_str(args, "serviceUrl")?),
                    args,
                )
                .await
            }
            "cancel_access_request" => {
                c.cancel_access_request(required_str(args, "url")?).await?;
                Ok(json!({}))
            }
            "grant_access" => {
                let service = required_str(args, "serviceUrl")?;
                let grant = args::document(
                    "grant",
                    required_object(args, "grant")?,
                    AccessGrant::from_json,
                )?;
                let location = c.grant_access(service, &grant).await?;
                Ok(json!({"location": results::url(&location)}))
            }
            "get_access_grant" => Ok(
                json!({"document": c.get_access_grant(required_str(args, "url")?).await?.to_json()}),
            ),
            "list_access_grants" => {
                take_items(
                    c.list_access_grants(required_str(args, "serviceUrl")?),
                    args,
                )
                .await
            }
            "revoke_access_grant" => {
                c.revoke_access_grant(required_str(args, "url")?).await?;
                Ok(json!({}))
            }
            "read_type_index" => {
                let page = c.read_type_index(required_str(args, "url")?).await?;
                let link = |u: &Option<lws_client::Url>| u.as_ref().map(results::url);
                Ok(Object::new()
                    .opt("totalItems", page.total_items)
                    .set("types", page.types.clone())
                    .opt("first", link(&page.first))
                    .opt("next", link(&page.next))
                    .opt("prev", link(&page.prev))
                    .opt("last", link(&page.last))
                    .into())
            }
            "list_types" => {
                let stream = c.list_types(required_str(args, "serviceUrl")?);
                let (types, truncated) = take(stream, limit(args)?).await?;
                Ok(json!({"types": types, "truncated": truncated}))
            }
            "search_types" => {
                let service = required_str(args, "serviceUrl")?;
                let query = args::query(required_object(args, "query")?)?;
                Ok(results::search_page(
                    &c.search_types(service, &query).await?,
                ))
            }
            "search_all" => {
                let service = required_str(args, "serviceUrl")?;
                let query = args::query(required_object(args, "query")?)?;
                take_items(c.search_all(service, &query), args).await
            }
            "accepted_query_formats" => Ok(
                json!({"formats": c.accepted_query_formats(required_str(args, "serviceUrl")?).await?}),
            ),
            "shutdown" => Ok(json!({})),
            other => Err(Failure::unsupported(format!("unknown operation '{other}'"))),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// configure

/// A private JWK as the library's signing key. A key the library does not import is
/// `InvalidArguments`.
fn import_key(jwk: &Map<String, Value>) -> Result<SigningKey> {
    args::document("privateJwk", jwk, |v| {
        SigningKey::from_jwk(&Jwk::from_json(&v)?)
    })
}

/// Builds the client every later operation uses (PROTOCOL.md section 4.1).
async fn configure(args: &Args) -> Result<(Client, Value)> {
    let none = Map::from_iter([("type".to_owned(), Value::from("none"))]);
    let auth = match args.get("auth") {
        None | Some(Value::Null) => &none,
        Some(Value::Object(auth)) => auth,
        Some(_) => return Err(Failure::invalid("argument 'auth' must be an object")),
    };
    // The token-exchange option of section 6.2, step 3; it applies to token exchange only.
    let allow_insecure_http = optional_bool(args, "allowInsecureHttp")?;
    let with_options = |builder: TokenExchangeAuthenticatorBuilder| match allow_insecure_http {
        Some(allow) => builder.allow_insecure_http(allow).build(),
        None => builder.build(),
    };
    let mut result = Object::new().set("library", LIBRARY);
    let mut builder = Client::builder();
    match auth.get("type").and_then(Value::as_str) {
        Some("none") => {}
        Some("bearer") => {
            let mut authenticator = BearerTokenAuthenticator::new(required_str(auth, "token")?);
            if let Some(realm) = optional_str(auth, "realm")? {
                authenticator = authenticator.with_realm(args::url("realm", realm)?);
            }
            builder = builder.authenticator(authenticator);
        }
        Some("openid") => {
            let credentials = OpenIdCredentials::new(required_str(auth, "idToken")?);
            builder = builder.authenticator(with_options(TokenExchangeAuthenticator::builder(
                credentials,
            )));
        }
        Some("selfSigned") => {
            let agent = required_str(auth, "agent")?;
            let jwk = required_object(auth, "privateJwk")?;
            let kid = match optional_str(auth, "kid")? {
                Some(kid) => kid,
                None => jwk.get("kid").and_then(Value::as_str).ok_or_else(|| {
                    Failure::invalid("selfSigned needs 'kid', or a 'kid' in the private JWK")
                })?,
            };
            let key = import_key(jwk)?;
            let credentials = SelfSignedCredentials::for_agent(agent, key, kid);
            result = result.set("agent", agent).set("kid", kid);
            builder = builder.authenticator(with_options(TokenExchangeAuthenticator::builder(
                credentials,
            )));
        }
        Some("didKey") => {
            let algorithm = match optional_str(auth, "algorithm")?.unwrap_or("ES256") {
                "ES256" => KeyAlgorithm::P256,
                "EdDSA" => KeyAlgorithm::Ed25519,
                other => return Err(Failure::invalid(format!("unknown algorithm '{other}'"))),
            };
            let credentials = SelfSignedCredentials::did_key(SigningKey::generate(algorithm)?);
            result = result
                .set("agent", credentials.agent())
                .set("kid", credentials.kid());
            builder = builder.authenticator(with_options(TokenExchangeAuthenticator::builder(
                credentials,
            )));
        }
        other => {
            let other = other.map_or_else(
                || {
                    auth.get("type")
                        .map_or("undefined".to_owned(), Value::to_string)
                },
                str::to_owned,
            );
            return Err(Failure::invalid(format!("unknown auth type '{other}'")));
        }
    }
    if let Some(user_agent) = optional_str(args, "userAgent")? {
        builder = builder.user_agent(user_agent);
    }
    if let Some(seconds) = optional_positive(args, "timeoutSeconds")? {
        builder = builder.timeout(Duration::from_secs(seconds));
    }
    if let Some(headers) = optional_object(args, "headers")? {
        for (name, value) in headers {
            let Some(value) = value.as_str() else {
                return Err(Failure::invalid(format!(
                    "header '{name}' must have a string value"
                )));
            };
            builder = builder.default_header(name, value);
        }
    }
    Ok((builder.build()?, result.into()))
}

// ---------------------------------------------------------------------------------------------
// Reading and writing

async fn read(c: &Client, args: &Args) -> Result<Value> {
    let mut request = c.read(required_str(args, "url")?);
    if let Some(accept) = optional_str(args, "accept")? {
        request = request.accept(accept);
    }
    match (
        optional_index(args, "rangeStart")?,
        optional_index(args, "rangeEnd")?,
    ) {
        (Some(start), end) => request = request.range(start, end),
        (None, Some(_)) => return Err(Failure::invalid("rangeEnd needs rangeStart")),
        (None, None) => {}
    }
    if let Some(etag) = optional_str(args, "ifNoneMatch")? {
        request = request.if_none_match(etag);
    }
    if let Some(preference) = optional_str(args, "prefer")? {
        request = request.prefer(preference);
    }
    let resource = request.await?;
    Ok(Object::new()
        .set("metadata", results::metadata(&resource.metadata))
        .set("notModified", resource.not_modified)
        .opt("contentRange", resource.metadata.content_range())
        .set(
            "body",
            results::body(&resource.body, resource.metadata.content_type.as_deref()),
        )
        .into())
}

async fn create(c: &Client, args: &Args) -> Result<Value> {
    let container = required_str(args, "container")?;
    let (bytes, content_type) = args::body(args.get("body"), optional_str(args, "contentType")?)?;
    let mut request = c.create(container, bytes, &content_type);
    if let Some(slug) = optional_str(args, "slug")? {
        request = request.slug(slug);
    }
    if let Some(types) = optional_array(args, "types")? {
        for type_iri in args::strings("types", types)? {
            request = request.resource_type(type_iri);
        }
    }
    if let Some(links) = optional_array(args, "links")? {
        for link in links {
            let (Some(href), Some(rel)) = (
                link.get("href").and_then(Value::as_str),
                link.get("rel").and_then(Value::as_str),
            ) else {
                return Err(Failure::invalid(
                    "argument 'links' must be a list of {\"href\", \"rel\"} objects",
                ));
            };
            request = request.link(Link::new(args::url("links", href)?, rel));
        }
    }
    Ok(results::created(&request.await?))
}

async fn update(c: &Client, args: &Args) -> Result<Value> {
    let url = required_str(args, "url")?;
    let body = match args.get("body") {
        None | Some(Value::Null) => return Err(Failure::invalid("missing argument 'body'")),
        body => body,
    };
    let (bytes, content_type) = args::body(body, optional_str(args, "contentType")?)?;
    let mut request = c.update(url, bytes, &content_type);
    if let Some(etag) = optional_str(args, "ifMatch")? {
        request = request.if_match(etag);
    }
    if let Some(etag) = optional_str(args, "ifNoneMatch")? {
        request = request.if_none_match(etag);
    }
    Ok(results::update(&request.await?))
}

// ---------------------------------------------------------------------------------------------
// Notifications

/// Verifies a delivery with the library's `WebhookVerifier`, which fetches the storage
/// description through the configured client (PROTOCOL.md section 4.2).
async fn verify_notification(c: &Client, args: &Args) -> Result<Value> {
    let fields = required_object(args, "headers")?;
    let method = required_str(args, "method")?;
    let inbox = args::url("url", required_str(args, "url")?)?;
    let body = args::base64("bodyBase64", required_str(args, "bodyBase64")?)?;
    let trusted = optional_array(args, "trustedStorages")?
        .map(|t| args::urls("trustedStorages", t))
        .transpose()?;
    let mut headers = HeaderMap::new();
    for (name, values) in fields {
        let header = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| Failure::invalid(format!("invalid header name {name:?}")))?;
        let values = match values {
            Value::String(v) => vec![v.as_str()],
            Value::Array(vs) => args::strings("headers", vs)?,
            _ => {
                return Err(Failure::invalid(format!(
                    "header '{name}' must have a list of values"
                )));
            }
        };
        for value in values {
            let value = HeaderValue::from_bytes(value.as_bytes())
                .map_err(|_| Failure::invalid(format!("invalid value of header '{name}'")))?;
            headers.append(header.clone(), value);
        }
    }
    let mut verifier = WebhookVerifier::builder().client(c.clone());
    if let Some(trusted) = trusted {
        verifier = verifier.trusted_storages(trusted);
    }
    let verified = verifier
        .build()
        .verify(method, &inbox, &headers, &body)
        .await?;
    let activities: Vec<Value> = verified
        .notification
        .activities
        .iter()
        .map(|a| {
            Object::new()
                .opt("id", Some(a.id.clone()).filter(|id| !id.is_empty()))
                .set("types", a.types.clone())
                .set("object", a.object.id.clone())
                .set("objectTypes", a.object.types.clone())
                .into()
        })
        .collect();
    Ok(json!({
        "storage": results::url(&verified.storage),
        "keyid": verified.key_id,
        "activities": activities,
        "raw": verified.notification.raw,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_announced_operation_is_dispatched() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let mut state = State::new();
        for op in OPERATIONS {
            // With no arguments every operation either succeeds or fails on its arguments;
            // none is unknown.
            let outcome = runtime.block_on(state.run(op, &Args::new()));
            if let Err(Failure::Adapter { kind, message }) = &outcome {
                assert_ne!(*kind, "Unsupported", "{op}: {message}");
            }
        }
    }
}
