// SPDX-License-Identifier: MIT
//! The operations of driver/PROTOCOL.md section 4, each a call of the component's own operation
//! (wit/lws.wit) with its own options.

use serde_json::{Map, Value, json};
use wasmtime::Store;
use wasmtime::component::ResourceAny;

use crate::Args;
use crate::args::{
    self, limit, optional_array, optional_bool, optional_index, optional_object, optional_positive,
    optional_str, required_array, required_object, required_str,
};
use crate::errors::Failure;
use crate::lws::{
    Auth, BearerToken, CreateOptions, DeleteOptions, Error, Item, KeyAlgorithm, Link, Options,
    ReadOptions, SelfSignedKey, SubjectToken, SubscriptionRequest, UpdateOptions,
};
use crate::results::{self, Object};
use crate::runtime::{Host, Instance, Runtime};

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

/// The options of the client before the first `configure`: anonymous, the defaults.
fn default_options() -> Options {
    Options {
        auth: Auth::None,
        user_agent: None,
        timeout_ms: None,
        headers: Vec::new(),
        allow_insecure_http: false,
    }
}

/// The outcome of a call into the component: a trap, or the operation's own result.
fn outcome<T>(call: wasmtime::Result<std::result::Result<T, Error>>) -> Result<T> {
    match call {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(e.into()),
        Err(trap) => Err(Failure::trap(&trap)),
    }
}

fn trapped<T>(call: wasmtime::Result<T>) -> Result<T> {
    call.map_err(|trap| Failure::trap(&trap))
}

/// The adapter's state: the instance of the component, and the client every operation uses.
pub(crate) struct State {
    runtime: Runtime,
    instance: Instance,
    client: ResourceAny,
    library: String,
}

impl State {
    /// An instance with a client with no authenticator, as before the first `configure`.
    pub(crate) fn new(runtime: Runtime) -> wasmtime::Result<Self> {
        let (mut instance, client) = Self::fresh(&runtime)?;
        let library = instance
            .lws
            .ebremer_lws_client()
            .call_library(&mut instance.store)?;
        Ok(Self {
            runtime,
            instance,
            client,
            library,
        })
    }

    fn fresh(runtime: &Runtime) -> wasmtime::Result<(Instance, ResourceAny)> {
        let mut instance = runtime.instantiate()?;
        let client = instance
            .lws
            .ebremer_lws_client()
            .client()
            .call_new(&mut instance.store, &default_options())?
            .map_err(|e| wasmtime::Error::msg(e.message))?;
        Ok((instance, client))
    }

    /// The library, as the component names it.
    pub(crate) fn library(&self) -> String {
        format!("{} (WebAssembly component)", self.library)
    }

    /// Runs one operation of [`OPERATIONS`]. After a trap the instance is gone: the next
    /// operation runs in a fresh one, with the client of before the first `configure`.
    pub(crate) fn run(&mut self, op: &str, args: &Args) -> Result<Value> {
        let result = self.dispatch(op, args);
        if matches!(result, Err(Failure::Trap(_))) {
            self.restart();
        }
        result
    }

    /// Replaces the instance after a trap.
    pub(crate) fn restart(&mut self) {
        match Self::fresh(&self.runtime) {
            Ok((instance, client)) => {
                self.instance = instance;
                self.client = client;
            }
            Err(e) => {
                eprintln!("lws-driver-adapter-wasm: cannot start a new instance: {e:?}");
                std::process::exit(1);
            }
        }
    }

    /// Calls an operation of the current client.
    fn call<T>(
        &mut self,
        f: impl FnOnce(
            &crate::bindings::exports::ebremer::lws::client::GuestClient<'_>,
            &mut Store<Host>,
            ResourceAny,
        ) -> wasmtime::Result<std::result::Result<T, Error>>,
    ) -> Result<T> {
        let Instance { store, lws } = &mut self.instance;
        outcome(f(&lws.ebremer_lws_client().client(), store, self.client))
    }

    /// Pulls at most `limit + 1` items from a lazy listing: the first `limit`, and whether there
    /// was one more.
    fn take_items(
        &mut self,
        list: impl FnOnce(
            &crate::bindings::exports::ebremer::lws::client::GuestClient<'_>,
            &mut Store<Host>,
            ResourceAny,
        ) -> wasmtime::Result<ResourceAny>,
        args: &Args,
    ) -> Result<Value> {
        let limit = limit(args)?;
        let Instance { store, lws } = &mut self.instance;
        let client = lws.ebremer_lws_client();
        let listing = trapped(list(&client.client(), store, self.client))?;
        let mut items: Vec<Item> = Vec::new();
        let mut truncated = false;
        let pulled = loop {
            match outcome(client.items().call_next(&mut *store, listing)) {
                Ok(Some(item)) if items.len() == limit => {
                    drop(item);
                    truncated = true;
                    break Ok(());
                }
                Ok(Some(item)) => items.push(item),
                Ok(None) => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        trapped(listing.resource_drop(&mut *store))?;
        pulled?;
        Ok(json!({"items": results::items(&items), "truncated": truncated}))
    }

    fn dispatch(&mut self, op: &str, args: &Args) -> Result<Value> {
        match op {
            "configure" => self.configure(args),
            "discover_storage" => {
                let url = required_str(args, "url")?;
                let s = self.call(|c, s, me| c.call_discover_storage(s, me, url))?;
                Ok(results::storage(&s))
            }
            "get_storage_description" => {
                let url = required_str(args, "url")?;
                let s = self.call(|c, s, me| c.call_get_storage_description(s, me, url))?;
                Ok(results::storage(&s))
            }
            "head" => {
                let url = required_str(args, "url")?;
                let m = self.call(|c, s, me| c.call_head(s, me, url))?;
                Ok(results::metadata(&m))
            }
            "read" => self.read(args),
            "read_container" => {
                let url = required_str(args, "url")?;
                let p = self.call(|c, s, me| c.call_read_container(s, me, url))?;
                Ok(results::page(&p))
            }
            "list_container" => {
                let url = required_str(args, "url")?;
                self.take_items(|c, s, me| c.call_list_container(s, me, url), args)
            }
            "create" => self.create(args),
            "create_container" => {
                let parent = required_str(args, "parent")?;
                let options = CreateOptions {
                    slug: optional_str(args, "slug")?.map(str::to_owned),
                    types: Vec::new(),
                    links: Vec::new(),
                    headers: Vec::new(),
                };
                let c = self.call(|c, s, me| c.call_create_container(s, me, parent, &options))?;
                Ok(results::created(&c))
            }
            "update" => self.update(args),
            "patch" => {
                let url = required_str(args, "url")?;
                let patch = args::patch(args.get("patch"))?;
                let options = update_options(optional_str(args, "ifMatch")?, None);
                let u = self.call(|c, s, me| c.call_patch(s, me, url, &patch, &options))?;
                Ok(results::update(&u))
            }
            "delete" => {
                let url = required_str(args, "url")?;
                let options = DeleteOptions {
                    if_match: optional_str(args, "ifMatch")?.map(str::to_owned),
                    recursive: optional_bool(args, "recursive")? == Some(true),
                    headers: Vec::new(),
                };
                self.call(|c, s, me| c.call_delete(s, me, url, &options))?;
                Ok(json!({}))
            }
            "linkset_url" => {
                let url = required_str(args, "url")?;
                let linkset = self.call(|c, s, me| c.call_linkset_url(s, me, url))?;
                Ok(json!({ "linkset": linkset }))
            }
            "read_linkset" => {
                let url = required_str(args, "url")?;
                let doc = self.call(|c, s, me| c.call_read_linkset(s, me, url))?;
                Ok(Object::new()
                    .set("url", doc.url.as_str())
                    .opt("etag", doc.etag.clone())
                    .set("linkset", results::json_text(&doc.linkset))
                    .set("allow", doc.allow.clone())
                    .set("acceptPatch", doc.accept_patch.clone())
                    .into())
            }
            "update_linkset" => {
                let url = required_str(args, "linksetUrl")?;
                let linkset = args::document(required_object(args, "linkset")?);
                let options = update_options(optional_str(args, "ifMatch")?, None);
                let u =
                    self.call(|c, s, me| c.call_update_linkset(s, me, url, &linkset, &options))?;
                Ok(results::update(&u))
            }
            "patch_linkset" => {
                let url = required_str(args, "linksetUrl")?;
                let patch = args::patch(args.get("patch"))?;
                let options = update_options(optional_str(args, "ifMatch")?, None);
                let u = self.call(|c, s, me| c.call_patch_linkset(s, me, url, &patch, &options))?;
                Ok(results::update(&u))
            }
            "subscribe" => {
                let service = required_str(args, "serviceUrl")?;
                let request = SubscriptionRequest {
                    topics: args::owned_strings("topics", required_array(args, "topics")?)?,
                    inbox: required_str(args, "inbox")?.to_owned(),
                    expires: optional_str(args, "expires")?.map(str::to_owned),
                };
                let sub = self.call(|c, s, me| c.call_subscribe(s, me, service, &request))?;
                Ok(results::subscription(&sub))
            }
            "list_subscriptions" => {
                let service = required_str(args, "serviceUrl")?;
                self.take_items(|c, s, me| c.call_list_subscriptions(s, me, service), args)
            }
            "get_subscription" => {
                let url = required_str(args, "url")?;
                let sub = self.call(|c, s, me| c.call_get_subscription(s, me, url))?;
                Ok(results::subscription(&sub))
            }
            "unsubscribe" => {
                let url = required_str(args, "url")?;
                self.call(|c, s, me| c.call_unsubscribe(s, me, url))?;
                Ok(json!({}))
            }
            "verify_notification" => self.verify_notification(args),
            "request_access" => {
                let service = required_str(args, "serviceUrl")?;
                let request = args::document(required_object(args, "request")?);
                let location =
                    self.call(|c, s, me| c.call_request_access(s, me, service, &request))?;
                Ok(json!({ "location": location }))
            }
            "get_access_request" => {
                let url = required_str(args, "url")?;
                let document = self.call(|c, s, me| c.call_get_access_request(s, me, url))?;
                Ok(json!({"document": results::json_text(&document)}))
            }
            "list_access_requests" => {
                let service = required_str(args, "serviceUrl")?;
                self.take_items(|c, s, me| c.call_list_access_requests(s, me, service), args)
            }
            "cancel_access_request" => {
                let url = required_str(args, "url")?;
                self.call(|c, s, me| c.call_cancel_access_request(s, me, url))?;
                Ok(json!({}))
            }
            "grant_access" => {
                let service = required_str(args, "serviceUrl")?;
                let grant = args::document(required_object(args, "grant")?);
                let location = self.call(|c, s, me| c.call_grant_access(s, me, service, &grant))?;
                Ok(json!({ "location": location }))
            }
            "get_access_grant" => {
                let url = required_str(args, "url")?;
                let document = self.call(|c, s, me| c.call_get_access_grant(s, me, url))?;
                Ok(json!({"document": results::json_text(&document)}))
            }
            "list_access_grants" => {
                let service = required_str(args, "serviceUrl")?;
                self.take_items(|c, s, me| c.call_list_access_grants(s, me, service), args)
            }
            "revoke_access_grant" => {
                let url = required_str(args, "url")?;
                self.call(|c, s, me| c.call_revoke_access_grant(s, me, url))?;
                Ok(json!({}))
            }
            "read_type_index" => {
                let url = required_str(args, "url")?;
                let page = self.call(|c, s, me| c.call_read_type_index(s, me, url))?;
                Ok(results::type_index_page(&page))
            }
            "list_types" => self.list_types(args),
            "search_types" => {
                let service = required_str(args, "serviceUrl")?;
                let query = args::query(required_object(args, "query")?)?;
                let page = self.call(|c, s, me| c.call_search_types(s, me, service, &query))?;
                Ok(results::page(&page))
            }
            "search_all" => {
                let service = required_str(args, "serviceUrl")?;
                let query = args::query(required_object(args, "query")?)?;
                self.take_items(|c, s, me| c.call_search_all(s, me, service, &query), args)
            }
            "accepted_query_formats" => {
                let service = required_str(args, "serviceUrl")?;
                let formats =
                    self.call(|c, s, me| c.call_accepted_query_formats(s, me, service))?;
                Ok(json!({ "formats": formats }))
            }
            "shutdown" => Ok(json!({})),
            other => Err(Failure::unsupported(format!("unknown operation '{other}'"))),
        }
    }

    // -----------------------------------------------------------------------------------------
    // configure

    /// Builds the client every later operation uses (PROTOCOL.md section 4.1).
    fn configure(&mut self, args: &Args) -> Result<Value> {
        let none = Map::from_iter([("type".to_owned(), Value::from("none"))]);
        let auth = match args.get("auth") {
            None | Some(Value::Null) => &none,
            Some(Value::Object(auth)) => auth,
            Some(_) => return Err(Failure::invalid("argument 'auth' must be an object")),
        };
        let auth = match auth.get("type").and_then(Value::as_str) {
            Some("none") => Auth::None,
            Some("bearer") => Auth::Bearer(BearerToken {
                token: required_str(auth, "token")?.to_owned(),
                realm: optional_str(auth, "realm")?.map(str::to_owned),
            }),
            Some("openid") => Auth::Openid(SubjectToken::Fixed(
                required_str(auth, "idToken")?.to_owned(),
            )),
            Some("selfSigned") => Auth::SelfSigned(SelfSignedKey {
                agent: required_str(auth, "agent")?.to_owned(),
                private_jwk: args::document(required_object(auth, "privateJwk")?),
                kid: optional_str(auth, "kid")?.map(str::to_owned),
            }),
            Some("didKey") => {
                Auth::DidKey(match optional_str(auth, "algorithm")?.unwrap_or("ES256") {
                    "ES256" => KeyAlgorithm::Es256,
                    "EdDSA" => KeyAlgorithm::Eddsa,
                    other => return Err(Failure::invalid(format!("unknown algorithm '{other}'"))),
                })
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
        };
        let mut headers = Vec::new();
        if let Some(fields) = optional_object(args, "headers")? {
            for (name, value) in fields {
                let Some(value) = value.as_str() else {
                    return Err(Failure::invalid(format!(
                        "header '{name}' must have a string value"
                    )));
                };
                headers.push((name.clone(), value.to_owned()));
            }
        }
        let options = Options {
            auth,
            user_agent: optional_str(args, "userAgent")?.map(str::to_owned),
            timeout_ms: optional_positive(args, "timeoutSeconds")?
                .map(|seconds| seconds.saturating_mul(1000)),
            headers,
            // The token-exchange option of section 6.2, step 3; it applies to token exchange only.
            allow_insecure_http: optional_bool(args, "allowInsecureHttp")? == Some(true),
        };
        let Instance { store, lws } = &mut self.instance;
        let client = lws.ebremer_lws_client().client();
        let new = outcome(client.call_new(&mut *store, &options))?;
        let identity = trapped(client.call_identity(&mut *store, new))?;
        trapped(self.client.resource_drop(&mut *store))?;
        self.client = new;
        let mut result = Object::new().set("library", self.library());
        if let Some(identity) = identity {
            result = result.set("agent", identity.agent).set("kid", identity.kid);
        }
        Ok(result.into())
    }

    // -----------------------------------------------------------------------------------------
    // Reading and writing

    fn read(&mut self, args: &Args) -> Result<Value> {
        let url = required_str(args, "url")?;
        let (range_start, range_end) = match (
            optional_index(args, "rangeStart")?,
            optional_index(args, "rangeEnd")?,
        ) {
            (None, Some(_)) => return Err(Failure::invalid("rangeEnd needs rangeStart")),
            range => range,
        };
        let options = ReadOptions {
            accept: optional_str(args, "accept")?.map(str::to_owned),
            range_start,
            range_end,
            if_none_match: optional_str(args, "ifNoneMatch")?.map(str::to_owned),
            prefer: optional_str(args, "prefer")?.map(str::to_owned),
            headers: Vec::new(),
        };
        let r = self.call(|c, s, me| c.call_read(s, me, url, &options))?;
        Ok(Object::new()
            .set("metadata", results::metadata(&r.metadata))
            .set("notModified", r.not_modified)
            .opt("contentRange", r.content_range.clone())
            .set(
                "body",
                results::body(&r.body, r.metadata.content_type.as_deref()),
            )
            .into())
    }

    fn create(&mut self, args: &Args) -> Result<Value> {
        let container = required_str(args, "container")?;
        let (bytes, content_type) =
            args::body(args.get("body"), optional_str(args, "contentType")?)?;
        let mut links = Vec::new();
        if let Some(values) = optional_array(args, "links")? {
            for link in values {
                let (Some(href), Some(rel)) = (
                    link.get("href").and_then(Value::as_str),
                    link.get("rel").and_then(Value::as_str),
                ) else {
                    return Err(Failure::invalid(
                        "argument 'links' must be a list of {\"href\", \"rel\"} objects",
                    ));
                };
                links.push(Link {
                    href: href.to_owned(),
                    rel: rel.to_owned(),
                    params: Vec::new(),
                });
            }
        }
        let options = CreateOptions {
            slug: optional_str(args, "slug")?.map(str::to_owned),
            types: match optional_array(args, "types")? {
                Some(types) => args::owned_strings("types", types)?,
                None => Vec::new(),
            },
            links,
            headers: Vec::new(),
        };
        let c =
            self.call(|c, s, me| c.call_create(s, me, container, &bytes, &content_type, &options))?;
        Ok(results::created(&c))
    }

    fn update(&mut self, args: &Args) -> Result<Value> {
        let url = required_str(args, "url")?;
        let body = match args.get("body") {
            None | Some(Value::Null) => return Err(Failure::invalid("missing argument 'body'")),
            body => body,
        };
        let (bytes, content_type) = args::body(body, optional_str(args, "contentType")?)?;
        let options = update_options(
            optional_str(args, "ifMatch")?,
            optional_str(args, "ifNoneMatch")?,
        );
        let u = self.call(|c, s, me| c.call_update(s, me, url, &bytes, &content_type, &options))?;
        Ok(results::update(&u))
    }

    // -----------------------------------------------------------------------------------------
    // Type Index

    fn list_types(&mut self, args: &Args) -> Result<Value> {
        let service = required_str(args, "serviceUrl")?;
        let limit = limit(args)?;
        let Instance { store, lws } = &mut self.instance;
        let client = lws.ebremer_lws_client();
        let listing = trapped(
            client
                .client()
                .call_list_types(&mut *store, self.client, service),
        )?;
        let mut types: Vec<String> = Vec::new();
        let mut truncated = false;
        let pulled = loop {
            match outcome(client.type_iris().call_next(&mut *store, listing)) {
                Ok(Some(_)) if types.len() == limit => {
                    truncated = true;
                    break Ok(());
                }
                Ok(Some(type_iri)) => types.push(type_iri),
                Ok(None) => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        trapped(listing.resource_drop(&mut *store))?;
        pulled?;
        Ok(json!({"types": types, "truncated": truncated}))
    }

    // -----------------------------------------------------------------------------------------
    // Notifications

    /// Verifies a delivery with the component's webhook verifier, which fetches the storage
    /// description through the configured client (PROTOCOL.md section 4.2).
    fn verify_notification(&mut self, args: &Args) -> Result<Value> {
        let fields = required_object(args, "headers")?;
        let method = required_str(args, "method")?;
        let inbox = required_str(args, "url")?;
        let body = args::base64("bodyBase64", required_str(args, "bodyBase64")?)?;
        let trusted = optional_array(args, "trustedStorages")?
            .map(|t| args::owned_strings("trustedStorages", t))
            .transpose()?;
        let mut headers = Vec::new();
        for (name, values) in fields {
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
                headers.push((name.clone(), value.to_owned()));
            }
        }
        let Instance { store, lws } = &mut self.instance;
        let verifier = lws.ebremer_lws_webhook().verifier();
        let instance = outcome(verifier.call_new(&mut *store, self.client, trusted.as_deref()))?;
        let verified =
            outcome(verifier.call_verify(&mut *store, instance, method, inbox, &headers, &body));
        trapped(instance.resource_drop(&mut *store))?;
        let verified = verified?;
        let activities: Vec<Value> = verified
            .activities
            .iter()
            .map(|a| {
                Object::new()
                    .opt("id", a.id.clone())
                    .set("types", a.types.clone())
                    .set("object", a.object.as_str())
                    .set("objectTypes", a.object_types.clone())
                    .into()
            })
            .collect();
        Ok(json!({
            "storage": verified.storage,
            "keyid": verified.key_id,
            "activities": activities,
            "raw": results::json_text(&verified.raw),
        }))
    }
}

fn update_options(if_match: Option<&str>, if_none_match: Option<&str>) -> UpdateOptions {
    UpdateOptions {
        if_match: if_match.map(str::to_owned),
        if_none_match: if_none_match.map(str::to_owned),
        links: Vec::new(),
        set_linkset: false,
        headers: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// The component: `LWS_CLIENT_WASM`, or the release build of ../../../wasm.
    fn component() -> PathBuf {
        std::env::var_os("LWS_CLIENT_WASM")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../../wasm/target/wasm32-wasip2/release/lws_client.wasm")
            })
    }

    #[test]
    fn every_announced_operation_is_dispatched() {
        let path = component();
        let runtime = Runtime::load(&path).unwrap_or_else(|e| {
            panic!(
                "cannot load {} (build ../../../wasm first, or set LWS_CLIENT_WASM): {e:?}",
                path.display()
            )
        });
        let mut state = State::new(runtime).expect("an instance of the component");
        for op in OPERATIONS {
            // With no arguments every operation either succeeds or fails on its arguments; none
            // is unknown, and none traps.
            let outcome = state.run(op, &Args::new());
            if let Err(Failure::Adapter { kind, message }) = &outcome {
                assert_ne!(*kind, "Unsupported", "{op}: {message}");
            }
            assert!(
                !matches!(outcome, Err(Failure::Trap(_))),
                "{op} trapped: {outcome:?}"
            );
        }
    }
}
