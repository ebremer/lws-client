// SPDX-License-Identifier: MIT
//! Results: the library's values in the shapes of driver/PROTOCOL.md section 3.1. Absent values
//! are omitted.

use base64::Engine as _;
use lws_client::{
    ContainedResource, ContainerPage, CreateResult, ResourceMetadata, SearchPage,
    StorageDescription, Subscription, UpdateResult, Url,
};
use serde_json::{Map, Value, json};

/// A JSON object under construction that leaves absent members out.
#[derive(Default)]
pub(crate) struct Object(Map<String, Value>);

impl Object {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    /// Sets a member.
    pub(crate) fn set(mut self, name: &str, value: impl Into<Value>) -> Self {
        self.0.insert(name.to_owned(), value.into());
        self
    }
    /// Sets a member when the value is present.
    pub(crate) fn opt(mut self, name: &str, value: Option<impl Into<Value>>) -> Self {
        if let Some(v) = value {
            self.0.insert(name.to_owned(), v.into());
        }
        self
    }
}

impl From<Object> for Value {
    fn from(o: Object) -> Self {
        Value::Object(o.0)
    }
}

pub(crate) fn url(u: &Url) -> Value {
    Value::String(u.as_str().to_owned())
}

fn opt_url(u: Option<&Url>) -> Option<Value> {
    u.map(url)
}

/// Whether a content type is textual: `text/*`, `application/json`, `*+json`,
/// `application/xml`, `*+xml`.
fn is_textual(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    essence.starts_with("text/")
        || essence == "application/json"
        || essence == "application/xml"
        || essence.ends_with("+json")
        || essence.ends_with("+xml")
}

/// A response body: `{"text"}` for a textual content type, `{"base64"}` otherwise.
pub(crate) fn body(bytes: &[u8], content_type: Option<&str>) -> Value {
    if content_type.is_some_and(is_textual) {
        json!({"text": String::from_utf8_lossy(bytes)})
    } else {
        json!({"base64": base64::engine::general_purpose::STANDARD.encode(bytes)})
    }
}

/// Metadata (`ResourceMetadata`).
pub(crate) fn metadata(m: &ResourceMetadata) -> Value {
    let links: Vec<Value> = m
        .links
        .iter()
        .map(|l| {
            let params: Map<String, Value> = l
                .params
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            json!({"href": l.href.as_str(), "rel": l.rel, "params": params})
        })
        .collect();
    Object::new()
        .set("url", url(&m.url))
        .set("status", m.status.as_u16())
        .opt("etag", m.etag.clone())
        .opt("lastModified", m.last_modified.clone())
        .opt("contentType", m.content_type.clone())
        .opt("contentLength", m.content_length)
        .set("links", links)
        .opt("linkset", opt_url(m.linkset()))
        .opt("parent", opt_url(m.parent()))
        .opt("storage", opt_url(m.storage()))
        .set("types", m.types())
        .set("allow", m.allow.clone())
        .set("acceptPatch", m.accept_patch.clone())
        .into()
}

/// Item (`ContainedResource`).
pub(crate) fn item(i: &ContainedResource) -> Value {
    Object::new()
        .set("id", url(&i.id))
        .set("types", i.types.clone())
        .opt("format", i.format.clone())
        .opt("size", i.size)
        .opt("modified", i.modified_raw.clone())
        .into()
}

pub(crate) fn items(items: &[ContainedResource]) -> Vec<Value> {
    items.iter().map(item).collect()
}

/// Page (`ContainerPage`).
pub(crate) fn container_page(p: &ContainerPage) -> Value {
    Object::new()
        .set("id", url(&p.id))
        .set("types", p.types.clone())
        .opt("totalItems", p.total_items)
        .set("items", items(&p.items))
        .opt("first", opt_url(p.first.as_ref()))
        .opt("next", opt_url(p.next.as_ref()))
        .opt("prev", opt_url(p.prev.as_ref()))
        .opt("last", opt_url(p.last.as_ref()))
        .set("metadata", metadata(&p.metadata))
        .into()
}

/// Page, for a page of search results (`SearchPage`). The library's `SearchPage` has no `id`,
/// so the result has none either.
pub(crate) fn search_page(p: &SearchPage) -> Value {
    Object::new()
        .set("types", p.types.clone())
        .opt("totalItems", p.total_items)
        .set("items", items(&p.items))
        .opt("first", opt_url(p.first.as_ref()))
        .opt("next", opt_url(p.next.as_ref()))
        .opt("prev", opt_url(p.prev.as_ref()))
        .opt("last", opt_url(p.last.as_ref()))
        .set("metadata", metadata(&p.metadata))
        .into()
}

/// Update (`UpdateResult`).
pub(crate) fn update(u: &UpdateResult) -> Value {
    Object::new()
        .set("status", u.status.as_u16())
        .opt("etag", u.etag.clone())
        .set("metadata", metadata(&u.metadata))
        .into()
}

/// Created (`CreateResult`).
pub(crate) fn created(c: &CreateResult) -> Value {
    json!({"location": url(&c.location), "metadata": metadata(&c.metadata)})
}

/// Storage (`StorageDescription`).
pub(crate) fn storage(s: &StorageDescription) -> Value {
    let services: Vec<Value> = s
        .services
        .iter()
        .map(|svc| {
            Object::new()
                .opt("id", svc.id.clone())
                .set("types", svc.types.clone())
                .set("serviceEndpoint", url(&svc.service_endpoint))
                .opt(
                    "subscriptionType",
                    svc.property("subscriptionType")
                        .map(|_| svc.subscription_types()),
                )
                .into()
        })
        .collect();
    let verification_methods: Vec<Value> = s
        .verification_methods
        .iter()
        .map(|vm| {
            Object::new()
                .set("id", vm.id.clone())
                .opt("type", vm.method_type.clone())
                .opt("controller", vm.controller.clone())
                .into()
        })
        .collect();
    Object::new()
        .set("id", url(&s.id))
        .set("types", s.types.clone())
        // The library's `storage_root()` fails when there is no StorageRoot service.
        .opt("storageRoot", s.storage_root().ok().map(url))
        .set("services", services)
        .set("verificationMethods", verification_methods)
        .set("raw", s.raw.clone())
        .into()
}

/// Subscription.
pub(crate) fn subscription(s: &Subscription) -> Value {
    Object::new()
        .set("subscription", url(&s.subscription))
        .set("types", vec![s.subscription_type.clone()])
        .opt("expires", s.expires_raw.clone())
        .set("raw", s.raw.clone())
        .into()
}
