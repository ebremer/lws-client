// SPDX-License-Identifier: MIT
//! Results: the component's values in the shapes of driver/PROTOCOL.md section 3.1. Absent
//! values are omitted.

use base64::Engine as _;
use serde_json::{Map, Value, json};

use crate::lws::{
    Created, Item, Metadata, Page, StorageDescription, Subscription, TypeIndexPage, Updated,
};

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

/// A JSON text from the component, as a value (a text it cannot have produced is `null`).
pub(crate) fn json_text(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or(Value::Null)
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
pub(crate) fn metadata(m: &Metadata) -> Value {
    let links: Vec<Value> = m
        .links
        .iter()
        .map(|l| {
            let params: Map<String, Value> = l
                .params
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            json!({"href": l.href, "rel": l.rel, "params": params})
        })
        .collect();
    Object::new()
        .set("url", m.url.as_str())
        .set("status", m.status)
        .opt("etag", m.etag.clone())
        .opt("lastModified", m.last_modified.clone())
        .opt("contentType", m.content_type.clone())
        .opt("contentLength", m.content_length)
        .set("links", links)
        .opt("linkset", m.linkset.clone())
        .opt("parent", m.parent.clone())
        .opt("storage", m.storage.clone())
        .set("types", m.types.clone())
        .set("allow", m.allow.clone())
        .set("acceptPatch", m.accept_patch.clone())
        .into()
}

/// Item (`ContainedResource`).
pub(crate) fn item(i: &Item) -> Value {
    Object::new()
        .set("id", i.id.as_str())
        .set("types", i.types.clone())
        .opt("format", i.format.clone())
        .opt("size", i.size)
        .opt("modified", i.modified.clone())
        .into()
}

pub(crate) fn items(items: &[Item]) -> Vec<Value> {
    items.iter().map(item).collect()
}

/// Page (`ContainerPage`, or a page of search results).
pub(crate) fn page(p: &Page) -> Value {
    Object::new()
        .set("id", p.id.as_str())
        .set("types", p.types.clone())
        .opt("totalItems", p.total_items)
        .set("items", items(&p.items))
        .opt("first", p.first.clone())
        .opt("next", p.next.clone())
        .opt("prev", p.prev.clone())
        .opt("last", p.last.clone())
        .set("metadata", metadata(&p.metadata))
        .into()
}

/// A page of the Type Index.
pub(crate) fn type_index_page(p: &TypeIndexPage) -> Value {
    Object::new()
        .opt("totalItems", p.total_items)
        .set("types", p.types.clone())
        .opt("first", p.first.clone())
        .opt("next", p.next.clone())
        .opt("prev", p.prev.clone())
        .opt("last", p.last.clone())
        .into()
}

/// Update (`UpdateResult`).
pub(crate) fn update(u: &Updated) -> Value {
    Object::new()
        .set("status", u.status)
        .opt("etag", u.etag.clone())
        .set("metadata", metadata(&u.metadata))
        .into()
}

/// Created (`CreateResult`).
pub(crate) fn created(c: &Created) -> Value {
    json!({"location": c.location, "metadata": metadata(&c.metadata)})
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
                .set("serviceEndpoint", svc.service_endpoint.as_str())
                .opt("subscriptionType", svc.subscription_types.clone())
                .into()
        })
        .collect();
    let verification_methods: Vec<Value> = s
        .verification_methods
        .iter()
        .map(|vm| {
            Object::new()
                .set("id", vm.id.as_str())
                .opt("type", vm.method_type.clone())
                .opt("controller", vm.controller.clone())
                .into()
        })
        .collect();
    Object::new()
        .set("id", s.id.as_str())
        .set("types", s.types.clone())
        .opt("storageRoot", s.storage_root.clone())
        .set("services", services)
        .set("verificationMethods", verification_methods)
        .set("raw", json_text(&s.raw))
        .into()
}

/// Subscription.
pub(crate) fn subscription(s: &Subscription) -> Value {
    Object::new()
        .set("subscription", s.url.as_str())
        .set("types", vec![s.subscription_type.clone()])
        .opt("expires", s.expires.clone())
        .set("raw", json_text(&s.raw))
        .into()
}
