// SPDX-License-Identifier: MIT
//! The library's values as the component's (wit/lws.wit), and the component's arguments as the
//! library's.

use http::{HeaderMap, HeaderName, HeaderValue};
use lws_client::headers::ProblemDetails;
use lws_client::{
    ContainedResource, ContainerPage, CreateResult, Error as LwsError, JsonPatch, Link,
    LinksetDocument, ResourceMetadata, SearchPage, StorageDescription, Subscription, TypeIndexPage,
    UpdateResult, Url,
};
use serde_json::{Map, Value};

use crate::bindings::ebremer::lws::types::{
    Created, Error, ErrorKind, Header, HttpError, Item, Link as WitLink,
    LinksetDocument as WitLinkset, Metadata, Page, PatchOp, PatchOperation, QueryGroup, Service,
    StorageDescription as WitStorage, Subscription as WitSubscription,
    TypeIndexPage as WitTypeIndexPage, TypeQuery, Updated, VerificationMethod,
};

// ---------------------------------------------------------------------------------------------
// Errors

/// An argument the library cannot take.
pub(crate) fn invalid(message: impl Into<String>) -> Error {
    Error {
        kind: ErrorKind::InvalidInput,
        message: message.into(),
        http: None,
        oauth_error: None,
        oauth_error_description: None,
    }
}

fn problem_json(p: &ProblemDetails) -> String {
    let mut o = Map::new();
    let mut put = |name: &str, value: Option<Value>| {
        if let Some(v) = value {
            o.insert(name.to_owned(), v);
        }
    };
    put("type", p.problem_type.clone().map(Value::String));
    put("title", p.title.clone().map(Value::String));
    put("status", p.status.map(Value::from));
    put("detail", p.detail.clone().map(Value::String));
    put("instance", p.instance.clone().map(Value::String));
    for (k, v) in &p.extensions {
        o.insert(k.clone(), v.clone());
    }
    Value::Object(o).to_string()
}

/// An error's message with the chain of its causes.
fn message_with_causes(e: &LwsError) -> String {
    let mut message = e.to_string();
    let mut cause = std::error::Error::source(e);
    while let Some(c) = cause {
        let text = c.to_string();
        if !message.contains(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
        cause = c.source();
    }
    message
}

/// The library's error as the component's.
pub(crate) fn error(e: LwsError) -> Error {
    if let Some(h) = e.http_error() {
        let kind = match &e {
            LwsError::BadRequest(_) => ErrorKind::BadRequest,
            LwsError::Unauthorized(_) => ErrorKind::Unauthorized,
            LwsError::Forbidden(_) => ErrorKind::Forbidden,
            LwsError::NotFound(_) => ErrorKind::NotFound,
            LwsError::MethodNotAllowed(_) => ErrorKind::MethodNotAllowed,
            LwsError::NotAcceptable(_) => ErrorKind::NotAcceptable,
            LwsError::Conflict(_) => ErrorKind::Conflict,
            LwsError::Gone(_) => ErrorKind::Gone,
            LwsError::PreconditionFailed(_) => ErrorKind::PreconditionFailed,
            LwsError::UnsupportedMediaType(_) => ErrorKind::UnsupportedMediaType,
            LwsError::UnprocessableContent(_) => ErrorKind::UnprocessableContent,
            LwsError::NotImplemented(_) => ErrorKind::NotImplemented,
            LwsError::InsufficientStorage(_) => ErrorKind::InsufficientStorage,
            _ => ErrorKind::Http,
        };
        return Error {
            kind,
            message: e.to_string(),
            http: Some(HttpError {
                status: h.status.as_u16(),
                method: h.method.to_string(),
                url: h.url.to_string(),
                headers: header_list(&h.headers),
                problem: h.problem.as_ref().map(problem_json),
                body: h.body.clone(),
                allow: h.allow(),
                accept_patch: h.accept_patch(),
            }),
            oauth_error: None,
            oauth_error_description: None,
        };
    }
    if let LwsError::Authentication {
        error,
        error_description,
        ..
    } = &e
    {
        return Error {
            kind: ErrorKind::Authentication,
            message: e.to_string(),
            http: None,
            oauth_error: error.clone(),
            oauth_error_description: error_description.clone(),
        };
    }
    let kind = match &e {
        LwsError::Protocol(_) => ErrorKind::Protocol,
        LwsError::SignatureVerification(_) => ErrorKind::SignatureVerification,
        LwsError::InvalidInput(_) => ErrorKind::InvalidInput,
        LwsError::Crypto(_) => ErrorKind::Crypto,
        LwsError::Transport(_) => ErrorKind::Transport,
        _ => ErrorKind::Internal,
    };
    Error {
        kind,
        message: message_with_causes(&e),
        http: None,
        oauth_error: None,
        oauth_error_description: None,
    }
}

// ---------------------------------------------------------------------------------------------
// Arguments

pub(crate) fn url(name: &str, value: &str) -> Result<Url, Error> {
    Url::parse(value).map_err(|e| invalid(format!("{name}: invalid URL {value:?}: {e}")))
}

pub(crate) fn urls(name: &str, values: &[String]) -> Result<Vec<Url>, Error> {
    values.iter().map(|v| url(name, v)).collect()
}

pub(crate) fn json(name: &str, text: &str) -> Result<Value, Error> {
    serde_json::from_str(text).map_err(|e| invalid(format!("{name} is not JSON: {e}")))
}

/// A link to send.
pub(crate) fn link(l: &WitLink) -> Result<Link, Error> {
    let mut link = Link::new(url("link", &l.href)?, l.rel.as_str());
    for (name, value) in &l.params {
        link = link.with_param(name.as_str(), value.as_str());
    }
    Ok(link)
}

/// Header fields as a header map.
pub(crate) fn header_map(headers: &[Header]) -> Result<HeaderMap, Error> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid(format!("invalid header name {name:?}")))?;
        let value = HeaderValue::from_bytes(value.as_bytes())
            .map_err(|_| invalid(format!("invalid value of header '{name}'")))?;
        map.append(name, value);
    }
    Ok(map)
}

/// A JSON Patch, built with the library's builder.
pub(crate) fn patch(operations: &[PatchOperation]) -> Result<JsonPatch, Error> {
    let mut patch = JsonPatch::new();
    for op in operations {
        let name = match op.op {
            PatchOp::Add => "add",
            PatchOp::Remove => "remove",
            PatchOp::Replace => "replace",
            PatchOp::Move => "move",
            PatchOp::Copy => "copy",
            PatchOp::Test => "test",
        };
        let value = || -> Result<Value, Error> {
            let text = op
                .value
                .as_deref()
                .ok_or_else(|| invalid(format!("patch operation '{name}' needs a value")))?;
            json(&format!("the value of patch operation '{name}'"), text)
        };
        let from = || -> Result<String, Error> {
            op.from
                .clone()
                .ok_or_else(|| invalid(format!("patch operation '{name}' needs a from")))
        };
        let path = op.path.clone();
        patch = match op.op {
            PatchOp::Add => patch.add(path, value()?),
            PatchOp::Remove => patch.remove(path),
            PatchOp::Replace => patch.replace(path, value()?),
            PatchOp::Move => patch.move_value(from()?, path),
            PatchOp::Copy => patch.copy(from()?, path),
            PatchOp::Test => patch.test(path, value()?),
        };
    }
    Ok(patch)
}

/// A type query, built with the library's builder.
pub(crate) fn type_query(query: &TypeQuery) -> lws_client::TypeQuery {
    let mut q = lws_client::TypeQuery::new();
    for group in &query.types {
        q = match group {
            QueryGroup::One(iri) => q.all_of([iri.as_str()]),
            QueryGroup::Any(iris) => q.any_of(iris.iter().map(String::as_str)),
        };
    }
    for filter in &query.relations {
        for group in &filter.groups {
            let relation = q.relation(filter.relation.as_str());
            q = match group {
                QueryGroup::One(iri) => relation.all_of([iri.as_str()]),
                QueryGroup::Any(iris) => relation.any_of(iris.iter().map(String::as_str)),
            };
        }
    }
    q
}

// ---------------------------------------------------------------------------------------------
// Results

fn url_text(u: &Url) -> String {
    u.as_str().to_owned()
}

fn opt_url(u: Option<&Url>) -> Option<String> {
    u.map(url_text)
}

pub(crate) fn header_list(headers: &HeaderMap) -> Vec<Header> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

pub(crate) fn metadata(m: &ResourceMetadata) -> Metadata {
    Metadata {
        url: url_text(&m.url),
        status: m.status.as_u16(),
        etag: m.etag.clone(),
        last_modified: m.last_modified.clone(),
        content_type: m.content_type.clone(),
        content_length: m.content_length,
        links: m
            .links
            .iter()
            .map(|l| WitLink {
                href: url_text(&l.href),
                rel: l.rel.clone(),
                params: l
                    .params
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            })
            .collect(),
        linkset: opt_url(m.linkset()),
        parent: opt_url(m.parent()),
        storage: opt_url(m.storage()),
        types: m.types().into_iter().map(str::to_owned).collect(),
        allow: m.allow.clone(),
        accept_patch: m.accept_patch.clone(),
        headers: header_list(&m.headers),
    }
}

pub(crate) fn item(i: &ContainedResource) -> Item {
    Item {
        id: url_text(&i.id),
        types: i.types.clone(),
        format: i.format.clone(),
        size: i.size,
        modified: i.modified_raw.clone(),
    }
}

pub(crate) fn container_page(p: &ContainerPage) -> Page {
    Page {
        id: url_text(&p.id),
        types: p.types.clone(),
        total_items: p.total_items,
        items: p.items.iter().map(item).collect(),
        first: opt_url(p.first.as_ref()),
        next: opt_url(p.next.as_ref()),
        prev: opt_url(p.prev.as_ref()),
        last: opt_url(p.last.as_ref()),
        metadata: metadata(&p.metadata),
    }
}

pub(crate) fn search_page(p: &SearchPage) -> Page {
    Page {
        id: url_text(&p.id),
        types: p.types.clone(),
        total_items: p.total_items,
        items: p.items.iter().map(item).collect(),
        first: opt_url(p.first.as_ref()),
        next: opt_url(p.next.as_ref()),
        prev: opt_url(p.prev.as_ref()),
        last: opt_url(p.last.as_ref()),
        metadata: metadata(&p.metadata),
    }
}

pub(crate) fn type_index_page(p: &TypeIndexPage) -> WitTypeIndexPage {
    WitTypeIndexPage {
        total_items: p.total_items,
        types: p.types.clone(),
        first: opt_url(p.first.as_ref()),
        next: opt_url(p.next.as_ref()),
        prev: opt_url(p.prev.as_ref()),
        last: opt_url(p.last.as_ref()),
        metadata: metadata(&p.metadata),
    }
}

pub(crate) fn created(c: &CreateResult) -> Created {
    Created {
        location: url_text(&c.location),
        metadata: metadata(&c.metadata),
        body: c.body.to_vec(),
    }
}

pub(crate) fn updated(u: &UpdateResult) -> Updated {
    Updated {
        status: u.status.as_u16(),
        etag: u.etag.clone(),
        metadata: metadata(&u.metadata),
        body: u.body.to_vec(),
    }
}

pub(crate) fn storage(s: &StorageDescription) -> WitStorage {
    WitStorage {
        id: url_text(&s.id),
        types: s.types.clone(),
        // The library's `storage_root()` fails when there is no StorageRoot service.
        storage_root: s.storage_root().ok().map(url_text),
        services: s
            .services
            .iter()
            .map(|svc| Service {
                id: svc.id.clone(),
                types: svc.types.clone(),
                service_endpoint: url_text(&svc.service_endpoint),
                subscription_types: svc
                    .property("subscriptionType")
                    .map(|_| svc.subscription_types()),
                raw: Value::Object(svc.raw.clone()).to_string(),
            })
            .collect(),
        verification_methods: s
            .verification_methods
            .iter()
            .map(|vm| VerificationMethod {
                id: vm.id.clone(),
                method_type: vm.method_type.clone(),
                controller: vm.controller.clone(),
                public_key_jwk: vm
                    .public_key_jwk
                    .as_ref()
                    .map(|jwk| Value::Object(jwk.clone()).to_string()),
            })
            .collect(),
        raw: s.raw.to_string(),
    }
}

pub(crate) fn linkset_document(d: &LinksetDocument) -> WitLinkset {
    WitLinkset {
        url: url_text(&d.url),
        etag: d.etag.clone(),
        linkset: d.linkset.to_json().to_string(),
        allow: d.allow.clone(),
        accept_patch: d.accept_patch.clone(),
        metadata: metadata(&d.metadata),
    }
}

pub(crate) fn subscription(s: &Subscription) -> WitSubscription {
    WitSubscription {
        url: url_text(&s.subscription),
        subscription_type: s.subscription_type.clone(),
        expires: s.expires_raw.clone(),
        raw: s.raw.to_string(),
    }
}
