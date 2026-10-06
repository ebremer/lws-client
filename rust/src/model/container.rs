// SPDX-License-Identifier: MIT
//! Container representations (`application/lws+json`) and pagination.

use std::time::SystemTime;

use serde_json::Value;
use url::Url;

use crate::constants::{rel, types as lws_types};
use crate::datetime::parse_rfc3339;
use crate::error::{Error, Result};
use crate::model::ResourceMetadata;
use crate::types::{has_type, string_list};

/// Pagination links of a page (`first`, `next`, `prev`, `last`), absolute.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pagination {
    /// First page.
    pub first: Option<Url>,
    /// Next page (absent on the last page).
    pub next: Option<Url>,
    /// Previous page.
    pub prev: Option<Url>,
    /// Last page.
    pub last: Option<Url>,
}

impl Pagination {
    pub(crate) fn from_metadata(m: &ResourceMetadata) -> Self {
        let l = |r: &str| m.link(r).map(|l| l.href.clone());
        Self {
            first: l(rel::FIRST),
            next: l(rel::NEXT),
            prev: l(rel::PREV),
            last: l(rel::LAST),
        }
    }
}

/// A member of a container listing (or a Type Search result item).
#[derive(Debug, Clone, PartialEq)]
pub struct ContainedResource {
    /// Absolute resource URL.
    pub id: Url,
    /// Raw type values (`"DataResource"`, `"Container"`, custom type IRIs).
    pub types: Vec<String>,
    /// Media type (required for data resources).
    pub format: Option<String>,
    /// Size in bytes.
    pub size: Option<u64>,
    /// Last modification time, when parseable.
    pub modified: Option<SystemTime>,
    /// Raw `modified` value.
    pub modified_raw: Option<String>,
    /// The raw JSON object.
    pub raw: Value,
}

impl ContainedResource {
    pub(crate) fn from_json(value: &Value, base: &Url) -> Result<Self> {
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Protocol("container item without id".into()))?;
        let id = base
            .join(id)
            .map_err(|e| Error::Protocol(format!("invalid item id {id:?}: {e}")))?;
        let modified_raw = value
            .get("modified")
            .and_then(Value::as_str)
            .map(str::to_owned);
        Ok(Self {
            id,
            types: string_list(value.get("type")),
            format: value
                .get("format")
                .and_then(Value::as_str)
                .map(str::to_owned),
            size: value.get("size").and_then(Value::as_u64),
            modified: modified_raw.as_deref().and_then(parse_rfc3339),
            modified_raw,
            raw: value.clone(),
        })
    }

    /// `true` when the item is a container.
    pub fn is_container(&self) -> bool {
        has_type(&self.types, lws_types::CONTAINER)
    }
    /// `true` when the item is a data resource.
    pub fn is_data_resource(&self) -> bool {
        has_type(&self.types, lws_types::DATA_RESOURCE)
    }
    /// `true` when the item has the given type.
    pub fn has_type(&self, wanted: &str) -> bool {
        has_type(&self.types, wanted)
    }
}

pub(crate) fn parse_items(body: &Value, base: &Url) -> Result<Vec<ContainedResource>> {
    match body.get("items") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| ContainedResource::from_json(i, base))
            .collect(),
        Some(_) => Err(Error::Protocol("'items' is not an array".into())),
    }
}

/// One page of a container listing.
#[derive(Debug, Clone)]
pub struct ContainerPage {
    /// Absolute container URL.
    pub id: Url,
    /// Raw type values of the container.
    pub types: Vec<String>,
    /// Total number of members visible to the client (may be approximate).
    pub total_items: Option<u64>,
    /// Members on this page.
    pub items: Vec<ContainedResource>,
    /// First page.
    pub first: Option<Url>,
    /// Next page.
    pub next: Option<Url>,
    /// Previous page.
    pub prev: Option<Url>,
    /// Last page.
    pub last: Option<Url>,
    /// Response metadata (ETag, links, …).
    pub metadata: ResourceMetadata,
    /// The raw JSON body.
    pub raw: Value,
}

impl ContainerPage {
    /// Parses a container representation. Fails with [`Error::Protocol`] when the response is
    /// not an LWS container representation.
    pub fn parse(metadata: ResourceMetadata, body: &[u8]) -> Result<Self> {
        if let Some(mt) = metadata.media_type() {
            if !matches!(
                mt.as_str(),
                "application/lws+json" | "application/ld+json" | "application/json"
            ) {
                return Err(Error::Protocol(format!(
                    "unexpected container media type {mt}"
                )));
            }
        }
        let raw: Value = serde_json::from_slice(body)?;
        let types = string_list(raw.get("type"));
        if !metadata.is_container() && !has_type(&types, lws_types::CONTAINER) {
            return Err(Error::Protocol(format!(
                "{} is not a container",
                metadata.url
            )));
        }
        let base = metadata.url.clone();
        let id = match raw.get("id").and_then(Value::as_str) {
            Some(id) => base
                .join(id)
                .map_err(|e| Error::Protocol(format!("invalid container id: {e}")))?,
            None => base.clone(),
        };
        let items = parse_items(&raw, &base)?;
        let p = Pagination::from_metadata(&metadata);
        Ok(Self {
            id,
            types,
            total_items: raw.get("totalItems").and_then(Value::as_u64),
            items,
            first: p.first,
            next: p.next,
            prev: p.prev,
            last: p.last,
            metadata,
            raw,
        })
    }

    /// The container's entity tag.
    pub fn etag(&self) -> Option<&str> {
        self.metadata.etag.as_deref()
    }
}
