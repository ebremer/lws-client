// SPDX-License-Identifier: MIT
//! Resource metadata and read/write results.

use std::time::SystemTime;

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use serde::de::DeserializeOwned;
use url::Url;

use crate::constants::{rel, types as lws_types};
use crate::error::{Error, Result};
use crate::headers::{Link, essence, parse_link_headers, parse_list, rel_eq};
use crate::transport::Response;
use crate::types::type_matches;

/// Metadata parsed from response headers (`ETag`, `Link`, `Content-Type`, `Allow`, …).
#[derive(Debug, Clone)]
pub struct ResourceMetadata {
    /// Final URL of the response (after redirects).
    pub url: Url,
    /// Response status.
    pub status: StatusCode,
    /// Raw entity tag including quotes / `W/` — echo it verbatim in `If-Match`.
    pub etag: Option<String>,
    /// Raw `Last-Modified` value.
    pub last_modified: Option<String>,
    /// Raw `Content-Type` value.
    pub content_type: Option<String>,
    /// `Content-Length`, when present.
    pub content_length: Option<u64>,
    /// All links, resolved against the response URL.
    pub links: Vec<Link>,
    /// Methods from `Allow`.
    pub allow: Vec<String>,
    /// Media types from `Accept-Patch`.
    pub accept_patch: Vec<String>,
    /// All response headers.
    pub headers: HeaderMap,
}

impl ResourceMetadata {
    /// Builds metadata from a response's URL, status and headers.
    pub fn from_parts(url: Url, status: StatusCode, headers: HeaderMap) -> Self {
        let values = |name: &str| -> Vec<&str> {
            headers
                .get_all(name)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect()
        };
        let first = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let links = parse_link_headers(values("link"), &url);
        let allow = parse_list(values("allow"));
        let accept_patch = parse_list(values("accept-patch"));
        Self {
            etag: first("etag"),
            last_modified: first("last-modified"),
            content_type: first("content-type"),
            content_length: first("content-length").and_then(|v| v.trim().parse().ok()),
            links,
            allow,
            accept_patch,
            url,
            status,
            headers,
        }
    }

    /// The first link with the given relation type.
    pub fn link(&self, relation: &str) -> Option<&Link> {
        self.links.iter().find(|l| rel_eq(&l.rel, relation))
    }

    /// All links with the given relation type.
    pub fn links_with<'a>(&'a self, relation: &'a str) -> impl Iterator<Item = &'a Link> + 'a {
        self.links.iter().filter(move |l| rel_eq(&l.rel, relation))
    }

    /// The linkset (metadata) resource (`rel="linkset"`).
    pub fn linkset(&self) -> Option<&Url> {
        self.link(rel::LINKSET).map(|l| &l.href)
    }

    /// The parent container (`rel="up"`).
    pub fn parent(&self) -> Option<&Url> {
        self.link(rel::UP).map(|l| &l.href)
    }

    /// The storage (`rel="https://www.w3.org/ns/lws#storage"`).
    pub fn storage(&self) -> Option<&Url> {
        self.link(rel::STORAGE).map(|l| &l.href)
    }

    /// Targets of `rel="type"` links.
    pub fn types(&self) -> Vec<&str> {
        self.links_with(rel::TYPE)
            .map(|l| l.href.as_str())
            .collect()
    }

    /// `true` when a `rel="type"` link matches `wanted`.
    pub fn has_type(&self, wanted: &str) -> bool {
        self.links_with(rel::TYPE)
            .any(|l| type_matches(l.href.as_str(), wanted))
    }

    /// `true` when the resource is a container.
    pub fn is_container(&self) -> bool {
        self.has_type(lws_types::CONTAINER)
    }

    /// `true` when the resource is a data resource.
    pub fn is_data_resource(&self) -> bool {
        self.has_type(lws_types::DATA_RESOURCE)
    }

    /// The parsed `Last-Modified` time.
    pub fn last_modified_time(&self) -> Option<SystemTime> {
        self.last_modified
            .as_deref()
            .and_then(|v| httpdate::parse_http_date(v).ok())
    }

    /// The `Content-Type` essence (no parameters, lower-cased).
    pub fn media_type(&self) -> Option<String> {
        self.content_type.as_deref().map(essence)
    }

    /// `Content-Range` (for 206 Partial Content).
    pub fn content_range(&self) -> Option<&str> {
        self.header("content-range")
    }

    /// A response header as text.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

/// A resource representation returned by [`Client::read`](crate::Client::read).
#[derive(Debug, Clone)]
pub struct Resource {
    /// Header metadata.
    pub metadata: ResourceMetadata,
    /// The body (empty when [`not_modified`](Self::not_modified)).
    pub body: Bytes,
    /// `true` when a conditional read returned `304 Not Modified`.
    pub not_modified: bool,
}

impl Resource {
    /// The body bytes.
    pub fn bytes(&self) -> &Bytes {
        &self.body
    }

    /// The body decoded as UTF-8 text.
    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.to_vec())
            .map_err(|_| Error::Protocol("body is not valid UTF-8".into()))
    }

    /// The body parsed as JSON.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        Ok(serde_json::from_slice(&self.body)?)
    }

    /// `true` for `206 Partial Content`.
    pub fn is_partial(&self) -> bool {
        self.metadata.status == StatusCode::PARTIAL_CONTENT
    }
}

/// A resource whose body is consumed incrementally, from
/// [`ReadRequest::send_streaming`](crate::ReadRequest::send_streaming).
#[derive(Debug)]
pub struct StreamingResource {
    /// Header metadata.
    pub metadata: ResourceMetadata,
    response: Response,
}

impl StreamingResource {
    pub(crate) fn new(metadata: ResourceMetadata, response: Response) -> Self {
        Self { metadata, response }
    }
    /// The next body chunk, or `None` at the end.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>> {
        Ok(self.response.chunk().await?)
    }
    /// The underlying `reqwest` response (not on WASI, which has no `reqwest`).
    #[cfg(not(target_os = "wasi"))]
    pub fn into_response(self) -> reqwest::Response {
        self.response
    }
}

/// Result of [`Client::create`](crate::Client::create) / [`Client::create_container`](crate::Client::create_container).
#[derive(Debug, Clone)]
pub struct CreateResult {
    /// Absolute URL of the new resource (from `Location`).
    pub location: Url,
    /// Metadata of the `201 Created` response (linkset, up, type links).
    pub metadata: ResourceMetadata,
    /// Optional response body.
    pub body: Bytes,
}

/// Result of an update (`PUT`) or patch (`PATCH`).
#[derive(Debug, Clone)]
pub struct UpdateResult {
    /// Response status (200 or 204).
    pub status: StatusCode,
    /// New entity tag, when returned.
    pub etag: Option<String>,
    /// Response metadata.
    pub metadata: ResourceMetadata,
    /// Optional response body.
    pub body: Bytes,
}
