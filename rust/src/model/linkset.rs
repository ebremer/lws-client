// SPDX-License-Identifier: MIT
//! RFC 9264 linksets (`application/linkset+json`) — the LWS metadata resource format.

use http::StatusCode;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use url::Url;

use crate::constants::rel;
use crate::error::{Error, Result};
use crate::headers::rel_eq;
use crate::model::ResourceMetadata;
use crate::patch::{JsonPatch, JsonPointer};

/// A link target object (`{"href": …, "type": …, "title": …}`).
#[derive(Debug, Clone, PartialEq)]
pub struct LinkTarget {
    /// Target URI (as written; may be relative).
    pub href: String,
    /// Target attributes other than `href` (`type`, `title`, `hreflang`, `title*`, …).
    pub attributes: Map<String, Value>,
}

impl LinkTarget {
    /// A target with no attributes.
    pub fn new(href: impl Into<String>) -> Self {
        Self {
            href: href.into(),
            attributes: Map::new(),
        }
    }
    /// Adds an attribute (builder style).
    #[must_use]
    pub fn with_attribute(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.attributes.insert(name.into(), value.into());
        self
    }
    fn to_json(&self) -> Value {
        let mut o = Map::new();
        o.insert("href".into(), Value::String(self.href.clone()));
        for (k, v) in &self.attributes {
            o.insert(k.clone(), v.clone());
        }
        Value::Object(o)
    }
}

/// A link context object: an anchor plus its relations, in document order.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LinkContext {
    /// The context (`anchor`) URI.
    pub anchor: Option<String>,
    /// Relation type → targets, in document order.
    pub relations: Vec<(String, Vec<LinkTarget>)>,
    /// Members that are not relation arrays (preserved for round-tripping).
    pub extra: Map<String, Value>,
}

impl LinkContext {
    /// Targets for a relation type.
    pub fn targets(&self, relation: &str) -> impl Iterator<Item = &LinkTarget> {
        self.relations
            .iter()
            .filter(move |(r, _)| rel_eq(r, relation))
            .flat_map(|(_, t)| t.iter())
    }

    /// The first `up` target with a string `href`: the member's name, the target's index in it
    /// and the `href` as written.
    fn up_link(&self) -> Option<(&str, usize, &str)> {
        if let Some((name, targets)) = self.relations.iter().find(|(r, _)| rel_eq(r, rel::UP)) {
            return targets.first().map(|t| (name.as_str(), 0, t.href.as_str()));
        }
        // A relation with a target that has no string href is kept as it was received.
        let (name, targets) = self
            .extra
            .iter()
            .find(|(k, v)| rel_eq(k, rel::UP) && v.is_array())?;
        targets
            .as_array()?
            .iter()
            .enumerate()
            .find_map(|(i, t)| Some((name.as_str(), i, t.get("href")?.as_str()?)))
    }
}

/// A flattened link from a linkset.
#[derive(Debug, Clone, PartialEq)]
pub struct LinksetLink {
    /// Context anchor.
    pub anchor: Option<String>,
    /// Relation type.
    pub rel: String,
    /// Target URI.
    pub href: String,
    /// Target attributes.
    pub attributes: Map<String, Value>,
}

/// An RFC 9264 linkset.
///
/// ```
/// use lws_client::Linkset;
/// let mut ls = Linkset::new();
/// ls.add("https://s.example/a", "license", "https://creativecommons.org/licenses/by/4.0/", None);
/// assert_eq!(ls.targets("license"), ["https://creativecommons.org/licenses/by/4.0/"]);
/// ```
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Linkset {
    /// Link context objects.
    pub contexts: Vec<LinkContext>,
    /// Top-level members other than `linkset`.
    pub extra: Map<String, Value>,
}

impl Linkset {
    /// An empty linkset.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses `application/linkset+json`.
    pub fn parse(body: &[u8]) -> Result<Self> {
        Self::from_json(&serde_json::from_slice(body)?)
    }

    /// Builds a linkset from its JSON form.
    pub fn from_json(value: &Value) -> Result<Self> {
        let obj = value
            .as_object()
            .ok_or_else(|| Error::Protocol("linkset is not a JSON object".into()))?;
        let list = obj
            .get("linkset")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Protocol("linkset document has no 'linkset' array".into()))?;
        let mut contexts = Vec::with_capacity(list.len());
        for ctx in list {
            let ctx = ctx
                .as_object()
                .ok_or_else(|| Error::Protocol("link context is not an object".into()))?;
            let mut lc = LinkContext::default();
            for (k, v) in ctx {
                if k == "anchor" {
                    lc.anchor = v.as_str().map(str::to_owned);
                    continue;
                }
                match v {
                    Value::Array(targets)
                        if targets
                            .iter()
                            .all(|t| t.get("href").and_then(Value::as_str).is_some()) =>
                    {
                        let targets = targets
                            .iter()
                            .filter_map(Value::as_object)
                            .map(|t| LinkTarget {
                                href: t
                                    .get("href")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                                attributes: t
                                    .iter()
                                    .filter(|(k, _)| *k != "href")
                                    .map(|(k, v)| (k.clone(), v.clone()))
                                    .collect(),
                            })
                            .collect();
                        lc.relations.push((k.clone(), targets));
                    }
                    _ => {
                        lc.extra.insert(k.clone(), v.clone());
                    }
                }
            }
            contexts.push(lc);
        }
        let extra = obj
            .iter()
            .filter(|(k, _)| *k != "linkset")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Ok(Self { contexts, extra })
    }

    /// The JSON form (`{"linkset": [...]}`).
    pub fn to_json(&self) -> Value {
        let contexts: Vec<Value> = self
            .contexts
            .iter()
            .map(|c| {
                let mut o = Map::new();
                if let Some(a) = &c.anchor {
                    o.insert("anchor".into(), Value::String(a.clone()));
                }
                for (r, targets) in &c.relations {
                    o.insert(
                        r.clone(),
                        Value::Array(targets.iter().map(LinkTarget::to_json).collect()),
                    );
                }
                for (k, v) in &c.extra {
                    o.insert(k.clone(), v.clone());
                }
                Value::Object(o)
            })
            .collect();
        let mut root = Map::new();
        root.insert("linkset".into(), Value::Array(contexts));
        for (k, v) in &self.extra {
            root.insert(k.clone(), v.clone());
        }
        Value::Object(root)
    }

    /// All links, flattened.
    pub fn links(&self) -> Vec<LinksetLink> {
        self.contexts
            .iter()
            .flat_map(|c| {
                c.relations.iter().flat_map(move |(r, targets)| {
                    targets.iter().map(move |t| LinksetLink {
                        anchor: c.anchor.clone(),
                        rel: r.clone(),
                        href: t.href.clone(),
                        attributes: t.attributes.clone(),
                    })
                })
            })
            .collect()
    }

    /// Target URIs for a relation type, across all contexts.
    pub fn targets(&self, relation: &str) -> Vec<&str> {
        self.contexts
            .iter()
            .flat_map(|c| c.targets(relation))
            .map(|t| t.href.as_str())
            .collect()
    }

    /// Target URIs for a relation type in the context with the given anchor.
    pub fn targets_for(&self, anchor: &str, relation: &str) -> Vec<&str> {
        self.context(anchor)
            .map(|c| c.targets(relation).map(|t| t.href.as_str()).collect())
            .unwrap_or_default()
    }

    /// The context with the given anchor.
    pub fn context(&self, anchor: &str) -> Option<&LinkContext> {
        self.contexts
            .iter()
            .find(|c| c.anchor.as_deref() == Some(anchor))
    }

    /// Adds a link, creating the context and relation as needed.
    pub fn add(
        &mut self,
        anchor: &str,
        relation: &str,
        href: &str,
        attributes: Option<Map<String, Value>>,
    ) {
        let idx = match self
            .contexts
            .iter()
            .position(|c| c.anchor.as_deref() == Some(anchor))
        {
            Some(i) => i,
            None => {
                self.contexts.push(LinkContext {
                    anchor: Some(anchor.to_owned()),
                    ..Default::default()
                });
                self.contexts.len() - 1
            }
        };
        let ctx = &mut self.contexts[idx];
        let target = LinkTarget {
            href: href.to_owned(),
            attributes: attributes.unwrap_or_default(),
        };
        match ctx.relations.iter_mut().find(|(r, _)| rel_eq(r, relation)) {
            Some((_, targets)) => targets.push(target),
            None => ctx.relations.push((relation.to_owned(), vec![target])),
        }
    }

    /// The JSON Patch that moves `resource` into the container `destination` (lws10-core "Moving
    /// Resources"), for this linkset as read from `linkset_url`: `test` that the resource's `up`
    /// link still holds the target read, and `replace` it with `destination`.
    ///
    /// The resource's link context is the first whose `anchor` resolves to `resource`, or the only
    /// one when it has no anchor; its `up` link is its first `up` target. Without either the
    /// linkset gives nothing to change: [`Error::Protocol`].
    ///
    /// ```
    /// use lws_client::{Linkset, Url};
    /// let ls = Linkset::from_json(&serde_json::json!({"linkset": [
    ///     {"anchor": "/alice/a.txt", "up": [{"href": "/alice/"}]}
    /// ]})).unwrap();
    /// let u = |s| Url::parse(s).unwrap();
    /// let patch = ls
    ///     .move_patch(&u("https://s.example/alice/a.txt.meta"), &u("https://s.example/alice/a.txt"), &u("https://s.example/bob/"))
    ///     .unwrap();
    /// assert_eq!(patch.to_json(), serde_json::json!([
    ///     {"op": "test", "path": "/linkset/0/up/0/href", "value": "/alice/"},
    ///     {"op": "replace", "path": "/linkset/0/up/0/href", "value": "https://s.example/bob/"}
    /// ]));
    /// ```
    pub fn move_patch(
        &self,
        linkset_url: &Url,
        resource: &Url,
        destination: &Url,
    ) -> Result<JsonPatch> {
        let index = self
            .contexts
            .iter()
            .position(|c| {
                c.anchor
                    .as_deref()
                    .and_then(|a| linkset_url.join(a).ok())
                    .is_some_and(|a| a == *resource)
            })
            .or_else(|| match self.contexts.as_slice() {
                [only] if only.anchor.is_none() => Some(0),
                _ => None,
            })
            .ok_or_else(|| {
                Error::Protocol(format!(
                    "the linkset {linkset_url} has no link context for {resource}"
                ))
            })?;
        let (name, target, href) = self.contexts[index].up_link().ok_or_else(|| {
            Error::Protocol(format!(
                "the linkset {linkset_url} has no up link for {resource}"
            ))
        })?;
        let path = JsonPointer::root()
            .push("linkset")
            .push(index)
            .push(name)
            .push(target)
            .push("href");
        Ok(JsonPatch::new()
            .test(path.clone(), href)
            .replace(path, destination.as_str()))
    }

    /// Removes links of a relation type from the context with the given anchor (all targets, or
    /// only `href`). Returns the number of removed links.
    pub fn remove(&mut self, anchor: &str, relation: &str, href: Option<&str>) -> usize {
        let Some(ctx) = self
            .contexts
            .iter_mut()
            .find(|c| c.anchor.as_deref() == Some(anchor))
        else {
            return 0;
        };
        let mut removed = 0;
        for (r, targets) in ctx.relations.iter_mut() {
            if rel_eq(r, relation) {
                let before = targets.len();
                targets.retain(|t| href.is_some_and(|h| h != t.href));
                removed += before - targets.len();
            }
        }
        ctx.relations.retain(|(_, t)| !t.is_empty());
        removed
    }
}

impl Serialize for Linkset {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        self.to_json().serialize(s)
    }
}

impl<'de> Deserialize<'de> for Linkset {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        Linkset::from_json(&v).map_err(serde::de::Error::custom)
    }
}

/// A linkset resource as retrieved by [`Client::read_linkset`](crate::Client::read_linkset).
#[derive(Debug, Clone)]
pub struct LinksetDocument {
    /// URL of the linkset resource (use it for updates).
    pub url: Url,
    /// Entity tag (use it as `If-Match` for updates).
    pub etag: Option<String>,
    /// The linkset.
    pub linkset: Linkset,
    /// Methods from `Allow` (PUT support is optional).
    pub allow: Vec<String>,
    /// Patch formats from `Accept-Patch`.
    pub accept_patch: Vec<String>,
    /// Response metadata.
    pub metadata: ResourceMetadata,
}

/// Result of [`Client::move_resource`](crate::Client::move_resource): where the resource is after
/// the move.
#[derive(Debug, Clone)]
pub struct MoveResult {
    /// Response status (200 or 204).
    pub status: StatusCode,
    /// Absolute URL of the resource after the move.
    pub location: Url,
    /// Absolute URL of its linkset after the move.
    pub linkset: Url,
    /// `true` when the resource kept its identifier (`location` is the URL moved).
    pub identifier_preserved: bool,
    /// The linkset's new entity tag, when returned.
    pub etag: Option<String>,
    /// Response metadata.
    pub metadata: ResourceMetadata,
    /// The updated linkset, when the response carried it.
    pub document: Option<Linkset>,
}

impl MoveResult {
    /// Interprets the answer to the linkset `PATCH` that moved `resource` (`metadata.url` is the
    /// linkset patched). A storage that keeps identifiers answers `204` (or `200` with the
    /// linkset). One that does not answers `200` with the updated linkset, whose `anchor` is the
    /// new identifier, and `Content-Location`, the linkset's new URL: the location is the anchor of
    /// the body's first context with an `up` link, resolved against `Content-Location` (else the
    /// linkset patched).
    pub fn from_response(resource: &Url, metadata: ResourceMetadata, body: &[u8]) -> Result<Self> {
        let linkset = match metadata.header("content-location") {
            Some(l) => metadata
                .url
                .join(l)
                .map_err(|e| Error::Protocol(format!("invalid Content-Location: {e}")))?,
            None => metadata.url.clone(),
        };
        let is_json = metadata.media_type().is_none_or(|t| t.ends_with("json"));
        let document = if body.is_empty() || !is_json {
            None
        } else {
            Some(Linkset::parse(body)?)
        };
        let anchor = document
            .as_ref()
            .and_then(|d| {
                d.contexts
                    .iter()
                    .find(|c| c.targets(rel::UP).next().is_some())
            })
            .and_then(|c| c.anchor.as_deref());
        let location = match anchor {
            Some(a) => linkset
                .join(a)
                .map_err(|e| Error::Protocol(format!("invalid anchor {a:?}: {e}")))?,
            None => resource.clone(),
        };
        Ok(Self {
            status: metadata.status,
            identifier_preserved: location == *resource,
            location,
            linkset,
            etag: metadata.etag.clone(),
            metadata,
            document,
        })
    }
}
