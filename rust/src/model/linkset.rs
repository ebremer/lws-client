// SPDX-License-Identifier: MIT
//! RFC 9264 linksets (`application/linkset+json`) — the LWS metadata resource format.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use url::Url;

use crate::error::{Error, Result};
use crate::headers::rel_eq;
use crate::model::ResourceMetadata;

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
