// SPDX-License-Identifier: MIT
//! Type Index and Type Search services (`application/lws-query+json`, HTTP `QUERY`).

use serde_json::{Map, Value};
use url::Url;

use crate::error::{Error, Result};
use crate::model::{ContainedResource, Pagination, ResourceMetadata, parse_items};
use crate::types::string_list;

#[derive(Debug, Clone, PartialEq)]
enum Group {
    One(String),
    Any(Vec<String>),
}

/// A type search filter in conjunctive normal form (AND of OR-groups).
///
/// ```
/// use lws_client::TypeQuery;
/// use serde_json::json;
/// let q = TypeQuery::new()
///     .any_of(["https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"])
///     .all_of(["https://www.w3.org/ns/lws#DataResource"]);
/// assert_eq!(q.to_json().unwrap(), json!({"type": [
///     ["https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person"],
///     "https://www.w3.org/ns/lws#DataResource"
/// ]}));
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TypeQuery {
    keys: Vec<(String, Vec<Group>)>,
}

/// Builder step for filtering on an indexed relation; see [`TypeQuery::relation`].
#[derive(Debug, Clone)]
pub struct RelationFilter {
    query: TypeQuery,
    relation: String,
}

impl RelationFilter {
    /// Each value becomes its own AND group for this relation.
    pub fn all_of<I: IntoIterator<Item = S>, S: Into<String>>(mut self, values: I) -> TypeQuery {
        self.query.push_all(&self.relation, values);
        self.query
    }
    /// One OR group for this relation.
    pub fn any_of<I: IntoIterator<Item = S>, S: Into<String>>(mut self, values: I) -> TypeQuery {
        self.query.push_any(&self.relation, values);
        self.query
    }
}

impl TypeQuery {
    /// An empty query (matches every visible resource).
    pub fn new() -> Self {
        Self::default()
    }

    fn groups(&mut self, key: &str) -> &mut Vec<Group> {
        if let Some(i) = self.keys.iter().position(|(k, _)| k == key) {
            &mut self.keys[i].1
        } else {
            self.keys.push((key.to_owned(), Vec::new()));
            &mut self.keys.last_mut().expect("just pushed").1
        }
    }
    fn push_all<I: IntoIterator<Item = S>, S: Into<String>>(&mut self, key: &str, values: I) {
        let groups: Vec<Group> = values.into_iter().map(|v| Group::One(v.into())).collect();
        self.groups(key).extend(groups);
    }
    fn push_any<I: IntoIterator<Item = S>, S: Into<String>>(&mut self, key: &str, values: I) {
        let group = Group::Any(values.into_iter().map(Into::into).collect());
        self.groups(key).push(group);
    }

    /// Resources must have every one of these types (one AND group per type).
    #[must_use]
    pub fn all_of<I: IntoIterator<Item = S>, S: Into<String>>(mut self, types: I) -> Self {
        self.push_all("type", types);
        self
    }

    /// Resources must have at least one of these types (one OR group).
    #[must_use]
    pub fn any_of<I: IntoIterator<Item = S>, S: Into<String>>(mut self, types: I) -> Self {
        self.push_any("type", types);
        self
    }

    /// Filters on an indexed descriptive relation (same grammar as `type`).
    pub fn relation(self, relation: impl Into<String>) -> RelationFilter {
        RelationFilter {
            query: self,
            relation: relation.into(),
        }
    }

    /// Validates the query (absolute IRIs, no empty OR groups).
    pub fn validate(&self) -> Result<()> {
        for (key, groups) in &self.keys {
            if key.starts_with('@') {
                return Err(Error::InvalidInput(format!("invalid filter key {key:?}")));
            }
            for g in groups {
                let values: &[String] = match g {
                    Group::One(v) => std::slice::from_ref(v),
                    Group::Any(v) if v.is_empty() => {
                        return Err(Error::InvalidInput(format!("empty OR group for {key:?}")));
                    }
                    Group::Any(v) => v,
                };
                for v in values {
                    if !is_absolute_iri(v) {
                        return Err(Error::InvalidInput(format!("{v:?} is not an absolute IRI")));
                    }
                }
            }
        }
        Ok(())
    }

    /// The validated filter document.
    pub fn to_json(&self) -> Result<Value> {
        self.validate()?;
        let mut o = Map::new();
        for (key, groups) in &self.keys {
            let arr: Vec<Value> = groups
                .iter()
                .map(|g| match g {
                    Group::One(v) => Value::String(v.clone()),
                    Group::Any(v) if v.len() == 1 => Value::String(v[0].clone()),
                    Group::Any(v) => Value::Array(v.iter().cloned().map(Value::String).collect()),
                })
                .collect();
            o.insert(key.clone(), Value::Array(arr));
        }
        Ok(Value::Object(o))
    }
}

/// `true` for an absolute IRI (`scheme:rest`, no whitespace).
pub(crate) fn is_absolute_iri(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        && !rest.is_empty()
        && !s
            .chars()
            .any(|c| c.is_whitespace() || "<>\"{}|\\^`".contains(c))
}

/// One page of a Type Index listing.
#[derive(Debug, Clone)]
pub struct TypeIndexPage {
    /// Number of types visible to the client.
    pub total_items: Option<u64>,
    /// Type IRIs on this page.
    pub types: Vec<String>,
    /// First page.
    pub first: Option<Url>,
    /// Next page.
    pub next: Option<Url>,
    /// Previous page.
    pub prev: Option<Url>,
    /// Last page.
    pub last: Option<Url>,
    /// Response metadata.
    pub metadata: ResourceMetadata,
    /// Raw JSON body.
    pub raw: Value,
}

impl TypeIndexPage {
    /// Parses a Type Index page.
    pub fn parse(metadata: ResourceMetadata, body: &[u8]) -> Result<Self> {
        let raw: Value = serde_json::from_slice(body)?;
        let types = match raw.get("items") {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|i| match i {
                    Value::String(s) => Some(s.clone()),
                    _ => i.get("id").and_then(Value::as_str).map(str::to_owned),
                })
                .collect(),
            _ => Vec::new(),
        };
        let p = Pagination::from_metadata(&metadata);
        Ok(Self {
            total_items: raw.get("totalItems").and_then(Value::as_u64),
            types,
            first: p.first,
            next: p.next,
            prev: p.prev,
            last: p.last,
            metadata,
            raw,
        })
    }
}

/// One page of Type Search results (a synthetic `ContainerPage`).
#[derive(Debug, Clone)]
pub struct SearchPage {
    /// The page's `id`, absolute; the page's own URL when the body names none.
    pub id: Url,
    /// Number of matching resources visible to the client.
    pub total_items: Option<u64>,
    /// Raw type values of the page (`ContainerPage`).
    pub types: Vec<String>,
    /// Matching resources on this page.
    pub items: Vec<ContainedResource>,
    /// First page.
    pub first: Option<Url>,
    /// Next page (dereference with GET).
    pub next: Option<Url>,
    /// Previous page.
    pub prev: Option<Url>,
    /// Last page.
    pub last: Option<Url>,
    /// Response metadata.
    pub metadata: ResourceMetadata,
    /// Raw JSON body.
    pub raw: Value,
}

impl SearchPage {
    /// Parses a search result page.
    pub fn parse(metadata: ResourceMetadata, body: &[u8]) -> Result<Self> {
        let raw: Value = serde_json::from_slice(body)?;
        let items = parse_items(&raw, &metadata.url)?;
        let p = Pagination::from_metadata(&metadata);
        let id = raw
            .get("id")
            .or_else(|| raw.get("@id"))
            .and_then(Value::as_str)
            .and_then(|id| metadata.url.join(id).ok())
            .unwrap_or_else(|| metadata.url.clone());
        Ok(Self {
            id,
            total_items: raw.get("totalItems").and_then(Value::as_u64),
            types: string_list(raw.get("type")),
            items,
            first: p.first,
            next: p.next,
            prev: p.prev,
            last: p.last,
            metadata,
            raw,
        })
    }
}
