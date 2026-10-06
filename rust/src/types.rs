// SPDX-License-Identifier: MIT
//! Type matching helpers.
//!
//! LWS documents use short terms (`"Container"`), compact IRIs (`"lws:Container"`) and full IRIs
//! (`"https://www.w3.org/ns/lws#Container"`) interchangeably. Models keep the raw values and use
//! these helpers for comparisons.

use std::borrow::Cow;

use serde_json::Value;

use crate::constants::LWS_NS;

/// Expands an LWS short term or `lws:` compact IRI to a full IRI; other values are returned
/// unchanged.
///
/// ```
/// use lws_client::types::expand_term;
/// assert_eq!(expand_term("Container"), "https://www.w3.org/ns/lws#Container");
/// assert_eq!(expand_term("lws:DataResource"), "https://www.w3.org/ns/lws#DataResource");
/// assert_eq!(expand_term("https://schema.org/Person"), "https://schema.org/Person");
/// ```
pub fn expand_term(term: &str) -> Cow<'_, str> {
    if let Some(local) = term.strip_prefix("lws:") {
        Cow::Owned(format!("{LWS_NS}{local}"))
    } else if !term.contains(':') && !term.is_empty() {
        Cow::Owned(format!("{LWS_NS}{term}"))
    } else {
        Cow::Borrowed(term)
    }
}

/// Returns `true` when two type values denote the same type (`Term`, `lws:Term` and the full LWS
/// IRI are equal).
pub fn type_matches(a: &str, b: &str) -> bool {
    a == b || expand_term(a) == expand_term(b)
}

/// Returns `true` when `types` contains a value matching `wanted` (see [`type_matches`]).
pub fn has_type<S: AsRef<str>>(types: &[S], wanted: &str) -> bool {
    types.iter().any(|t| type_matches(t.as_ref(), wanted))
}

/// Reads a JSON value that is either a string or an array of strings.
pub(crate) fn string_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// Serde helper: deserialize a string or an array of strings into a `Vec<String>`.
pub(crate) fn one_or_many<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
    })
}
