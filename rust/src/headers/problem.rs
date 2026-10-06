// SPDX-License-Identifier: MIT
//! RFC 9457 problem details.

use serde_json::{Map, Value};

/// An RFC 9457 problem details object attached to error responses.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProblemDetails {
    /// `type`: a URI identifying the problem type.
    pub problem_type: Option<String>,
    /// `title`: short summary.
    pub title: Option<String>,
    /// `status`: the HTTP status code.
    pub status: Option<u16>,
    /// `detail`: human-readable explanation.
    pub detail: Option<String>,
    /// `instance`: URI of this occurrence.
    pub instance: Option<String>,
    /// Extension members.
    pub extensions: Map<String, Value>,
}

impl ProblemDetails {
    /// Builds a problem from a JSON object when it has at least one of the standard members.
    pub fn from_json(value: &Value) -> Option<Self> {
        let obj = value.as_object()?;
        let standard = ["type", "title", "status", "detail", "instance"];
        if !standard.iter().any(|k| obj.contains_key(*k)) {
            return None;
        }
        let s = |k: &str| obj.get(k).and_then(Value::as_str).map(str::to_owned);
        Some(Self {
            problem_type: s("type"),
            title: s("title"),
            status: obj
                .get("status")
                .and_then(Value::as_u64)
                .and_then(|n| u16::try_from(n).ok()),
            detail: s("detail"),
            instance: s("instance"),
            extensions: obj
                .iter()
                .filter(|(k, _)| !standard.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })
    }

    /// Parses a problem from a response body.
    pub fn parse(body: &[u8]) -> Option<Self> {
        serde_json::from_slice::<Value>(body)
            .ok()
            .as_ref()
            .and_then(Self::from_json)
    }
}
