// SPDX-License-Identifier: MIT
//! JSON Patch (RFC 6902) and JSON Pointer (RFC 6901) — the baseline LWS patch format for
//! resources and linksets.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One JSON Patch operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum PatchOperation {
    /// Add a value.
    Add {
        /// Target location.
        path: String,
        /// Value to add.
        value: Value,
    },
    /// Remove a value.
    Remove {
        /// Target location.
        path: String,
    },
    /// Replace a value.
    Replace {
        /// Target location.
        path: String,
        /// New value.
        value: Value,
    },
    /// Move a value.
    Move {
        /// Source location.
        from: String,
        /// Target location.
        path: String,
    },
    /// Copy a value.
    Copy {
        /// Source location.
        from: String,
        /// Target location.
        path: String,
    },
    /// Test that a value equals the given value.
    Test {
        /// Target location.
        path: String,
        /// Expected value.
        value: Value,
    },
}

/// A JSON Patch document (`application/json-patch+json`), built fluently.
///
/// ```
/// use lws_client::JsonPatch;
/// use serde_json::json;
/// let patch = JsonPatch::new().test("/age", 30).replace("/age", 31).add("/city", "Boston");
/// assert_eq!(patch.to_json()[1], json!({"op": "replace", "path": "/age", "value": 31}));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JsonPatch {
    operations: Vec<PatchOperation>,
}

impl JsonPatch {
    /// An empty patch.
    pub fn new() -> Self {
        Self::default()
    }
    /// Appends an `add` operation.
    #[must_use]
    pub fn add(mut self, path: impl Into<String>, value: impl Into<Value>) -> Self {
        self.operations.push(PatchOperation::Add {
            path: path.into(),
            value: value.into(),
        });
        self
    }
    /// Appends a `remove` operation.
    #[must_use]
    pub fn remove(mut self, path: impl Into<String>) -> Self {
        self.operations
            .push(PatchOperation::Remove { path: path.into() });
        self
    }
    /// Appends a `replace` operation.
    #[must_use]
    pub fn replace(mut self, path: impl Into<String>, value: impl Into<Value>) -> Self {
        self.operations.push(PatchOperation::Replace {
            path: path.into(),
            value: value.into(),
        });
        self
    }
    /// Appends a `move` operation.
    #[must_use]
    pub fn move_value(mut self, from: impl Into<String>, path: impl Into<String>) -> Self {
        self.operations.push(PatchOperation::Move {
            from: from.into(),
            path: path.into(),
        });
        self
    }
    /// Appends a `copy` operation.
    #[must_use]
    pub fn copy(mut self, from: impl Into<String>, path: impl Into<String>) -> Self {
        self.operations.push(PatchOperation::Copy {
            from: from.into(),
            path: path.into(),
        });
        self
    }
    /// Appends a `test` operation.
    #[must_use]
    pub fn test(mut self, path: impl Into<String>, value: impl Into<Value>) -> Self {
        self.operations.push(PatchOperation::Test {
            path: path.into(),
            value: value.into(),
        });
        self
    }
    /// Appends an arbitrary operation.
    pub fn push(&mut self, op: PatchOperation) {
        self.operations.push(op);
    }
    /// The operations.
    pub fn operations(&self) -> &[PatchOperation] {
        &self.operations
    }
    /// Number of operations.
    pub fn len(&self) -> usize {
        self.operations.len()
    }
    /// `true` when there are no operations.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }
    /// The patch as a JSON array.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Array(Vec::new()))
    }
    /// The serialized patch body.
    pub fn to_vec(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_else(|_| b"[]".to_vec())
    }
}

impl From<Vec<PatchOperation>> for JsonPatch {
    fn from(operations: Vec<PatchOperation>) -> Self {
        Self { operations }
    }
}

/// A JSON Pointer (RFC 6901), built from unescaped segments.
///
/// ```
/// use lws_client::JsonPointer;
/// let p = JsonPointer::root().push("linkset").push(0).push("https://example.org/rel").push("-");
/// assert_eq!(p.as_str(), "/linkset/0/https:~1~1example.org~1rel/-");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct JsonPointer(String);

impl JsonPointer {
    /// The empty (whole-document) pointer.
    pub fn root() -> Self {
        Self(String::new())
    }
    /// Appends a segment, escaping `~` and `/`.
    #[must_use]
    pub fn push(mut self, segment: impl fmt::Display) -> Self {
        self.0.push('/');
        self.0.push_str(&Self::escape(&segment.to_string()));
        self
    }
    /// Builds a pointer from unescaped segments.
    pub fn from_segments<I, S>(segments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        segments
            .into_iter()
            .fold(Self::root(), |p, s| p.push(s.as_ref()))
    }
    /// Escapes one segment (`~` → `~0`, `/` → `~1`).
    pub fn escape(segment: &str) -> Cow<'_, str> {
        if segment.contains(['~', '/']) {
            Cow::Owned(segment.replace('~', "~0").replace('/', "~1"))
        } else {
            Cow::Borrowed(segment)
        }
    }
    /// Unescapes one segment (`~1` → `/`, `~0` → `~`).
    pub fn unescape(segment: &str) -> Cow<'_, str> {
        if segment.contains('~') {
            Cow::Owned(segment.replace("~1", "/").replace("~0", "~"))
        } else {
            Cow::Borrowed(segment)
        }
    }
    /// The pointer string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JsonPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<JsonPointer> for String {
    fn from(p: JsonPointer) -> String {
        p.0
    }
}
