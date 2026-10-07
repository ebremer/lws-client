// SPDX-License-Identifier: MIT
//! Arguments: typed access to a request's `args`, and the argument forms of driver/PROTOCOL.md
//! section 3 (bodies, JSON Patch, type queries, `limit`). A missing or malformed argument is
//! `InvalidArguments`.

use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use serde_json::{Map, Value};

use crate::Args;
use crate::errors::Failure;
use crate::lws::{PatchOp, PatchOperation, QueryGroup, RelationFilter, TypeQuery};

type Result<T> = std::result::Result<T, Failure>;

/// The kinds of JSON value an argument can be required to be.
#[derive(Clone, Copy)]
enum Kind {
    String,
    Boolean,
    Number,
    Object,
    Array,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::String => "string",
            Kind::Boolean => "boolean",
            Kind::Number => "number",
            Kind::Object => "object",
            Kind::Array => "array",
        }
    }
    fn matches(self, v: &Value) -> bool {
        match self {
            Kind::String => v.is_string(),
            Kind::Boolean => v.is_boolean(),
            Kind::Number => v.is_number(),
            Kind::Object => v.is_object(),
            Kind::Array => v.is_array(),
        }
    }
}

/// An argument of the given kind; `None` when absent (omitted or `null`).
fn optional<'a>(args: &'a Args, name: &str, kind: Kind) -> Result<Option<&'a Value>> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) if kind.matches(v) => Ok(Some(v)),
        Some(_) => Err(Failure::invalid(format!(
            "argument '{name}' must be a {}",
            kind.name()
        ))),
    }
}

fn required<'a>(args: &'a Args, name: &str, kind: Kind) -> Result<&'a Value> {
    optional(args, name, kind)?
        .ok_or_else(|| Failure::invalid(format!("missing argument '{name}'")))
}

pub(crate) fn required_str<'a>(args: &'a Args, name: &str) -> Result<&'a str> {
    Ok(required(args, name, Kind::String)?
        .as_str()
        .unwrap_or_default())
}

pub(crate) fn optional_str<'a>(args: &'a Args, name: &str) -> Result<Option<&'a str>> {
    Ok(optional(args, name, Kind::String)?.and_then(Value::as_str))
}

pub(crate) fn optional_bool(args: &Args, name: &str) -> Result<Option<bool>> {
    Ok(optional(args, name, Kind::Boolean)?.and_then(Value::as_bool))
}

pub(crate) fn required_object<'a>(args: &'a Args, name: &str) -> Result<&'a Map<String, Value>> {
    Ok(required(args, name, Kind::Object)?
        .as_object()
        .expect("checked to be an object"))
}

pub(crate) fn optional_object<'a>(
    args: &'a Args,
    name: &str,
) -> Result<Option<&'a Map<String, Value>>> {
    Ok(optional(args, name, Kind::Object)?.and_then(Value::as_object))
}

pub(crate) fn required_array<'a>(args: &'a Args, name: &str) -> Result<&'a [Value]> {
    Ok(required(args, name, Kind::Array)?
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default())
}

pub(crate) fn optional_array<'a>(args: &'a Args, name: &str) -> Result<Option<&'a [Value]>> {
    Ok(optional(args, name, Kind::Array)?
        .and_then(Value::as_array)
        .map(Vec::as_slice))
}

/// A JSON number that is a non-negative integer (`3` or `3.0`).
fn non_negative_integer(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| {
        v.as_f64()
            .filter(|f| f.is_finite() && *f >= 0.0 && f.fract() == 0.0 && *f <= u64::MAX as f64)
            .map(|f| f as u64)
    })
}

/// An optional non-negative integer argument.
pub(crate) fn optional_index(args: &Args, name: &str) -> Result<Option<u64>> {
    match optional(args, name, Kind::Number)? {
        None => Ok(None),
        Some(v) => non_negative_integer(v).map(Some).ok_or_else(|| {
            Failure::invalid(format!("argument '{name}' must be a non-negative integer"))
        }),
    }
}

/// An optional positive integer argument.
pub(crate) fn optional_positive(args: &Args, name: &str) -> Result<Option<u64>> {
    match optional(args, name, Kind::Number)? {
        None => Ok(None),
        Some(v) => non_negative_integer(v)
            .filter(|n| *n > 0)
            .map(Some)
            .ok_or_else(|| {
                Failure::invalid(format!("argument '{name}' must be a positive integer"))
            }),
    }
}

/// The `limit` of a lazy sequence (default 1000).
pub(crate) fn limit(args: &Args) -> Result<usize> {
    let limit = optional_index(args, "limit")?.unwrap_or(1000);
    Ok(usize::try_from(limit).unwrap_or(usize::MAX))
}

/// A list of strings.
pub(crate) fn strings<'a>(name: &str, values: &'a [Value]) -> Result<Vec<&'a str>> {
    values
        .iter()
        .map(|v| {
            v.as_str().ok_or_else(|| {
                Failure::invalid(format!("argument '{name}' must be a list of strings"))
            })
        })
        .collect()
}

/// A list of strings, owned.
pub(crate) fn owned_strings(name: &str, values: &[Value]) -> Result<Vec<String>> {
    Ok(strings(name, values)?
        .into_iter()
        .map(str::to_owned)
        .collect())
}

/// Standard, padded base64, decoded strictly: only the standard alphabet with its canonical
/// padding. As in the other adapters, the unused low bits of the last symbol are not checked.
const STRICT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// Decodes a base64 argument.
pub(crate) fn base64(name: &str, value: &str) -> Result<Vec<u8>> {
    STRICT_BASE64
        .decode(value)
        .map_err(|e| Failure::invalid(format!("argument '{name}' is not base64: {e}")))
}

/// An argument document, as the JSON text the component takes. The component parses it with the
/// library's own model, and reports a document the library rejects as `invalid-input`.
pub(crate) fn document(value: &Map<String, Value>) -> String {
    Value::Object(value.clone()).to_string()
}

/// A request body (`{"text"}`, `{"base64"}` or `{"json"}`) as bytes, with the content type it
/// implies when `contentType` is not given. An absent body is empty.
pub(crate) fn body(body: Option<&Value>, content_type: Option<&str>) -> Result<(Vec<u8>, String)> {
    let with = |default: &str| content_type.unwrap_or(default).to_owned();
    let body = match body {
        None | Some(Value::Null) => return Ok((Vec::new(), with("application/octet-stream"))),
        Some(Value::Object(o)) => o,
        Some(_) => return Err(Failure::invalid("argument 'body' must be an object")),
    };
    if let Some(Value::String(text)) = body.get("text") {
        return Ok((text.as_bytes().to_vec(), with("text/plain")));
    }
    if let Some(Value::String(b64)) = body.get("base64") {
        return Ok((
            base64("body.base64", b64)?,
            with("application/octet-stream"),
        ));
    }
    if let Some(json) = body.get("json") {
        let bytes = serde_json::to_vec(json).expect("a JSON value serializes");
        return Ok((bytes, with("application/json")));
    }
    Err(Failure::invalid(
        "argument 'body' must have text, base64 or json",
    ))
}

/// An RFC 6902 operations array, as the component's patch operations (which it rebuilds with
/// the library's `JsonPatch` builder).
pub(crate) fn patch(value: Option<&Value>) -> Result<Vec<PatchOperation>> {
    let Some(Value::Array(operations)) = value else {
        return Err(Failure::invalid(
            "argument 'patch' must be an array of operations",
        ));
    };
    let mut patch = Vec::new();
    for op in operations {
        let Some(name) = op.get("op").and_then(Value::as_str) else {
            return Err(Failure::invalid(
                "a patch operation must be an object with an op",
            ));
        };
        let member = |member: &str| -> Result<String> {
            op.get(member)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    Failure::invalid(format!(
                        "patch operation '{name}' needs a string '{member}'"
                    ))
                })
        };
        // `null` is a value of its own here: only a missing member is missing.
        let value = || -> Result<Option<String>> {
            op.get("value").map(|v| Some(v.to_string())).ok_or_else(|| {
                Failure::invalid(format!("patch operation '{name}' needs a 'value'"))
            })
        };
        let (op, from, value) = match name {
            "add" => (PatchOp::Add, None, value()?),
            "remove" => (PatchOp::Remove, None, None),
            "replace" => (PatchOp::Replace, None, value()?),
            "move" => (PatchOp::Move, Some(member("from")?), None),
            "copy" => (PatchOp::Copy, Some(member("from")?), None),
            "test" => (PatchOp::Test, None, value()?),
            other => {
                return Err(Failure::invalid(format!(
                    "unknown patch operation '{other}'"
                )));
            }
        };
        patch.push(PatchOperation {
            op,
            path: member("path")?,
            from,
            value,
        });
    }
    Ok(patch)
}

/// An `application/lws-query+json` document, as the component's type query: a string group is
/// `one`, an array group `any`, on the key's relation, in order. (The component rebuilds it with
/// the library's `TypeQuery` builder: `all_of([iri])` and `any_of(iris)`.)
pub(crate) fn query(query: &Map<String, Value>) -> Result<TypeQuery> {
    let mut q = TypeQuery {
        types: Vec::new(),
        relations: Vec::new(),
    };
    for (key, groups) in query {
        let Value::Array(groups) = groups else {
            return Err(Failure::invalid(format!(
                "query member '{key}' must be a list of groups"
            )));
        };
        let mut converted = Vec::new();
        for group in groups {
            converted.push(match group {
                Value::String(iri) => QueryGroup::One(iri.clone()),
                Value::Array(iris) => {
                    let iris = iris
                        .iter()
                        .map(|v| v.as_str().map(str::to_owned))
                        .collect::<Option<Vec<_>>>();
                    let Some(iris) = iris else {
                        return Err(Failure::invalid(format!(
                            "an OR group of query member '{key}' must be a list of IRIs"
                        )));
                    };
                    QueryGroup::Any(iris)
                }
                _ => {
                    return Err(Failure::invalid(format!(
                        "a group of query member '{key}' must be an IRI or a list of IRIs"
                    )));
                }
            });
        }
        if key == "type" {
            q.types.extend(converted);
        } else {
            q.relations.push(RelationFilter {
                relation: key.clone(),
                groups: converted,
            });
        }
    }
    Ok(q)
}
