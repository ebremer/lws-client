// SPDX-License-Identifier: MIT
//! Arguments: typed access to a request's `args`, and the argument forms of driver/PROTOCOL.md
//! section 3 (bodies, JSON Patch, type queries, `limit`). A missing or malformed argument is
//! `InvalidArguments`.

use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use lws_client::{JsonPatch, TypeQuery, Url};
use serde_json::{Map, Value};

use crate::Args;
use crate::errors::Failure;

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

/// A URL value. The library takes most URLs as strings and checks them itself; this is for the
/// parameters it takes as [`Url`] values.
pub(crate) fn url(name: &str, value: &str) -> Result<Url> {
    Url::parse(value)
        .map_err(|e| Failure::invalid(format!("argument '{name}': invalid URL {value:?}: {e}")))
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

/// A list of URLs.
pub(crate) fn urls(name: &str, values: &[Value]) -> Result<Vec<Url>> {
    strings(name, values)?
        .into_iter()
        .map(|s| url(name, s))
        .collect()
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

/// An argument document parsed by the library's own model. A document the library rejects is
/// `InvalidArguments`, whatever error the library reports it with (its parsers report a
/// malformed document as a protocol error, which is for responses only).
pub(crate) fn document<T>(
    name: &str,
    value: &Map<String, Value>,
    parse: impl FnOnce(Value) -> lws_client::Result<T>,
) -> Result<T> {
    parse(Value::Object(value.clone()))
        .map_err(|e| Failure::invalid(format!("argument '{name}' is not a valid document: {e}")))
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

/// An RFC 6902 operations array, rebuilt with the library's [`JsonPatch`] builder.
pub(crate) fn patch(value: Option<&Value>) -> Result<JsonPatch> {
    let Some(Value::Array(operations)) = value else {
        return Err(Failure::invalid(
            "argument 'patch' must be an array of operations",
        ));
    };
    let mut patch = JsonPatch::new();
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
        let value = || -> Result<Value> {
            op.get("value").cloned().ok_or_else(|| {
                Failure::invalid(format!("patch operation '{name}' needs a 'value'"))
            })
        };
        patch = match name {
            "add" => patch.add(member("path")?, value()?),
            "remove" => patch.remove(member("path")?),
            "replace" => patch.replace(member("path")?, value()?),
            "move" => patch.move_value(member("from")?, member("path")?),
            "copy" => patch.copy(member("from")?, member("path")?),
            "test" => patch.test(member("path")?, value()?),
            other => {
                return Err(Failure::invalid(format!(
                    "unknown patch operation '{other}'"
                )));
            }
        };
    }
    Ok(patch)
}

/// An `application/lws-query+json` document, rebuilt with the library's [`TypeQuery`] builder:
/// a string group is `all_of([iri])`, an array group `any_of(iris)`, on the key's relation, in
/// order.
pub(crate) fn query(query: &Map<String, Value>) -> Result<TypeQuery> {
    let mut q = TypeQuery::new();
    for (key, groups) in query {
        let Value::Array(groups) = groups else {
            return Err(Failure::invalid(format!(
                "query member '{key}' must be a list of groups"
            )));
        };
        for group in groups {
            q = match group {
                Value::String(iri) if key == "type" => q.all_of([iri.as_str()]),
                Value::String(iri) => q.relation(key.as_str()).all_of([iri.as_str()]),
                Value::Array(iris) => {
                    let iris = iris.iter().map(Value::as_str).collect::<Option<Vec<_>>>();
                    let Some(iris) = iris else {
                        return Err(Failure::invalid(format!(
                            "an OR group of query member '{key}' must be a list of IRIs"
                        )));
                    };
                    if key == "type" {
                        q.any_of(iris)
                    } else {
                        q.relation(key.as_str()).any_of(iris)
                    }
                }
                _ => {
                    return Err(Failure::invalid(format!(
                        "a group of query member '{key}' must be an IRI or a list of IRIs"
                    )));
                }
            };
        }
    }
    Ok(q)
}
