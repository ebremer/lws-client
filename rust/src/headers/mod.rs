// SPDX-License-Identifier: MIT
//! HTTP header parsers and helpers: `Link` (RFC 8288), `WWW-Authenticate` (RFC 9110),
//! structured fields (RFC 8941/9651), problem details (RFC 9457), list-valued headers and `Slug`.

mod link;
mod problem;
pub mod structured;
mod www_authenticate;

use std::fmt;

pub(crate) use link::rel_eq;
pub use link::{Link, parse_link_headers};
pub use problem::ProblemDetails;
pub use www_authenticate::{AuthChallenge, parse_www_authenticate};

/// A header parsing error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

/// Splits comma-separated list headers (`Allow`, `Accept-Patch`, `Accept-Query`), respecting
/// quoted strings; surrounding quotes of a whole element are removed.
///
/// ```
/// use lws_client::headers::parse_list;
/// assert_eq!(parse_list(["GET, HEAD", "PATCH"]), ["GET", "HEAD", "PATCH"]);
/// ```
pub fn parse_list<'a, I>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut out = Vec::new();
    for value in values {
        let mut current = String::new();
        let mut in_quotes = false;
        let mut escaped = false;
        for c in value.chars() {
            if escaped {
                current.push(c);
                escaped = false;
                continue;
            }
            match c {
                '\\' if in_quotes => escaped = true,
                '"' => {
                    in_quotes = !in_quotes;
                    current.push(c);
                }
                ',' if !in_quotes => {
                    push_element(&mut out, &current);
                    current.clear();
                }
                _ => current.push(c),
            }
        }
        push_element(&mut out, &current);
    }
    out
}

fn push_element(out: &mut Vec<String>, element: &str) {
    let t = element.trim();
    if t.is_empty() {
        return;
    }
    let t = t
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(t);
    out.push(t.to_owned());
}

/// Percent-encodes an identity hint for the `Slug` header (RFC 5023 §9.7): printable ASCII is
/// kept, `%` and everything else is encoded as UTF-8 `%XX`.
///
/// ```
/// assert_eq!(lws_client::headers::encode_slug("Grüße 100%.txt"), "Gr%C3%BC%C3%9Fe 100%25.txt");
/// ```
pub fn encode_slug(slug: &str) -> String {
    let mut out = String::with_capacity(slug.len());
    for b in slug.bytes() {
        if (0x20..=0x7e).contains(&b) && b != b'%' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Returns the media type of a `Content-Type` value without parameters, lower-cased.
pub fn essence(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}
