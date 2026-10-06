// SPDX-License-Identifier: MIT
//! RFC 8288 `Link` header parsing and serialization.

use std::collections::BTreeMap;
use std::fmt;

use url::Url;

/// A single typed link (one relation type) from a `Link` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// The absolute link target.
    pub href: Url,
    /// The relation type. Registered relation names are lower-cased; extension relation URIs are
    /// kept as received.
    pub rel: String,
    /// Target attributes, excluding `rel`. Names are lower-cased; values are unquoted. A
    /// parameter without a value has the value `""`.
    pub params: BTreeMap<String, String>,
}

impl Link {
    /// Creates a link with no extra parameters.
    pub fn new(href: Url, rel: impl Into<String>) -> Self {
        Self {
            href,
            rel: rel.into(),
            params: BTreeMap::new(),
        }
    }

    /// Adds a target attribute (builder style).
    #[must_use]
    pub fn with_param(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.params
            .insert(name.into().to_ascii_lowercase(), value.into());
        self
    }

    /// Returns a target attribute by (case-insensitive) name.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// The `type` attribute (media type hint), if present.
    pub fn media_type(&self) -> Option<&str> {
        self.param("type")
    }

    /// The raw `anchor` attribute, if present.
    pub fn anchor(&self) -> Option<&str> {
        self.param("anchor")
    }

    /// Returns `true` when this link has the given relation type (registered names compared
    /// case-insensitively, extension URIs exactly).
    pub fn has_rel(&self, rel: &str) -> bool {
        rel_eq(&self.rel, rel)
    }

    /// Serializes the link as a `Link` header field value: `<href>; rel="rel"; name="value"`.
    pub fn to_header_value(&self) -> String {
        let mut out = format!("<{}>; rel=\"{}\"", self.href, escape(&self.rel));
        for (k, v) in &self.params {
            if v.is_empty() {
                out.push_str(&format!("; {k}"));
            } else {
                out.push_str(&format!("; {k}=\"{}\"", escape(v)));
            }
        }
        out
    }
}

impl fmt::Display for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_header_value())
    }
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Compares relation types: case-insensitive for registered names, exact for extension URIs.
pub(crate) fn rel_eq(a: &str, b: &str) -> bool {
    if a.contains(':') || b.contains(':') {
        a == b
    } else {
        a.eq_ignore_ascii_case(b)
    }
}

/// Parses any number of `Link` header field values, resolving targets against `base`.
///
/// A link-value with several space-separated relation types yields one [`Link`] per relation.
/// Link-values whose target cannot be resolved, or that have no `rel`, are skipped.
///
/// ```
/// use lws_client::headers::parse_link_headers;
/// use url::Url;
/// let base = Url::parse("https://example.org/alice/notes/a.txt").unwrap();
/// let links = parse_link_headers(["</alice/notes/>; rel=\"up\", <b.meta>; rel=linkset"], &base);
/// assert_eq!(links[0].href.as_str(), "https://example.org/alice/notes/");
/// assert_eq!(links[1].rel, "linkset");
/// ```
pub fn parse_link_headers<'a, I>(values: I, base: &Url) -> Vec<Link>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut out = Vec::new();
    for value in values {
        parse_one(value, base, &mut out);
    }
    out
}

fn parse_one(value: &str, base: &Url, out: &mut Vec<Link>) {
    let s: Vec<char> = value.chars().collect();
    let mut i = 0;
    let skip_ws = |i: &mut usize| {
        while *i < s.len() && s[*i].is_whitespace() {
            *i += 1;
        }
    };
    loop {
        while i < s.len() && (s[i].is_whitespace() || s[i] == ',') {
            i += 1;
        }
        if i >= s.len() {
            break;
        }
        if s[i] != '<' {
            // Not a link-value: skip to the next comma.
            while i < s.len() && s[i] != ',' {
                i += 1;
            }
            continue;
        }
        i += 1;
        let start = i;
        while i < s.len() && s[i] != '>' {
            i += 1;
        }
        if i >= s.len() {
            break;
        }
        let target: String = s[start..i].iter().collect();
        i += 1;
        let mut params: BTreeMap<String, String> = BTreeMap::new();
        let mut rel: Option<String> = None;
        loop {
            skip_ws(&mut i);
            if i >= s.len() || s[i] == ',' {
                break;
            }
            if s[i] != ';' {
                // Garbage: skip to the next separator.
                while i < s.len() && s[i] != ';' && s[i] != ',' {
                    i += 1;
                }
                continue;
            }
            i += 1;
            skip_ws(&mut i);
            let ns = i;
            while i < s.len() && !matches!(s[i], '=' | ';' | ',') && !s[i].is_whitespace() {
                i += 1;
            }
            let name: String = s[ns..i].iter().collect::<String>().to_ascii_lowercase();
            skip_ws(&mut i);
            let mut val = String::new();
            if i < s.len() && s[i] == '=' {
                i += 1;
                skip_ws(&mut i);
                if i < s.len() && s[i] == '"' {
                    i += 1;
                    while i < s.len() && s[i] != '"' {
                        if s[i] == '\\' && i + 1 < s.len() {
                            i += 1;
                        }
                        val.push(s[i]);
                        i += 1;
                    }
                    i += 1; // closing quote
                } else {
                    let vs = i;
                    while i < s.len() && !matches!(s[i], ';' | ',') && !s[i].is_whitespace() {
                        i += 1;
                    }
                    val = s[vs..i].iter().collect();
                }
            }
            if name.is_empty() {
                continue;
            }
            if name == "rel" {
                if rel.is_none() {
                    rel = Some(val);
                }
            } else {
                params.entry(name).or_insert(val);
            }
        }
        let (Some(rel), Ok(href)) = (rel, base.join(target.trim())) else {
            continue;
        };
        for r in rel.split_whitespace() {
            let r = if r.contains(':') {
                r.to_owned()
            } else {
                r.to_ascii_lowercase()
            };
            out.push(Link {
                href: href.clone(),
                rel: r,
                params: params.clone(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_header_value() {
        let l = Link::new(Url::parse("https://example.org/x").unwrap(), "describedby")
            .with_param("title", "a \"b\"");
        let base = Url::parse("https://example.org/").unwrap();
        let parsed = parse_link_headers([l.to_header_value().as_str()], &base);
        assert_eq!(parsed, vec![l]);
    }
}
