// SPDX-License-Identifier: MIT
//! `WWW-Authenticate` challenge parsing (RFC 9110 §11.6.1).

use std::collections::BTreeMap;

/// One authentication challenge.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthChallenge {
    /// The authentication scheme as received (compare case-insensitively).
    pub scheme: String,
    /// Auth parameters with lower-cased names and unquoted values.
    pub params: BTreeMap<String, String>,
    /// The token68 form, when the challenge uses it.
    pub token68: Option<String>,
}

impl AuthChallenge {
    /// Returns a parameter by (case-insensitive) name.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
    /// `true` for the `Bearer` scheme.
    pub fn is_bearer(&self) -> bool {
        self.scheme.eq_ignore_ascii_case("bearer")
    }
    /// The LWS `as_uri` parameter (authorization server).
    pub fn as_uri(&self) -> Option<&str> {
        self.param("as_uri")
    }
    /// The `realm` parameter (protection scope; the token audience in LWS).
    pub fn realm(&self) -> Option<&str> {
        self.param("realm")
    }
    /// The OAuth `error` parameter.
    pub fn error(&self) -> Option<&str> {
        self.param("error")
    }
    /// The OAuth `error_description` parameter.
    pub fn error_description(&self) -> Option<&str> {
        self.param("error_description")
    }
}

fn is_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

fn is_token68(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._~+/".contains(c)
}

/// Parses all challenges from any number of `WWW-Authenticate` field values.
///
/// ```
/// use lws_client::headers::parse_www_authenticate;
/// let c = parse_www_authenticate([r#"Bearer as_uri="https://as.example", realm="https://s.example/""#]);
/// assert_eq!(c[0].as_uri(), Some("https://as.example"));
/// ```
pub fn parse_www_authenticate<'a, I>(values: I) -> Vec<AuthChallenge>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut out = Vec::new();
    for value in values {
        let s: Vec<char> = value.chars().collect();
        let mut p = Parser { s: &s, i: 0 };
        p.challenges(&mut out);
    }
    out
}

struct Parser<'a> {
    s: &'a [char],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }
    fn skip_ws(&mut self) {
        while self.peek().is_some_and(char::is_whitespace) {
            self.i += 1;
        }
    }
    fn skip_ws_commas(&mut self) {
        while self.peek().is_some_and(|c| c.is_whitespace() || c == ',') {
            self.i += 1;
        }
    }
    fn token(&mut self) -> String {
        let start = self.i;
        while self.peek().is_some_and(is_tchar) {
            self.i += 1;
        }
        self.s[start..self.i].iter().collect()
    }
    fn quoted(&mut self) -> String {
        self.i += 1; // opening quote
        let mut out = String::new();
        while let Some(c) = self.peek() {
            self.i += 1;
            match c {
                '"' => break,
                '\\' => {
                    if let Some(n) = self.peek() {
                        out.push(n);
                        self.i += 1;
                    }
                }
                _ => out.push(c),
            }
        }
        out
    }
    fn try_token68(&mut self) -> Option<String> {
        let save = self.i;
        let start = self.i;
        while self.peek().is_some_and(is_token68) {
            self.i += 1;
        }
        if self.i == start {
            return None;
        }
        while self.peek() == Some('=') {
            self.i += 1;
        }
        let end = self.i;
        self.skip_ws();
        if self.peek().is_none() || self.peek() == Some(',') {
            Some(self.s[start..end].iter().collect())
        } else {
            self.i = save;
            None
        }
    }
    fn challenges(&mut self, out: &mut Vec<AuthChallenge>) {
        loop {
            self.skip_ws_commas();
            if self.peek().is_none() {
                return;
            }
            let scheme = self.token();
            if scheme.is_empty() {
                self.i += 1; // skip an unexpected character
                continue;
            }
            let mut challenge = AuthChallenge {
                scheme,
                ..Default::default()
            };
            self.skip_ws();
            if let Some(t) = self.try_token68() {
                challenge.token68 = Some(t);
            } else {
                loop {
                    let save = self.i;
                    self.skip_ws_commas();
                    let name = self.token();
                    if name.is_empty() {
                        self.i = save;
                        break;
                    }
                    self.skip_ws();
                    if self.peek() != Some('=') {
                        self.i = save;
                        break;
                    }
                    self.i += 1;
                    self.skip_ws();
                    let value = if self.peek() == Some('"') {
                        self.quoted()
                    } else {
                        let start = self.i;
                        while self.peek().is_some_and(|c| c != ',' && !c.is_whitespace()) {
                            self.i += 1;
                        }
                        self.s[start..self.i].iter().collect()
                    };
                    challenge
                        .params
                        .entry(name.to_ascii_lowercase())
                        .or_insert(value);
                }
            }
            out.push(challenge);
        }
    }
}
