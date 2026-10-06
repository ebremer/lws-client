// SPDX-License-Identifier: MIT
//! Structured Field Values (RFC 8941 / RFC 9651): the dictionary subset used by
//! `Signature-Input`, `Signature` and `Content-Digest`.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_PAD_INDIFFERENT};

use super::ParseError;

/// A bare item value.
#[derive(Debug, Clone, PartialEq)]
pub enum BareItem {
    /// Integer (up to 15 digits).
    Integer(i64),
    /// Decimal (up to 12 integer and 3 fractional digits).
    Decimal(f64),
    /// String.
    String(String),
    /// Token.
    Token(String),
    /// Byte sequence (`:base64:`).
    ByteSequence(Vec<u8>),
    /// Boolean (`?1` / `?0`).
    Boolean(bool),
    /// Date (`@seconds`, RFC 9651).
    Date(i64),
    /// Display string (`%"..."`, RFC 9651).
    DisplayString(String),
}

impl BareItem {
    /// The string value, for [`BareItem::String`].
    pub fn as_str(&self) -> Option<&str> {
        match self {
            BareItem::String(s) => Some(s),
            _ => None,
        }
    }
    /// The token value, for [`BareItem::Token`].
    pub fn as_token(&self) -> Option<&str> {
        match self {
            BareItem::Token(s) => Some(s),
            _ => None,
        }
    }
    /// The integer value, for [`BareItem::Integer`].
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            BareItem::Integer(n) => Some(*n),
            _ => None,
        }
    }
    /// The bytes, for [`BareItem::ByteSequence`].
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            BareItem::ByteSequence(b) => Some(b),
            _ => None,
        }
    }
    /// The boolean value, for [`BareItem::Boolean`].
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            BareItem::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    /// Canonical serialization (RFC 8941 §4.1).
    pub fn serialize(&self) -> String {
        match self {
            BareItem::Integer(n) => n.to_string(),
            BareItem::Decimal(d) => {
                let rounded = (d * 1000.0).round() / 1000.0;
                let mut s = format!("{rounded:.3}");
                while s.ends_with('0') && !s.ends_with(".0") {
                    s.pop();
                }
                s
            }
            BareItem::String(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
            BareItem::Token(t) => t.clone(),
            BareItem::ByteSequence(b) => format!(":{}:", STANDARD.encode(b)),
            BareItem::Boolean(b) => {
                if *b {
                    "?1".into()
                } else {
                    "?0".into()
                }
            }
            BareItem::Date(n) => format!("@{n}"),
            BareItem::DisplayString(s) => {
                let mut out = String::from("%\"");
                for byte in s.as_bytes() {
                    if *byte == b'%' || *byte == b'"' || !(0x20..=0x7e).contains(byte) {
                        out.push_str(&format!("%{byte:02x}"));
                    } else {
                        out.push(*byte as char);
                    }
                }
                out.push('"');
                out
            }
        }
    }
}

/// Ordered parameters (later duplicates overwrite earlier ones in place).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Parameters(pub Vec<(String, BareItem)>);

impl Parameters {
    /// Looks up a parameter.
    pub fn get(&self, key: &str) -> Option<&BareItem> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
    /// Inserts or overwrites a parameter.
    pub fn insert(&mut self, key: impl Into<String>, value: BareItem) {
        let key = key.into();
        if let Some(slot) = self.0.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.0.push((key, value));
        }
    }
    /// Iterates parameters in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &BareItem)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }
    /// `true` when there are no parameters.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Canonical serialization (`;key=value…`).
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        for (k, v) in &self.0 {
            out.push(';');
            out.push_str(k);
            if *v != BareItem::Boolean(true) {
                out.push('=');
                out.push_str(&v.serialize());
            }
        }
        out
    }
}

/// An item with parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    /// The value.
    pub value: BareItem,
    /// The parameters.
    pub params: Parameters,
}

impl Item {
    /// Canonical serialization.
    pub fn serialize(&self) -> String {
        format!("{}{}", self.value.serialize(), self.params.serialize())
    }
}

/// An inner list with parameters.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct InnerList {
    /// The items.
    pub items: Vec<Item>,
    /// The list parameters.
    pub params: Parameters,
}

impl InnerList {
    /// Canonical serialization, e.g. `("@method" "@path");created=1;keyid="k"`.
    pub fn serialize(&self) -> String {
        let items: Vec<String> = self.items.iter().map(Item::serialize).collect();
        format!("({}){}", items.join(" "), self.params.serialize())
    }
}

/// A dictionary member value.
#[derive(Debug, Clone, PartialEq)]
pub enum MemberValue {
    /// A single item.
    Item(Item),
    /// An inner list.
    InnerList(InnerList),
}

impl MemberValue {
    /// Canonical serialization.
    pub fn serialize(&self) -> String {
        match self {
            MemberValue::Item(i) => i.serialize(),
            MemberValue::InnerList(l) => l.serialize(),
        }
    }
}

/// An ordered dictionary.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Dictionary(pub Vec<(String, MemberValue)>);

impl Dictionary {
    /// Parses a dictionary field value.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        parse_dictionary(input)
    }
    /// Looks up a member.
    pub fn get(&self, key: &str) -> Option<&MemberValue> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
    /// Iterates members in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &MemberValue)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }
    /// Number of members.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// `true` when empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Parses a structured-field dictionary (RFC 8941 §4.2.2).
///
/// ```
/// use lws_client::headers::structured::parse_dictionary;
/// let d = parse_dictionary(r#"sig1=("@method" "@path");created=1;keyid="k""#).unwrap();
/// assert_eq!(d.get("sig1").unwrap().serialize(), r#"("@method" "@path");created=1;keyid="k""#);
/// ```
pub fn parse_dictionary(input: &str) -> Result<Dictionary, ParseError> {
    let mut p = P {
        s: input.as_bytes(),
        i: 0,
    };
    p.skip_sp();
    let mut dict = Dictionary::default();
    if p.eof() {
        return Ok(dict);
    }
    loop {
        let key = p.key()?;
        let value = if p.peek() == Some(b'=') {
            p.i += 1;
            p.item_or_inner_list()?
        } else {
            let params = p.parameters()?;
            MemberValue::Item(Item {
                value: BareItem::Boolean(true),
                params,
            })
        };
        if let Some(slot) = dict.0.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            dict.0.push((key, value));
        }
        p.skip_ows();
        if p.eof() {
            return Ok(dict);
        }
        if p.peek() != Some(b',') {
            return Err(p.err("expected ','"));
        }
        p.i += 1;
        p.skip_ows();
        if p.eof() {
            return Err(p.err("trailing comma"));
        }
    }
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
}

impl P<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn eof(&self) -> bool {
        self.i >= self.s.len()
    }
    fn err(&self, msg: &str) -> ParseError {
        ParseError(format!("structured field: {msg} at offset {}", self.i))
    }
    fn skip_sp(&mut self) {
        while self.peek() == Some(b' ') {
            self.i += 1;
        }
    }
    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.i += 1;
        }
    }
    fn key(&mut self) -> Result<String, ParseError> {
        match self.peek() {
            Some(c) if c.is_ascii_lowercase() || c == b'*' => {}
            _ => return Err(self.err("invalid key")),
        }
        let start = self.i;
        while matches!(self.peek(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-.*".contains(&c))
        {
            self.i += 1;
        }
        Ok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }
    fn item_or_inner_list(&mut self) -> Result<MemberValue, ParseError> {
        if self.peek() == Some(b'(') {
            self.inner_list().map(MemberValue::InnerList)
        } else {
            self.item().map(MemberValue::Item)
        }
    }
    fn inner_list(&mut self) -> Result<InnerList, ParseError> {
        self.i += 1; // '('
        let mut items = Vec::new();
        loop {
            self.skip_sp();
            match self.peek() {
                None => return Err(self.err("unterminated inner list")),
                Some(b')') => {
                    self.i += 1;
                    let params = self.parameters()?;
                    return Ok(InnerList { items, params });
                }
                _ => {
                    items.push(self.item()?);
                    if !matches!(self.peek(), Some(b' ' | b')')) {
                        return Err(self.err("expected SP or ')' in inner list"));
                    }
                }
            }
        }
    }
    fn item(&mut self) -> Result<Item, ParseError> {
        let value = self.bare_item()?;
        let params = self.parameters()?;
        Ok(Item { value, params })
    }
    fn parameters(&mut self) -> Result<Parameters, ParseError> {
        let mut params = Parameters::default();
        while self.peek() == Some(b';') {
            self.i += 1;
            self.skip_sp();
            let key = self.key()?;
            let value = if self.peek() == Some(b'=') {
                self.i += 1;
                self.bare_item()?
            } else {
                BareItem::Boolean(true)
            };
            params.insert(key, value);
        }
        Ok(params)
    }
    fn bare_item(&mut self) -> Result<BareItem, ParseError> {
        match self.peek() {
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(b'"') => self.string().map(BareItem::String),
            Some(c) if c.is_ascii_alphabetic() || c == b'*' => Ok(BareItem::Token(self.token())),
            Some(b':') => self.bytes(),
            Some(b'?') => {
                self.i += 1;
                let b = match self.peek() {
                    Some(b'1') => true,
                    Some(b'0') => false,
                    _ => return Err(self.err("invalid boolean")),
                };
                self.i += 1;
                Ok(BareItem::Boolean(b))
            }
            Some(b'@') => {
                self.i += 1;
                match self.number()? {
                    BareItem::Integer(n) => Ok(BareItem::Date(n)),
                    _ => Err(self.err("invalid date")),
                }
            }
            Some(b'%') => self.display_string(),
            _ => Err(self.err("invalid bare item")),
        }
    }
    fn number(&mut self) -> Result<BareItem, ParseError> {
        let start = self.i;
        let neg = self.peek() == Some(b'-');
        if neg {
            self.i += 1;
        }
        if !self.peek().is_some_and(|c| c.is_ascii_digit()) {
            return Err(self.err("invalid number"));
        }
        let digits_start = self.i;
        let mut dot: Option<usize> = None;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.i += 1;
            } else if c == b'.' && dot.is_none() {
                dot = Some(self.i);
                self.i += 1;
            } else {
                break;
            }
            let len = self.i - digits_start;
            if (dot.is_none() && len > 15) || (dot.is_some() && len > 16) {
                return Err(self.err("number too long"));
            }
        }
        let text =
            std::str::from_utf8(&self.s[start..self.i]).map_err(|_| self.err("invalid number"))?;
        match dot {
            None => text
                .parse()
                .map(BareItem::Integer)
                .map_err(|_| self.err("invalid integer")),
            Some(d) => {
                if d - digits_start > 12 {
                    return Err(self.err("decimal integer part too long"));
                }
                let frac = self.i - d - 1;
                if frac == 0 || frac > 3 {
                    return Err(self.err("invalid decimal fraction"));
                }
                text.parse()
                    .map(BareItem::Decimal)
                    .map_err(|_| self.err("invalid decimal"))
            }
        }
    }
    fn string(&mut self) -> Result<String, ParseError> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let Some(c) = self.peek() else {
                return Err(self.err("unterminated string"));
            };
            self.i += 1;
            match c {
                b'\\' => match self.peek() {
                    Some(n @ (b'"' | b'\\')) => {
                        out.push(n as char);
                        self.i += 1;
                    }
                    _ => return Err(self.err("invalid escape")),
                },
                b'"' => return Ok(out),
                0x20..=0x7e => out.push(c as char),
                _ => return Err(self.err("invalid string character")),
            }
        }
    }
    fn token(&mut self) -> String {
        let start = self.i;
        while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~:/".contains(&c))
        {
            self.i += 1;
        }
        String::from_utf8_lossy(&self.s[start..self.i]).into_owned()
    }
    fn bytes(&mut self) -> Result<BareItem, ParseError> {
        self.i += 1;
        let start = self.i;
        while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || b"+/=".contains(&c)) {
            self.i += 1;
        }
        if self.peek() != Some(b':') {
            return Err(self.err("unterminated byte sequence"));
        }
        let decoded = STANDARD_PAD_INDIFFERENT
            .decode(&self.s[start..self.i])
            .map_err(|_| self.err("invalid base64"))?;
        self.i += 1;
        Ok(BareItem::ByteSequence(decoded))
    }
    fn display_string(&mut self) -> Result<BareItem, ParseError> {
        self.i += 1;
        if self.peek() != Some(b'"') {
            return Err(self.err("invalid display string"));
        }
        self.i += 1;
        let mut bytes = Vec::new();
        loop {
            let Some(c) = self.peek() else {
                return Err(self.err("unterminated display string"));
            };
            self.i += 1;
            match c {
                b'%' => {
                    let hex = self
                        .s
                        .get(self.i..self.i + 2)
                        .ok_or_else(|| self.err("bad escape"))?;
                    if !hex
                        .iter()
                        .all(|h| h.is_ascii_digit() || (b'a'..=b'f').contains(h))
                    {
                        return Err(self.err("bad escape"));
                    }
                    let v = u8::from_str_radix(std::str::from_utf8(hex).unwrap_or("zz"), 16)
                        .map_err(|_| self.err("bad escape"))?;
                    bytes.push(v);
                    self.i += 2;
                }
                b'"' => {
                    return String::from_utf8(bytes)
                        .map(BareItem::DisplayString)
                        .map_err(|_| self.err("invalid UTF-8"));
                }
                0x20..=0x7e => bytes.push(c),
                _ => return Err(self.err("invalid display string character")),
            }
        }
    }
}
