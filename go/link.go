// SPDX-License-Identifier: MIT

package lws

import (
	"net/url"
	"sort"
	"strings"
)

// Link is a single typed web link (RFC 8288).
type Link struct {
	// Href is the link target, resolved to an absolute URI when parsed from a
	// response.
	Href string
	// Rel is a single relation type. Registered relation names are
	// lower-cased; extension relation URIs are kept as-is.
	Rel string
	// Params holds the target attributes (except rel) with lower-cased names
	// and unquoted values. A parameter without a value maps to "".
	Params map[string]string
}

// NewLink returns a link with the given target and relation type.
func NewLink(href, rel string) Link {
	return Link{Href: href, Rel: rel}
}

// Type returns the "type" target attribute (a media type hint), if any.
func (l Link) Type() string { return l.Params["type"] }

// Anchor returns the "anchor" parameter (the link context), if any.
func (l Link) Anchor() string { return l.Params["anchor"] }

// String serialises the link as a Link header field value:
// <href>; rel="rel"; name="value".
func (l Link) String() string {
	var b strings.Builder
	b.WriteByte('<')
	b.WriteString(l.Href)
	b.WriteString(">; rel=")
	b.WriteString(quoteString(l.Rel))
	names := make([]string, 0, len(l.Params))
	for k := range l.Params {
		if k != "rel" {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	for _, k := range names {
		b.WriteString("; ")
		b.WriteString(k)
		if v := l.Params[k]; v != "" {
			b.WriteByte('=')
			b.WriteString(quoteString(v))
		}
	}
	return b.String()
}

// FormatLinks serialises links as a single comma-separated Link header value.
func FormatLinks(links []Link) string {
	parts := make([]string, len(links))
	for i, l := range links {
		parts[i] = l.String()
	}
	return strings.Join(parts, ", ")
}

// ParseLinkHeader parses one or more Link header field values (RFC 8288).
// Targets are resolved against base (normally the request URL). A link whose
// rel holds several space-separated relation types yields one Link per type.
// Malformed link-values are skipped.
func ParseLinkHeader(base string, values ...string) []Link {
	var b *url.URL
	if base != "" {
		b, _ = url.Parse(base)
	}
	return parseLinks(b, values)
}

func parseLinks(base *url.URL, values []string) []Link {
	var out []Link
	for _, v := range values {
		out = append(out, parseLinkValue(base, v)...)
	}
	return out
}

func parseLinkValue(base *url.URL, s string) []Link {
	var out []Link
	p := &scanner{s: s}
	for {
		p.skip(func(c byte) bool { return isWS(c) || c == ',' })
		if p.eof() {
			return out
		}
		if p.peek() != '<' {
			p.skipToComma()
			continue
		}
		p.pos++
		end := strings.IndexByte(s[p.pos:], '>')
		if end < 0 {
			return out
		}
		target := strings.TrimSpace(s[p.pos : p.pos+end])
		p.pos += end + 1
		params := map[string]string{}
		rel, hasRel := "", false
		ok := true
		for {
			p.skip(isWS)
			if p.eof() {
				break
			}
			if p.peek() == ',' {
				p.pos++
				break
			}
			if p.peek() != ';' {
				ok = false
				p.skipToComma()
				break
			}
			p.pos++
			p.skip(isWS)
			name := strings.ToLower(p.readWhile(func(c byte) bool {
				return !isWS(c) && c != '=' && c != ';' && c != ','
			}))
			p.skip(isWS)
			value := ""
			if !p.eof() && p.peek() == '=' {
				p.pos++
				p.skip(isWS)
				if !p.eof() && p.peek() == '"' {
					value = p.readQuoted()
				} else {
					value = p.readWhile(func(c byte) bool { return !isWS(c) && c != ';' && c != ',' })
				}
			}
			if name == "" {
				continue
			}
			if name == "rel" {
				if !hasRel {
					rel, hasRel = value, true
				}
				continue
			}
			if _, dup := params[name]; !dup {
				params[name] = value
			}
		}
		if !ok || !hasRel {
			continue
		}
		href := resolveRef(base, target)
		for _, r := range strings.Fields(rel) {
			if !strings.Contains(r, ":") {
				r = strings.ToLower(r)
			}
			cp := make(map[string]string, len(params))
			for k, v := range params {
				cp[k] = v
			}
			out = append(out, Link{Href: href, Rel: r, Params: cp})
		}
	}
}

// resolveRef resolves ref against base; unparsable references are returned
// unchanged.
func resolveRef(base *url.URL, ref string) string {
	if base == nil {
		return ref
	}
	u, err := base.Parse(ref)
	if err != nil {
		return ref
	}
	return u.String()
}

// resolveURL resolves ref against the base URL string.
func resolveURL(base, ref string) string {
	if ref == "" {
		return ""
	}
	b, err := url.Parse(base)
	if err != nil || base == "" {
		return ref
	}
	return resolveRef(b, ref)
}

// findLink returns the first link with the given relation type.
func findLink(links []Link, rel string) (Link, bool) {
	for _, l := range links {
		if relEquals(l.Rel, rel) {
			return l, true
		}
	}
	return Link{}, false
}

func relEquals(a, b string) bool {
	if strings.Contains(a, ":") || strings.Contains(b, ":") {
		return a == b
	}
	return strings.EqualFold(a, b)
}

// quoteString returns s as an HTTP quoted-string.
func quoteString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return b.String()
}

// scanner is a tiny cursor used by the header parsers.
type scanner struct {
	s   string
	pos int
}

func (p *scanner) eof() bool  { return p.pos >= len(p.s) }
func (p *scanner) peek() byte { return p.s[p.pos] }

func (p *scanner) skip(f func(byte) bool) {
	for p.pos < len(p.s) && f(p.s[p.pos]) {
		p.pos++
	}
}

func (p *scanner) readWhile(f func(byte) bool) string {
	start := p.pos
	p.skip(f)
	return p.s[start:p.pos]
}

// readQuoted reads a quoted-string starting at the opening quote and returns
// its unescaped content. An unterminated string consumes the rest of input.
func (p *scanner) readQuoted() string {
	p.pos++ // opening quote
	var b strings.Builder
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		p.pos++
		switch c {
		case '\\':
			if p.pos < len(p.s) {
				b.WriteByte(p.s[p.pos])
				p.pos++
			}
		case '"':
			return b.String()
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// skipToComma advances past the next comma that is not inside a quoted string
// or angle brackets.
func (p *scanner) skipToComma() {
	for p.pos < len(p.s) {
		switch p.s[p.pos] {
		case '"':
			p.readQuoted()
			continue
		case '<':
			if end := strings.IndexByte(p.s[p.pos:], '>'); end >= 0 {
				p.pos += end + 1
				continue
			}
		case ',':
			p.pos++
			return
		}
		p.pos++
	}
}

func isWS(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }
