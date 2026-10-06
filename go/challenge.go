// SPDX-License-Identifier: MIT

package lws

import "strings"

// Challenge is one authentication challenge from a WWW-Authenticate header
// (RFC 9110 section 11.6.1).
type Challenge struct {
	// Scheme is the authentication scheme as received (compare it
	// case-insensitively, e.g. with strings.EqualFold).
	Scheme string
	// Params holds the auth-params with lower-cased names and unquoted values.
	Params map[string]string
	// Token68 is set when the challenge uses the token68 form.
	Token68 string
}

// AsURI returns the LWS "as_uri" parameter: the authorization server issuer.
func (c Challenge) AsURI() string { return c.Params["as_uri"] }

// Realm returns the "realm" parameter: the scope of protection.
func (c Challenge) Realm() string { return c.Params["realm"] }

// Error returns the OAuth "error" parameter (e.g. "invalid_token").
func (c Challenge) Error() string { return c.Params["error"] }

// ErrorDescription returns the OAuth "error_description" parameter.
func (c Challenge) ErrorDescription() string { return c.Params["error_description"] }

// IsBearer reports whether the challenge uses the Bearer scheme.
func (c Challenge) IsBearer() bool { return strings.EqualFold(c.Scheme, "Bearer") }

// ParseChallenges parses one or more WWW-Authenticate header field values,
// including several challenges within one value.
func ParseChallenges(values ...string) []Challenge {
	var out []Challenge
	for _, v := range values {
		out = append(out, parseChallengeValue(v)...)
	}
	return out
}

func isTchar(c byte) bool {
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func isToken68Char(c byte) bool {
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
		return true
	}
	return strings.IndexByte("-._~+/", c) >= 0
}

func parseChallengeValue(s string) []Challenge {
	var out []Challenge
	p := &scanner{s: s}
	for {
		p.skip(func(c byte) bool { return isWS(c) || c == ',' })
		if p.eof() {
			return out
		}
		scheme := p.readWhile(isTchar)
		if scheme == "" {
			p.pos++ // skip an unexpected character
			continue
		}
		ch := Challenge{Scheme: scheme, Params: map[string]string{}}
		p.skip(isWS)
		if t68, ok := p.tryToken68(); ok {
			ch.Token68 = t68
			out = append(out, ch)
			continue
		}
		// auth-param list
		for {
			p.skip(isWS)
			if p.eof() || p.peek() == ',' {
				// Look past the comma(s) to decide whether the next element is
				// another auth-param or the start of a new challenge.
				save := p.pos
				p.skip(func(c byte) bool { return isWS(c) || c == ',' })
				if p.eof() || !p.atAuthParam() {
					p.pos = save
					break
				}
			}
			name := strings.ToLower(p.readWhile(isTchar))
			if name == "" {
				p.skipToComma()
				break
			}
			p.skip(isWS)
			if p.eof() || p.peek() != '=' {
				break
			}
			p.pos++
			p.skip(isWS)
			var value string
			if !p.eof() && p.peek() == '"' {
				value = p.readQuoted()
			} else {
				value = p.readWhile(isTchar)
			}
			if _, dup := ch.Params[name]; !dup {
				ch.Params[name] = value
			}
		}
		out = append(out, ch)
	}
}

// atAuthParam reports whether the input at the cursor is "token BWS =" (an
// auth-param) rather than a new challenge's scheme.
func (p *scanner) atAuthParam() bool {
	i := p.pos
	for i < len(p.s) && isTchar(p.s[i]) {
		i++
	}
	if i == p.pos {
		return false
	}
	for i < len(p.s) && isWS(p.s[i]) {
		i++
	}
	return i < len(p.s) && p.s[i] == '='
}

// tryToken68 reads a token68 if the input at the cursor is one (followed by
// a comma or the end of input).
func (p *scanner) tryToken68() (string, bool) {
	i := p.pos
	for i < len(p.s) && isToken68Char(p.s[i]) {
		i++
	}
	if i == p.pos {
		return "", false
	}
	for i < len(p.s) && p.s[i] == '=' {
		i++
	}
	j := i
	for j < len(p.s) && isWS(p.s[j]) {
		j++
	}
	if j < len(p.s) && p.s[j] != ',' {
		return "", false
	}
	t := p.s[p.pos:i]
	p.pos = i
	return t, true
}
