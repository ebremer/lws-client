// SPDX-License-Identifier: MIT

package lws

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// This file implements the subset of Structured Field Values (RFC 8941 /
// RFC 9651) needed for HTTP Message Signatures and Content-Digest:
// dictionaries whose members are items or inner lists with parameters.

// SFToken is a structured-field token (as opposed to an sf-string, which is
// represented by a Go string).
type SFToken string

// SFParam is one parameter of an item or inner list.
type SFParam struct {
	Name string
	// Value is one of: int64, float64, string, SFToken, []byte, bool.
	Value any
}

// SFParams is an ordered parameter list.
type SFParams []SFParam

// Get returns the value of the named parameter.
func (p SFParams) Get(name string) (any, bool) {
	for _, x := range p {
		if x.Name == name {
			return x.Value, true
		}
	}
	return nil, false
}

// SFItem is a bare item with parameters.
type SFItem struct {
	// Value is one of: int64, float64, string, SFToken, []byte, bool.
	Value  any
	Params SFParams
}

// SFInnerList is an inner list with parameters.
type SFInnerList struct {
	Items  []SFItem
	Params SFParams
}

// SFMember is one dictionary member: exactly one of Item and List is set.
type SFMember struct {
	Name string
	Item *SFItem
	List *SFInnerList
}

// SFDictionary is an ordered structured-field dictionary.
type SFDictionary []SFMember

// Get returns the member with the given name.
func (d SFDictionary) Get(name string) (SFMember, bool) {
	for _, m := range d {
		if m.Name == name {
			return m, true
		}
	}
	return SFMember{}, false
}

var errSF = errors.New("lws: invalid structured field")

// ParseSFDictionary parses a structured-field dictionary. Duplicate keys
// overwrite earlier values (keeping the original position).
func ParseSFDictionary(s string) (SFDictionary, error) {
	p := &sfParser{s: strings.Trim(s, " ")}
	var dict SFDictionary
	if p.eof() {
		return dict, nil
	}
	for {
		key, err := p.key()
		if err != nil {
			return nil, err
		}
		m := SFMember{Name: key}
		if !p.eof() && p.peek() == '=' {
			p.pos++
			if !p.eof() && p.peek() == '(' {
				l, err := p.innerList()
				if err != nil {
					return nil, err
				}
				m.List = l
			} else {
				it, err := p.item()
				if err != nil {
					return nil, err
				}
				m.Item = it
			}
		} else {
			params, err := p.params()
			if err != nil {
				return nil, err
			}
			m.Item = &SFItem{Value: true, Params: params}
		}
		replaced := false
		for i := range dict {
			if dict[i].Name == key {
				dict[i] = m
				replaced = true
				break
			}
		}
		if !replaced {
			dict = append(dict, m)
		}
		p.ows()
		if p.eof() {
			return dict, nil
		}
		if p.peek() != ',' {
			return nil, fmt.Errorf("%w: expected ',' at %d", errSF, p.pos)
		}
		p.pos++
		p.ows()
		if p.eof() {
			return nil, fmt.Errorf("%w: trailing comma", errSF)
		}
	}
}

type sfParser struct {
	s   string
	pos int
}

func (p *sfParser) eof() bool  { return p.pos >= len(p.s) }
func (p *sfParser) peek() byte { return p.s[p.pos] }

func (p *sfParser) ows() {
	for !p.eof() && (p.peek() == ' ' || p.peek() == '\t') {
		p.pos++
	}
}

func (p *sfParser) sp() {
	for !p.eof() && p.peek() == ' ' {
		p.pos++
	}
}

func isLcalpha(c byte) bool { return c >= 'a' && c <= 'z' }
func isDigit(c byte) bool   { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool   { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func (p *sfParser) key() (string, error) {
	if p.eof() || !(isLcalpha(p.peek()) || p.peek() == '*') {
		return "", fmt.Errorf("%w: invalid key at %d", errSF, p.pos)
	}
	start := p.pos
	for !p.eof() {
		c := p.peek()
		if isLcalpha(c) || isDigit(c) || c == '_' || c == '-' || c == '.' || c == '*' {
			p.pos++
			continue
		}
		break
	}
	return p.s[start:p.pos], nil
}

func (p *sfParser) innerList() (*SFInnerList, error) {
	p.pos++ // '('
	l := &SFInnerList{}
	for {
		p.sp()
		if p.eof() {
			return nil, fmt.Errorf("%w: unterminated inner list", errSF)
		}
		if p.peek() == ')' {
			p.pos++
			params, err := p.params()
			if err != nil {
				return nil, err
			}
			l.Params = params
			return l, nil
		}
		it, err := p.item()
		if err != nil {
			return nil, err
		}
		l.Items = append(l.Items, *it)
		if p.eof() {
			return nil, fmt.Errorf("%w: unterminated inner list", errSF)
		}
		if c := p.peek(); c != ' ' && c != ')' {
			return nil, fmt.Errorf("%w: bad inner list at %d", errSF, p.pos)
		}
	}
}

func (p *sfParser) item() (*SFItem, error) {
	v, err := p.bareItem()
	if err != nil {
		return nil, err
	}
	params, err := p.params()
	if err != nil {
		return nil, err
	}
	return &SFItem{Value: v, Params: params}, nil
}

func (p *sfParser) params() (SFParams, error) {
	var out SFParams
	for !p.eof() && p.peek() == ';' {
		p.pos++
		p.sp()
		k, err := p.key()
		if err != nil {
			return nil, err
		}
		var v any = true
		if !p.eof() && p.peek() == '=' {
			p.pos++
			if v, err = p.bareItem(); err != nil {
				return nil, err
			}
		}
		replaced := false
		for i := range out {
			if out[i].Name == k {
				out[i].Value = v
				replaced = true
			}
		}
		if !replaced {
			out = append(out, SFParam{Name: k, Value: v})
		}
	}
	return out, nil
}

func (p *sfParser) bareItem() (any, error) {
	if p.eof() {
		return nil, fmt.Errorf("%w: missing item", errSF)
	}
	c := p.peek()
	switch {
	case c == '-' || isDigit(c):
		return p.number()
	case c == '"':
		return p.str()
	case c == '*' || isAlpha(c):
		return p.token(), nil
	case c == ':':
		return p.bytes()
	case c == '?':
		if p.pos+1 >= len(p.s) {
			return nil, fmt.Errorf("%w: bad boolean", errSF)
		}
		b := p.s[p.pos+1]
		p.pos += 2
		switch b {
		case '1':
			return true, nil
		case '0':
			return false, nil
		}
		return nil, fmt.Errorf("%w: bad boolean", errSF)
	}
	return nil, fmt.Errorf("%w: unexpected %q at %d", errSF, c, p.pos)
}

func (p *sfParser) number() (any, error) {
	start := p.pos
	if p.peek() == '-' {
		p.pos++
	}
	if p.eof() || !isDigit(p.peek()) {
		return nil, fmt.Errorf("%w: bad number", errSF)
	}
	decimal := false
	for !p.eof() {
		c := p.peek()
		if isDigit(c) {
			p.pos++
		} else if c == '.' && !decimal {
			decimal = true
			p.pos++
		} else {
			break
		}
	}
	text := p.s[start:p.pos]
	if decimal {
		if strings.HasSuffix(text, ".") {
			return nil, fmt.Errorf("%w: bad decimal", errSF)
		}
		f, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errSF, err)
		}
		return f, nil
	}
	if len(strings.TrimPrefix(text, "-")) > 15 {
		return nil, fmt.Errorf("%w: integer too long", errSF)
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errSF, err)
	}
	return n, nil
}

func (p *sfParser) str() (string, error) {
	p.pos++ // opening quote
	var b strings.Builder
	for !p.eof() {
		c := p.peek()
		p.pos++
		switch {
		case c == '\\':
			if p.eof() {
				return "", fmt.Errorf("%w: bad escape", errSF)
			}
			n := p.peek()
			if n != '"' && n != '\\' {
				return "", fmt.Errorf("%w: bad escape", errSF)
			}
			b.WriteByte(n)
			p.pos++
		case c == '"':
			return b.String(), nil
		case c < 0x20 || c > 0x7e:
			return "", fmt.Errorf("%w: bad string character", errSF)
		default:
			b.WriteByte(c)
		}
	}
	return "", fmt.Errorf("%w: unterminated string", errSF)
}

func (p *sfParser) token() SFToken {
	start := p.pos
	p.pos++
	for !p.eof() {
		c := p.peek()
		if isTchar(c) || c == ':' || c == '/' {
			p.pos++
			continue
		}
		break
	}
	return SFToken(p.s[start:p.pos])
}

func (p *sfParser) bytes() ([]byte, error) {
	p.pos++
	end := strings.IndexByte(p.s[p.pos:], ':')
	if end < 0 {
		return nil, fmt.Errorf("%w: unterminated byte sequence", errSF)
	}
	text := p.s[p.pos : p.pos+end]
	p.pos += end + 1
	b, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		if b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(text, "=")); err != nil {
			return nil, fmt.Errorf("%w: bad base64", errSF)
		}
	}
	return b, nil
}

// String serialises the inner list canonically, e.g.
// ("@method" "@path");created=1;keyid="k".
func (l SFInnerList) String() string {
	var b strings.Builder
	b.WriteByte('(')
	for i, it := range l.Items {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(it.String())
	}
	b.WriteByte(')')
	b.WriteString(l.Params.String())
	return b.String()
}

// String serialises the item canonically.
func (it SFItem) String() string {
	return serializeBareItem(it.Value) + it.Params.String()
}

// String serialises the parameters canonically.
func (p SFParams) String() string {
	var b strings.Builder
	for _, x := range p {
		b.WriteByte(';')
		b.WriteString(x.Name)
		if v, ok := x.Value.(bool); ok && v {
			continue
		}
		b.WriteByte('=')
		b.WriteString(serializeBareItem(x.Value))
	}
	return b.String()
}

func serializeBareItem(v any) string {
	switch x := v.(type) {
	case int64:
		return strconv.FormatInt(x, 10)
	case int:
		return strconv.Itoa(x)
	case float64:
		r := math.Round(x*1000) / 1000
		s := strconv.FormatFloat(r, 'f', -1, 64)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		return s
	case string:
		return quoteString(x)
	case SFToken:
		return string(x)
	case []byte:
		return ":" + base64.StdEncoding.EncodeToString(x) + ":"
	case bool:
		if x {
			return "?1"
		}
		return "?0"
	}
	return fmt.Sprint(v)
}
