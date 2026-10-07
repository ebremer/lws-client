// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
)

// adapterError is an error the adapter reports itself, with its protocol kind.
type adapterError struct {
	kind    string
	message string
}

func (e *adapterError) Error() string { return e.message }

func invalid(format string, a ...any) error {
	return &adapterError{kind: "InvalidArguments", message: fmt.Sprintf(format, a...)}
}

// args is a JSON object whose members are decoded on demand, so that numbers and nested values
// keep their exact JSON form.
type args map[string]json.RawMessage

// member is one member of a JSON object, in document order.
type member struct {
	name  string
	value json.RawMessage
}

// jsonKind returns the JSON type of a (trimmed, non-empty) value.
func jsonKind(v json.RawMessage) string {
	switch v[0] {
	case '"':
		return "string"
	case '{':
		return "object"
	case '[':
		return "array"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	default:
		return "number"
	}
}

// objectOf decodes a JSON object; ok is false when raw is not one.
func objectOf(raw json.RawMessage) (args, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || jsonKind(raw) != "object" {
		return nil, false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil, false
	}
	return args(m), true
}

// orderedObject decodes a JSON object into its members in document order.
func orderedObject(raw json.RawMessage) ([]member, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if d, ok := tok.(json.Delim); err != nil || !ok || d != '{' {
		return nil, false
	}
	var out []member
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		name, ok := tok.(string)
		if !ok {
			return nil, false
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false
		}
		out = append(out, member{name, bytes.TrimSpace(value)})
	}
	if _, err := dec.Token(); err != nil {
		return nil, false
	}
	return out, true
}

// raw returns the member name, or false when it is absent or null (both mean absent).
func (a args) raw(name string) (json.RawMessage, bool) {
	v, ok := a[name]
	if !ok {
		return nil, false
	}
	v = bytes.TrimSpace(v)
	if len(v) == 0 || jsonKind(v) == "null" {
		return nil, false
	}
	return v, true
}

func (a args) typed(name, kind string) (json.RawMessage, bool, error) {
	v, ok := a.raw(name)
	if !ok {
		return nil, false, nil
	}
	if jsonKind(v) != kind {
		return nil, false, invalid("argument '%s' must be a %s", name, kind)
	}
	return v, true, nil
}

func (a args) optString(name string) (string, bool, error) {
	v, ok, err := a.typed(name, "string")
	if !ok || err != nil {
		return "", false, err
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", false, invalid("argument '%s' must be a string", name)
	}
	return s, true, nil
}

func (a args) str(name string) (string, error) {
	s, ok, err := a.optString(name)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", invalid("missing argument '%s'", name)
	}
	return s, nil
}

// url returns a required argument that must be an absolute URL (PROTOCOL.md section 3).
func (a args) url(name string) (string, error) {
	s, err := a.str(name)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(s)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return "", invalid("argument '%s' must be an absolute URL, got %q", name, s)
	}
	return s, nil
}

func (a args) optBool(name string) (bool, bool, error) {
	v, ok, err := a.typed(name, "boolean")
	if !ok || err != nil {
		return false, false, err
	}
	return string(v) == "true", true, nil
}

func (a args) optNumber(name string) (float64, bool, error) {
	v, ok, err := a.typed(name, "number")
	if !ok || err != nil {
		return 0, false, err
	}
	var n json.Number
	if err := json.Unmarshal(v, &n); err != nil {
		return 0, false, invalid("argument '%s' must be a number", name)
	}
	f, err := n.Float64()
	if err != nil {
		return 0, false, invalid("argument '%s' must be a number", name)
	}
	return f, true, nil
}

func (a args) optInt(name string) (int64, bool, error) {
	v, ok, err := a.typed(name, "number")
	if !ok || err != nil {
		return 0, false, err
	}
	var n json.Number
	if err := json.Unmarshal(v, &n); err != nil {
		return 0, false, invalid("argument '%s' must be an integer", name)
	}
	if i, err := n.Int64(); err == nil {
		return i, true, nil
	}
	// 4.0 and 1e3 are integers too.
	f, err := n.Float64()
	if err != nil || f != math.Trunc(f) || math.Abs(f) > 1<<53 {
		return 0, false, invalid("argument '%s' must be an integer", name)
	}
	return int64(f), true, nil
}

func (a args) optObject(name string) (json.RawMessage, bool, error) {
	return a.typed(name, "object")
}

func (a args) object(name string) (json.RawMessage, error) {
	v, ok, err := a.optObject(name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, invalid("missing argument '%s'", name)
	}
	return v, nil
}

func (a args) optStrings(name string) ([]string, bool, error) {
	v, ok, err := a.typed(name, "array")
	if !ok || err != nil {
		return nil, false, err
	}
	var list []string
	if err := json.Unmarshal(v, &list); err != nil {
		return nil, false, invalid("argument '%s' must be an array of strings", name)
	}
	if list == nil {
		list = []string{}
	}
	return list, true, nil
}

func (a args) strings(name string) ([]string, error) {
	list, ok, err := a.optStrings(name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, invalid("missing argument '%s'", name)
	}
	return list, nil
}

// limit is the optional limit of a lazy sequence (PROTOCOL.md section 3), default 1000.
func (a args) limit() (int64, error) {
	n, ok, err := a.optInt("limit")
	if err != nil || (ok && n < 0) {
		return 0, invalid("argument 'limit' must be a non-negative integer")
	}
	if !ok {
		return 1000, nil
	}
	return n, nil
}

// decodeBase64 decodes standard base64, padded or not.
func decodeBase64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// bodyOf returns a body argument (PROTOCOL.md section 3) as bytes, with the content type it
// implies unless contentType is given.
func bodyOf(a args, contentType string, hasContentType bool) ([]byte, string, error) {
	typeOr := func(fallback string) string {
		if hasContentType {
			return contentType
		}
		return fallback
	}
	raw, ok := a.raw("body")
	if !ok {
		return []byte{}, typeOr("application/octet-stream"), nil
	}
	body, ok := objectOf(raw)
	if !ok {
		return nil, "", invalid("argument 'body' must be an object")
	}
	if s, ok, err := body.optString("text"); err == nil && ok {
		return []byte(s), typeOr("text/plain"), nil
	}
	if s, ok, err := body.optString("base64"); err == nil && ok {
		data, err := decodeBase64(s)
		if err != nil {
			return nil, "", invalid("argument 'body': base64 is not valid base64: %v", err)
		}
		return data, typeOr("application/octet-stream"), nil
	}
	if v, ok := body["json"]; ok {
		var b bytes.Buffer
		if err := json.Compact(&b, v); err != nil {
			return nil, "", invalid("argument 'body': json is not valid JSON: %v", err)
		}
		return b.Bytes(), typeOr("application/json"), nil
	}
	return nil, "", invalid("argument 'body' must have text, base64 or json")
}
