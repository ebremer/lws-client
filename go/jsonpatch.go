// SPDX-License-Identifier: MIT

package lws

import (
	"encoding/json"
	"strings"
)

// PatchOperation is one JSON Patch (RFC 6902) operation.
type PatchOperation struct {
	Op    string
	Path  string
	From  string
	Value any
}

// MarshalJSON emits "value" for add, replace and test (even when it is null)
// and "from" for move and copy.
func (o PatchOperation) MarshalJSON() ([]byte, error) {
	m := map[string]any{"op": o.Op, "path": o.Path}
	switch o.Op {
	case "add", "replace", "test":
		m["value"] = o.Value
	case "move", "copy":
		m["from"] = o.From
	}
	return json.Marshal(m)
}

// UnmarshalJSON decodes an operation object.
func (o *PatchOperation) UnmarshalJSON(data []byte) error {
	var raw struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		From  string          `json:"from"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	o.Op, o.Path, o.From = raw.Op, raw.Path, raw.From
	o.Value = nil
	if len(raw.Value) > 0 {
		return json.Unmarshal(raw.Value, &o.Value)
	}
	return nil
}

// JSONPatch is a JSON Patch document (RFC 6902), the baseline PATCH format of
// LWS. Build one by chaining the methods, which return a new patch:
//
//	patch := lws.JSONPatch{}.Replace("/age", 31).Add("/city", "Boston")
type JSONPatch []PatchOperation

func (p JSONPatch) with(op PatchOperation) JSONPatch {
	out := make(JSONPatch, len(p), len(p)+1)
	copy(out, p)
	return append(out, op)
}

// Add appends an "add" operation.
func (p JSONPatch) Add(path string, value any) JSONPatch {
	return p.with(PatchOperation{Op: "add", Path: path, Value: value})
}

// Remove appends a "remove" operation.
func (p JSONPatch) Remove(path string) JSONPatch {
	return p.with(PatchOperation{Op: "remove", Path: path})
}

// Replace appends a "replace" operation.
func (p JSONPatch) Replace(path string, value any) JSONPatch {
	return p.with(PatchOperation{Op: "replace", Path: path, Value: value})
}

// Move appends a "move" operation.
func (p JSONPatch) Move(from, path string) JSONPatch {
	return p.with(PatchOperation{Op: "move", From: from, Path: path})
}

// Copy appends a "copy" operation.
func (p JSONPatch) Copy(from, path string) JSONPatch {
	return p.with(PatchOperation{Op: "copy", From: from, Path: path})
}

// Test appends a "test" operation.
func (p JSONPatch) Test(path string, value any) JSONPatch {
	return p.with(PatchOperation{Op: "test", Path: path, Value: value})
}

// MarshalJSON always emits a JSON array (never null).
func (p JSONPatch) MarshalJSON() ([]byte, error) {
	if p == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]PatchOperation(p))
}

var pointerEscaper = strings.NewReplacer("~", "~0", "/", "~1")
var pointerUnescaper = strings.NewReplacer("~1", "/", "~0", "~")

// EscapePointerSegment escapes one JSON Pointer reference token (RFC 6901):
// "~" becomes "~0" and "/" becomes "~1".
func EscapePointerSegment(segment string) string { return pointerEscaper.Replace(segment) }

// UnescapePointerSegment reverses EscapePointerSegment.
func UnescapePointerSegment(segment string) string { return pointerUnescaper.Replace(segment) }

// JSONPointer builds a JSON Pointer from unescaped segments, e.g.
// JSONPointer("linkset", "0", "https://example.org/rel", "-") returns
// "/linkset/0/https:~1~1example.org~1rel/-".
func JSONPointer(segments ...string) string {
	var b strings.Builder
	for _, s := range segments {
		b.WriteByte('/')
		b.WriteString(EscapePointerSegment(s))
	}
	return b.String()
}
