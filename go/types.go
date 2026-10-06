// SPDX-License-Identifier: MIT

package lws

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// TypeList is the value of a JSON-LD "type" member. It decodes from either a
// single string or an array of strings and keeps the values exactly as
// received.
type TypeList []string

// UnmarshalJSON accepts a string, an array of strings or null.
func (t *TypeList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		*t = nil
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*t = TypeList{s}
		return nil
	}
	var list []string
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("lws: type must be a string or an array of strings: %w", err)
	}
	*t = list
	return nil
}

// Has reports whether the list contains typ, treating "Term", "lws:Term" and
// "https://www.w3.org/ns/lws#Term" as equal.
func (t TypeList) Has(typ string) bool {
	for _, v := range t {
		if TypeEquals(v, typ) {
			return true
		}
	}
	return false
}

// TypeEquals reports whether two type values denote the same type. LWS short
// terms ("Container"), compact IRIs ("lws:Container") and full IRIs
// ("https://www.w3.org/ns/lws#Container") are equivalent.
func TypeEquals(a, b string) bool {
	return ExpandType(a) == ExpandType(b)
}

// ExpandType expands an LWS short term or "lws:" compact IRI to a full IRI.
// Values that are already absolute IRIs are returned unchanged.
func ExpandType(t string) string {
	if strings.HasPrefix(t, "lws:") {
		return LWSNamespace + t[len("lws:"):]
	}
	if t != "" && !strings.Contains(t, ":") {
		return LWSNamespace + t
	}
	return t
}
