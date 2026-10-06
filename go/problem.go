// SPDX-License-Identifier: MIT

package lws

import (
	"encoding/json"
	"mime"
	"strings"
)

// ProblemDetails is an RFC 9457 problem details object attached to error
// responses.
type ProblemDetails struct {
	Type     string
	Title    string
	Status   int
	Detail   string
	Instance string
	// Extensions holds all other members.
	Extensions map[string]json.RawMessage
}

// ParseProblemDetails parses an RFC 9457 problem details document.
func ParseProblemDetails(data []byte) (*ProblemDetails, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	pd := &ProblemDetails{Extensions: map[string]json.RawMessage{}}
	str := func(k string) string {
		var s string
		if v, ok := raw[k]; ok {
			_ = json.Unmarshal(v, &s)
		}
		return s
	}
	pd.Type, pd.Title, pd.Detail, pd.Instance = str("type"), str("title"), str("detail"), str("instance")
	if v, ok := raw["status"]; ok {
		_ = json.Unmarshal(v, &pd.Status)
	}
	for k, v := range raw {
		switch k {
		case "type", "title", "status", "detail", "instance":
		default:
			pd.Extensions[k] = v
		}
	}
	return pd, nil
}

// problemFromResponse returns problem details when the body is JSON that
// looks like an RFC 9457 document.
func problemFromResponse(contentType string, body []byte) *ProblemDetails {
	mt, _, _ := mime.ParseMediaType(contentType)
	if mt != MediaProblemJSON && mt != MediaJSON && !strings.HasSuffix(mt, "+json") {
		return nil
	}
	pd, err := ParseProblemDetails(body)
	if err != nil {
		return nil
	}
	if mt != MediaProblemJSON && pd.Type == "" && pd.Title == "" && pd.Detail == "" {
		return nil
	}
	return pd
}
