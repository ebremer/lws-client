// SPDX-License-Identifier: MIT

package lws

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Sentinel errors matched by *HTTPError with errors.Is. They correspond to the
// abstract LWS responses (e.g. ErrForbidden is "not permitted", ErrUnauthorized
// is "unknown requester", ErrInsufficientStorage is "quota exceeded").
var (
	ErrBadRequest           = errors.New("lws: bad request")
	ErrUnauthorized         = errors.New("lws: unauthorized")
	ErrForbidden            = errors.New("lws: forbidden")
	ErrNotFound             = errors.New("lws: not found")
	ErrMethodNotAllowed     = errors.New("lws: method not allowed")
	ErrNotAcceptable        = errors.New("lws: not acceptable")
	ErrConflict             = errors.New("lws: conflict")
	ErrGone                 = errors.New("lws: gone")
	ErrPreconditionFailed   = errors.New("lws: precondition failed")
	ErrUnsupportedMediaType = errors.New("lws: unsupported media type")
	ErrUnprocessableContent = errors.New("lws: unprocessable content")
	ErrNotImplemented       = errors.New("lws: not implemented")
	ErrInsufficientStorage  = errors.New("lws: insufficient storage")
)

var statusSentinels = map[int]error{
	http.StatusBadRequest:           ErrBadRequest,
	http.StatusUnauthorized:         ErrUnauthorized,
	http.StatusForbidden:            ErrForbidden,
	http.StatusNotFound:             ErrNotFound,
	http.StatusMethodNotAllowed:     ErrMethodNotAllowed,
	http.StatusNotAcceptable:        ErrNotAcceptable,
	http.StatusConflict:             ErrConflict,
	http.StatusGone:                 ErrGone,
	http.StatusPreconditionFailed:   ErrPreconditionFailed,
	http.StatusUnsupportedMediaType: ErrUnsupportedMediaType,
	http.StatusUnprocessableEntity:  ErrUnprocessableContent,
	http.StatusNotImplemented:       ErrNotImplemented,
	http.StatusInsufficientStorage:  ErrInsufficientStorage,
}

// HTTPError is returned when a server answers with a non-success status.
// It matches the corresponding sentinel error (ErrNotFound, ErrConflict, …)
// with errors.Is.
type HTTPError struct {
	StatusCode int
	Method     string
	URL        string
	Header     http.Header
	// Problem holds RFC 9457 problem details, when the body carried them.
	Problem *ProblemDetails
	// Body is the response body as text, truncated to 4 KiB.
	Body string
	// Challenges holds the parsed WWW-Authenticate challenges of a 401.
	Challenges []Challenge
}

func (e *HTTPError) Error() string {
	msg := fmt.Sprintf("lws: %s %s: %d %s", e.Method, e.URL, e.StatusCode, http.StatusText(e.StatusCode))
	if e.Problem != nil {
		if e.Problem.Title != "" {
			msg += ": " + e.Problem.Title
		}
		if e.Problem.Detail != "" {
			msg += ": " + e.Problem.Detail
		}
	}
	return msg
}

// Is reports whether target is the sentinel error for e's status code.
func (e *HTTPError) Is(target error) bool {
	s, ok := statusSentinels[e.StatusCode]
	return ok && s == target
}

// Allow returns the methods listed in the Allow header (useful for 405).
func (e *HTTPError) Allow() []string { return splitList(e.Header.Values("Allow")) }

// AcceptPatch returns the patch formats listed in Accept-Patch (useful for 415).
func (e *HTTPError) AcceptPatch() []string { return splitList(e.Header.Values("Accept-Patch")) }

// AcceptQuery returns the query formats listed in Accept-Query (useful for 415).
func (e *HTTPError) AcceptQuery() []string { return parseAcceptQuery(e.Header.Values("Accept-Query")) }

// AuthenticationError reports a failure of the LWS authorization flow: a
// rejected realm, an untrusted or insecure authorization server, invalid
// authorization server metadata, or a token endpoint error.
type AuthenticationError struct {
	Message string
	// Code is the OAuth "error" code of a token endpoint error response.
	Code string
	// Description is the OAuth "error_description".
	Description string
	// StatusCode is the HTTP status of a failed token or metadata request.
	StatusCode int
	Err        error
}

func (e *AuthenticationError) Error() string {
	var b strings.Builder
	b.WriteString("lws: authentication failed: ")
	b.WriteString(e.Message)
	if e.Code != "" {
		b.WriteString(" (" + e.Code)
		if e.Description != "" {
			b.WriteString(": " + e.Description)
		}
		b.WriteString(")")
	}
	if e.Err != nil {
		b.WriteString(": " + e.Err.Error())
	}
	return b.String()
}

func (e *AuthenticationError) Unwrap() error { return e.Err }

// ProtocolError reports a server response that violates the LWS protocol
// (a missing Location header, an unexpected media type, malformed JSON, …).
type ProtocolError struct {
	Message string
	Err     error
}

func (e *ProtocolError) Error() string {
	if e.Err != nil {
		return "lws: protocol error: " + e.Message + ": " + e.Err.Error()
	}
	return "lws: protocol error: " + e.Message
}

func (e *ProtocolError) Unwrap() error { return e.Err }

// SignatureVerificationError reports a webhook delivery that failed
// verification.
type SignatureVerificationError struct {
	Reason string
	Err    error
}

func (e *SignatureVerificationError) Error() string {
	if e.Err != nil {
		return "lws: webhook verification failed: " + e.Reason + ": " + e.Err.Error()
	}
	return "lws: webhook verification failed: " + e.Reason
}

func (e *SignatureVerificationError) Unwrap() error { return e.Err }

func protocolErr(format string, args ...any) error {
	return &ProtocolError{Message: fmt.Sprintf(format, args...)}
}

func authErr(format string, args ...any) *AuthenticationError {
	return &AuthenticationError{Message: fmt.Sprintf(format, args...)}
}

func sigErr(format string, args ...any) error {
	return &SignatureVerificationError{Reason: fmt.Sprintf(format, args...)}
}

// splitList splits comma-separated header values and trims the elements.
func splitList(values []string) []string {
	var out []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// parseAcceptQuery parses Accept-Query (a structured list of media types,
// as tokens or strings) and returns the bare media types.
func parseAcceptQuery(values []string) []string {
	var out []string
	for _, item := range splitList(values) {
		if i := strings.IndexByte(item, ';'); i >= 0 {
			item = item[:i]
		}
		item = strings.Trim(strings.TrimSpace(item), "\"")
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
