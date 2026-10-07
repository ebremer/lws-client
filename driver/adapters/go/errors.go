// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"

	lws "github.com/ebremer/lws-client/go"
)

// errorJSON is the error member of a response (PROTOCOL.md section 3.2).
type errorJSON struct {
	Kind                  string                     `json:"kind"`
	Message               string                     `json:"message"`
	Status                int                        `json:"status,omitempty"`
	Problem               map[string]json.RawMessage `json:"problem,omitempty"`
	Allow                 *[]string                  `json:"allow,omitempty"`
	AcceptPatch           *[]string                  `json:"acceptPatch,omitempty"`
	OAuthError            string                     `json:"oauthError,omitempty"`
	OAuthErrorDescription string                     `json:"oauthErrorDescription,omitempty"`
}

// The library's status sentinels (matched with errors.Is) and their names in the API contract.
var statusKinds = []struct {
	sentinel error
	kind     string
}{
	{lws.ErrBadRequest, "BadRequestError"},
	{lws.ErrUnauthorized, "UnauthorizedError"},
	{lws.ErrForbidden, "ForbiddenError"},
	{lws.ErrNotFound, "NotFoundError"},
	{lws.ErrMethodNotAllowed, "MethodNotAllowedError"},
	{lws.ErrNotAcceptable, "NotAcceptableError"},
	{lws.ErrConflict, "ConflictError"},
	{lws.ErrGone, "GoneError"},
	{lws.ErrPreconditionFailed, "PreconditionFailedError"},
	{lws.ErrUnsupportedMediaType, "UnsupportedMediaTypeError"},
	{lws.ErrUnprocessableContent, "UnprocessableContentError"},
	{lws.ErrNotImplemented, "NotImplementedError"},
	{lws.ErrInsufficientStorage, "InsufficientStorageError"},
}

// errorResult maps an error to its protocol kind.
//
// The library's error types are checked from the outermost wrapper inwards: a
// SignatureVerificationError may wrap the failure to fetch the storage description (an HTTPError,
// a ProtocolError, a transport error), and an AuthenticationError may wrap a transport error, but
// never the other way round. Transport failures come last because the library's own errors can
// wrap them.
func errorResult(err error) errorJSON {
	var ae *adapterError
	if errors.As(err, &ae) {
		return errorJSON{Kind: ae.kind, Message: ae.message}
	}
	var sve *lws.SignatureVerificationError
	if errors.As(err, &sve) {
		return errorJSON{Kind: "SignatureVerificationError", Message: err.Error()}
	}
	var authn *lws.AuthenticationError
	if errors.As(err, &authn) {
		return errorJSON{Kind: "AuthenticationError", Message: err.Error(), OAuthError: authn.Code, OAuthErrorDescription: authn.Description}
	}
	var pe *lws.ProtocolError
	if errors.As(err, &pe) {
		return errorJSON{Kind: "ProtocolError", Message: err.Error()}
	}
	var he *lws.HTTPError
	if errors.As(err, &he) {
		e := errorJSON{Kind: "HttpError", Status: he.StatusCode, Message: err.Error()}
		for _, s := range statusKinds {
			if errors.Is(err, s.sentinel) {
				e.Kind = s.kind
				break
			}
		}
		if he.Problem != nil {
			e.Problem = problemResult(he.Problem)
		}
		switch e.Kind {
		case "MethodNotAllowedError":
			allow := list(he.Allow())
			e.Allow = &allow
		case "UnsupportedMediaTypeError":
			acceptPatch := list(he.AcceptPatch())
			e.AcceptPatch = &acceptPatch
		}
		return e
	}
	// A URL that does not parse is a malformed argument; any other *url.Error comes from the
	// HTTP client's Do: no response (connection refused, TLS failure, timeout, redirect limit).
	var ue *url.Error
	if errors.As(err, &ue) && ue.Op == "parse" {
		return errorJSON{Kind: "InvalidArguments", Message: err.Error()}
	}
	var ne net.Error
	if errors.As(err, &ne) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
		errors.Is(err, io.ErrUnexpectedEOF) {
		return errorJSON{Kind: "TransportError", Message: err.Error()}
	}
	log.Printf("internal error: (%T) %v", err, err)
	return errorJSON{Kind: "InternalError", Message: fmt.Sprintf("(%T) %v", err, err)}
}

// problemResult rebuilds the RFC 9457 problem details object.
func problemResult(p *lws.ProblemDetails) map[string]json.RawMessage {
	m := map[string]json.RawMessage{}
	for k, v := range p.Extensions {
		m[k] = v
	}
	str := func(name, value string) {
		if value != "" {
			b, _ := json.Marshal(value)
			m[name] = b
		}
	}
	str("type", p.Type)
	str("title", p.Title)
	str("detail", p.Detail)
	str("instance", p.Instance)
	if p.Status != 0 {
		b, _ := json.Marshal(p.Status)
		m["status"] = b
	}
	return m
}
