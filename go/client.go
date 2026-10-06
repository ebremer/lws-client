// SPDX-License-Identifier: MIT

package lws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// Client performs LWS operations. Create one with NewClient; a Client is
// immutable and safe for concurrent use by multiple goroutines.
type Client struct {
	hc        *http.Client
	auth      Authenticator
	userAgent string
	headers   http.Header
}

// Option configures a Client.
type Option func(*clientConfig)

type clientConfig struct {
	httpClient *http.Client
	auth       Authenticator
	userAgent  string
	headers    http.Header
	timeout    time.Duration
}

// WithHTTPClient sets the underlying *http.Client (transport, proxies, TLS,
// cookie jar …). The client is copied; the original is not modified.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *clientConfig) { c.httpClient = hc }
}

// WithAuthenticator sets the Authenticator used for every request, such as a
// *TokenExchangeAuthenticator or a *BearerTokenAuthenticator.
func WithAuthenticator(a Authenticator) Option {
	return func(c *clientConfig) { c.auth = a }
}

// WithUserAgent overrides the User-Agent header (default "lws-client-go/<version>").
func WithUserAgent(ua string) Option {
	return func(c *clientConfig) { c.userAgent = ua }
}

// WithHeader adds a header sent with every request.
func WithHeader(key, value string) Option {
	return func(c *clientConfig) { c.headers.Add(key, value) }
}

// WithTimeout sets an overall timeout for each HTTP exchange (including
// reading the response body). Zero means no timeout beyond the context.
func WithTimeout(d time.Duration) Option {
	return func(c *clientConfig) { c.timeout = d }
}

// NewClient returns a Client configured with the given options.
func NewClient(opts ...Option) *Client {
	cfg := clientConfig{userAgent: DefaultUserAgent, headers: http.Header{}}
	for _, o := range opts {
		o(&cfg)
	}
	base := cfg.httpClient
	if base == nil {
		base = &http.Client{}
	}
	hc := *base
	if cfg.timeout > 0 {
		hc.Timeout = cfg.timeout
	}
	c := &Client{auth: cfg.auth, userAgent: cfg.userAgent, headers: cfg.headers}
	userCheck := base.CheckRedirect
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if userCheck != nil {
			if err := userCheck(req, via); err != nil {
				return err
			}
		} else if len(via) >= 10 {
			return errors.New("lws: stopped after 10 redirects")
		}
		// Never forward credentials outside the realm they were issued for:
		// drop the copied Authorization header and let the authenticator
		// decide again for the new URL.
		if c.auth != nil {
			req.Header.Del("Authorization")
			return c.auth.Authorize(req.Context(), req)
		}
		return nil
	}
	c.hc = &hc
	return c
}

// HTTPClient returns the *http.Client used by c.
func (c *Client) HTTPClient() *http.Client { return c.hc }

// CallOption configures a single operation. Each method documents which
// options it honours; others are ignored.
type CallOption func(*callOptions)

type callOptions struct {
	header          http.Header
	slug            string
	links           []Link
	types           []string
	ifMatch         string
	ifNoneMatch     string
	ifModifiedSince time.Time
	accept          string
	rangeHeader     string
	prefer          []string
	setLinkset      bool
	recursive       bool
}

func applyCallOptions(opts []CallOption) *callOptions {
	o := &callOptions{header: http.Header{}}
	for _, f := range opts {
		if f != nil {
			f(o)
		}
	}
	return o
}

// Header adds a request header to a single call.
func Header(key, value string) CallOption {
	return func(o *callOptions) { o.header.Add(key, value) }
}

// Slug sets the identity hint for a created resource (sent as the Slug header).
func Slug(name string) CallOption { return func(o *callOptions) { o.slug = name } }

// Links adds user-managed metadata links: initial links on create, or links
// to apply together with SetLinkset on update/patch.
func Links(links ...Link) CallOption {
	return func(o *callOptions) { o.links = append(o.links, links...) }
}

// Types adds rel="type" links (e.g. "https://schema.org/Person") to a create.
func Types(iris ...string) CallOption {
	return func(o *callOptions) { o.types = append(o.types, iris...) }
}

// IfMatch makes the request conditional on the resource's current ETag.
// Pass the ETag exactly as received (including quotes).
func IfMatch(etag string) CallOption { return func(o *callOptions) { o.ifMatch = etag } }

// IfNoneMatch sets If-None-Match (a conditional read, or "*" on update to
// require that the resource does not exist).
func IfNoneMatch(etag string) CallOption { return func(o *callOptions) { o.ifNoneMatch = etag } }

// IfModifiedSince makes a read conditional on the modification date.
func IfModifiedSince(t time.Time) CallOption {
	return func(o *callOptions) { o.ifModifiedSince = t }
}

// Accept overrides the Accept header of a read.
func Accept(mediaTypes string) CallOption { return func(o *callOptions) { o.accept = mediaTypes } }

// ByteRange requests a byte range (RFC 9110 Range). A negative end means "to
// the end"; a negative start requests the last -start bytes.
func ByteRange(start, end int64) CallOption {
	return func(o *callOptions) {
		switch {
		case start < 0:
			o.rangeHeader = fmt.Sprintf("bytes=-%d", -start)
		case end < 0:
			o.rangeHeader = fmt.Sprintf("bytes=%d-", start)
		default:
			o.rangeHeader = fmt.Sprintf("bytes=%d-%d", start, end)
		}
	}
}

// Prefer adds a Prefer header preference (RFC 7240).
func Prefer(preference string) CallOption {
	return func(o *callOptions) { o.prefer = append(o.prefer, preference) }
}

// SetLinkset asks the server to apply the Links of an update or patch to the
// resource's linkset atomically with the content change (Prefer: set-linkset).
func SetLinkset() CallOption { return func(o *callOptions) { o.setLinkset = true } }

// Recursive requests a recursive container delete (Depth: infinity).
func Recursive() CallOption { return func(o *callOptions) { o.recursive = true } }

// newRequest builds a request with the client's default headers and the
// per-call options applied. Bodies that are *bytes.Reader, *bytes.Buffer or
// *strings.Reader are replayable for the authentication retry.
func (c *Client) newRequest(ctx context.Context, method, rawURL string, body io.Reader, o *callOptions) (*http.Request, error) {
	if body == nil && (method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch) {
		body = http.NoBody
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	for k, vs := range c.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if o != nil {
		if o.accept != "" {
			req.Header.Set("Accept", o.accept)
		}
		if o.ifMatch != "" {
			req.Header.Set("If-Match", o.ifMatch)
		}
		if o.ifNoneMatch != "" {
			req.Header.Set("If-None-Match", o.ifNoneMatch)
		}
		if !o.ifModifiedSince.IsZero() {
			req.Header.Set("If-Modified-Since", o.ifModifiedSince.UTC().Format(http.TimeFormat))
		}
		if o.rangeHeader != "" {
			req.Header.Set("Range", o.rangeHeader)
		}
		if len(o.prefer) > 0 {
			req.Header.Set("Prefer", strings.Join(o.prefer, ", "))
		}
		for k, vs := range o.header {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}
	return req, nil
}

// send executes req, running the authenticator's challenge handling and a
// single retry on 401.
func (c *Client) send(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if c.auth != nil {
		if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
			// A streaming body cannot be replayed after a 401: establish
			// credentials first with a HEAD on the same URL.
			if cc, ok := c.auth.(credentialChecker); ok && !cc.hasCredentials(req.URL) {
				if probe, err := http.NewRequestWithContext(ctx, http.MethodHead, req.URL.String(), nil); err == nil {
					probe.Header.Set("User-Agent", req.Header.Get("User-Agent"))
					if resp, err := c.send(probe); err == nil {
						drainClose(resp)
					}
				}
			}
		}
		if err := c.auth.Authorize(ctx, req); err != nil {
			return nil, err
		}
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized || c.auth == nil {
		return resp, nil
	}
	retry, err := c.auth.HandleChallenge(ctx, req, resp)
	if err != nil {
		drainClose(resp)
		return nil, err
	}
	if !retry {
		return resp, nil
	}
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return resp, nil // cannot replay a streaming body
	}
	retryReq := req.Clone(ctx)
	if req.GetBody != nil {
		b, err := req.GetBody()
		if err != nil {
			drainClose(resp)
			return nil, err
		}
		retryReq.Body = b
	}
	retryReq.Header.Del("Authorization")
	drainClose(resp)
	if err := c.auth.Authorize(ctx, retryReq); err != nil {
		return nil, err
	}
	return c.hc.Do(retryReq)
}

// do sends the request and converts error statuses into *HTTPError. A 304
// Not Modified is returned as a response, not an error. The caller must close
// the body of a returned response.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	resp, err := c.send(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 400 {
		return resp, nil
	}
	defer resp.Body.Close()
	return nil, newHTTPError(req, resp)
}

func newHTTPError(req *http.Request, resp *http.Response) *HTTPError {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	e := &HTTPError{
		StatusCode: resp.StatusCode,
		Method:     req.Method,
		URL:        req.URL.String(),
		Header:     resp.Header,
		Problem:    problemFromResponse(resp.Header.Get("Content-Type"), body),
	}
	text := body
	if len(text) > 4096 {
		text = text[:4096]
	}
	if utf8.Valid(text) {
		e.Body = string(text)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		e.Challenges = ParseChallenges(resp.Header.Values("WWW-Authenticate")...)
	}
	return e
}

// execute builds and runs a request and returns the response metadata and
// fully read body.
func (c *Client) execute(ctx context.Context, method, rawURL string, body io.Reader, contentType string, o *callOptions) (*http.Response, []byte, error) {
	req, err := c.newRequest(ctx, method, rawURL, body, o)
	if err != nil {
		return nil, nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp, data, nil
}

// executeJSON is execute with a JSON request body.
func (c *Client) executeJSON(ctx context.Context, method, rawURL string, v any, contentType string, o *callOptions) (*http.Response, []byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, nil, err
	}
	return c.execute(ctx, method, rawURL, bytes.NewReader(data), contentType, o)
}

func drainClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
}

// responseURL returns the final URL of the exchange (after redirects).
func responseURL(resp *http.Response) string {
	if resp.Request != nil && resp.Request.URL != nil {
		return resp.Request.URL.String()
	}
	return ""
}

// isContainerMediaType reports whether ct is application/lws+json,
// application/ld+json or application/json (parameters ignored).
func isContainerMediaType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == MediaLWSJSON || mt == MediaLDJSON || mt == MediaJSON
}

// encodeSlug percent-encodes characters outside printable ASCII, and "%",
// as UTF-8 (RFC 5023 section 9.7).
func encodeSlug(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '%' {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
