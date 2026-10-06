// SPDX-License-Identifier: MIT

package lws

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
)

// Head retrieves a resource's metadata without its body.
//
// Honoured options: Header, IfNoneMatch, IfModifiedSince, Prefer.
func (c *Client) Head(ctx context.Context, url string, opts ...CallOption) (*ResourceMetadata, error) {
	resp, _, err := c.execute(ctx, http.MethodHead, url, nil, "", applyCallOptions(opts))
	if err != nil {
		return nil, err
	}
	m := newMetadata(resp)
	return &m, nil
}

// Read retrieves a resource's representation. A 304 Not Modified answer to a
// conditional read is not an error: the result has NotModified set and an
// empty body. A 206 Partial Content (see ByteRange) is a normal success.
//
// Honoured options: Accept, ByteRange, IfNoneMatch, IfModifiedSince, Prefer, Header.
func (c *Client) Read(ctx context.Context, url string, opts ...CallOption) (*Resource, error) {
	resp, body, err := c.execute(ctx, http.MethodGet, url, nil, "", applyCallOptions(opts))
	if err != nil {
		return nil, err
	}
	r := &Resource{ResourceMetadata: newMetadata(resp), Body: body}
	if resp.StatusCode == http.StatusNotModified {
		r.NotModified = true
		r.Body = nil
	}
	return r, nil
}

// ResourceStream is a read resource whose body is streamed. The caller must
// close Body.
type ResourceStream struct {
	ResourceMetadata
	Body        io.ReadCloser
	NotModified bool
}

// ReadStream is like Read but returns the body as a stream, which avoids
// buffering large resources in memory. The caller must close the body.
func (c *Client) ReadStream(ctx context.Context, url string, opts ...CallOption) (*ResourceStream, error) {
	req, err := c.newRequest(ctx, http.MethodGet, url, nil, applyCallOptions(opts))
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	return &ResourceStream{
		ResourceMetadata: newMetadata(resp),
		Body:             resp.Body,
		NotModified:      resp.StatusCode == http.StatusNotModified,
	}, nil
}

// CreateResult describes a newly created resource.
type CreateResult struct {
	// Location is the absolute URI assigned by the server.
	Location string
	// Metadata holds the server-managed links of the 201 response (linkset,
	// up, type).
	Metadata ResourceMetadata
	// Body is the optional minimal representation returned by the server.
	Body []byte
}

// Create creates a data resource in the container at containerURL by POSTing
// body with the given content type. The server assigns the final URI.
//
// Honoured options: Slug (identity hint), Types, Links (initial
// user-managed metadata), Header.
//
// Note: POST is not idempotent and is never retried, except once after a 401
// when the body is replayable (*bytes.Reader, *bytes.Buffer, *strings.Reader).
func (c *Client) Create(ctx context.Context, containerURL string, body io.Reader, contentType string, opts ...CallOption) (*CreateResult, error) {
	return c.create(ctx, containerURL, body, contentType, applyCallOptions(opts), false)
}

// CreateJSON creates a data resource whose body is v encoded as JSON
// (Content-Type application/json).
func (c *Client) CreateJSON(ctx context.Context, containerURL string, v any, opts ...CallOption) (*CreateResult, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return c.Create(ctx, containerURL, bytes.NewReader(data), MediaJSON, opts...)
}

// CreateContainer creates a sub-container of the container at parentURL.
//
// Honoured options: Slug, Types, Links, Header.
func (c *Client) CreateContainer(ctx context.Context, parentURL string, opts ...CallOption) (*CreateResult, error) {
	return c.create(ctx, parentURL, nil, "", applyCallOptions(opts), true)
}

func (c *Client) create(ctx context.Context, containerURL string, body io.Reader, contentType string, o *callOptions, container bool) (*CreateResult, error) {
	req, err := c.newRequest(ctx, http.MethodPost, containerURL, body, o)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if o.slug != "" {
		req.Header.Set("Slug", encodeSlug(o.slug))
	}
	if container {
		req.Header.Add("Link", NewLink(TypeContainer, RelType).String())
	}
	for _, t := range o.types {
		req.Header.Add("Link", NewLink(t, RelType).String())
	}
	for _, l := range o.links {
		req.Header.Add("Link", l.String())
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil, protocolErr("create response (%d) has no Location header", resp.StatusCode)
	}
	return &CreateResult{
		Location: resolveURL(responseURL(resp), loc),
		Metadata: newMetadata(resp),
		Body:     data,
	}, nil
}

// UpdateResult describes the outcome of an update or patch.
type UpdateResult struct {
	// StatusCode is 200 or 204 (or 201 if the server created the resource).
	StatusCode int
	// ETag is the new entity tag, when the server returned one.
	ETag     string
	Metadata ResourceMetadata
	// Body is the optional representation returned by the server.
	Body []byte
}

// Update replaces the content of the resource at url (HTTP PUT).
//
// Honoured options: IfMatch, IfNoneMatch, Links together with SetLinkset
// (replace the linkset atomically), Header.
func (c *Client) Update(ctx context.Context, url string, body io.Reader, contentType string, opts ...CallOption) (*UpdateResult, error) {
	return c.modify(ctx, http.MethodPut, url, body, contentType, applyCallOptions(opts))
}

// Patch applies a JSON Patch (application/json-patch+json, the LWS baseline
// patch format) to the resource at url.
//
// Honoured options: IfMatch, Links together with SetLinkset, Header.
func (c *Client) Patch(ctx context.Context, url string, patch JSONPatch, opts ...CallOption) (*UpdateResult, error) {
	data, err := json.Marshal(patch)
	if err != nil {
		return nil, err
	}
	return c.modify(ctx, http.MethodPatch, url, bytes.NewReader(data), MediaJSONPatch, applyCallOptions(opts))
}

// PatchRaw applies a patch document in another format advertised by the
// server's Accept-Patch header (for example application/sparql-update).
func (c *Client) PatchRaw(ctx context.Context, url string, body io.Reader, contentType string, opts ...CallOption) (*UpdateResult, error) {
	return c.modify(ctx, http.MethodPatch, url, body, contentType, applyCallOptions(opts))
}

func (c *Client) modify(ctx context.Context, method, url string, body io.Reader, contentType string, o *callOptions) (*UpdateResult, error) {
	req, err := c.newRequest(ctx, method, url, body, o)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if o.setLinkset {
		prefer := req.Header.Get("Prefer")
		if prefer != "" {
			prefer += ", "
		}
		req.Header.Set("Prefer", prefer+PreferSetLinkset)
	}
	for _, l := range o.links {
		req.Header.Add("Link", l.String())
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &UpdateResult{
		StatusCode: resp.StatusCode,
		ETag:       resp.Header.Get("ETag"),
		Metadata:   newMetadata(resp),
		Body:       data,
	}, nil
}

// Delete removes the resource at url. Deleting a non-empty container fails
// with ErrConflict unless the Recursive option is given.
//
// Honoured options: IfMatch, Recursive, Header.
func (c *Client) Delete(ctx context.Context, url string, opts ...CallOption) error {
	o := applyCallOptions(opts)
	req, err := c.newRequest(ctx, http.MethodDelete, url, nil, o)
	if err != nil {
		return err
	}
	if o.recursive {
		req.Header.Set("Depth", "infinity")
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	drainClose(resp)
	return nil
}
