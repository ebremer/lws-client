// SPDX-License-Identifier: MIT

package lws

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// ResourceMetadata is the metadata an LWS server conveys in response headers.
type ResourceMetadata struct {
	// URL is the final URL of the exchange (after redirects).
	URL        string
	StatusCode int
	// ETag is the raw entity tag, including quotes and any W/ prefix. Pass it
	// verbatim to IfMatch / IfNoneMatch.
	ETag string
	// LastModified is the parsed Last-Modified header (zero if absent).
	LastModified time.Time
	ContentType  string
	// ContentLength is the body length, or -1 if unknown.
	ContentLength int64
	// ContentRange is the Content-Range of a 206 Partial Content response.
	ContentRange string
	// Links holds every Link header, resolved to absolute URIs.
	Links []Link
	// Linkset is the URI of the resource's linkset (rel="linkset").
	Linkset string
	// Parent is the URI of the parent container (rel="up").
	Parent string
	// Storage is the URI of the storage (rel="https://www.w3.org/ns/lws#storage").
	Storage string
	// Types holds the targets of rel="type" links.
	Types       TypeList
	Allow       []string
	AcceptPatch []string
	// Header is the raw response header.
	Header http.Header
}

// IsContainer reports whether the rel="type" links mark a container.
func (m *ResourceMetadata) IsContainer() bool { return m.Types.Has(TypeContainer) }

// IsDataResource reports whether the rel="type" links mark a data resource.
func (m *ResourceMetadata) IsDataResource() bool { return m.Types.Has(TypeDataResource) }

// Link returns the first link with the given relation type.
func (m *ResourceMetadata) Link(rel string) (Link, bool) { return findLink(m.Links, rel) }

// LinksWithRel returns every link with the given relation type.
func (m *ResourceMetadata) LinksWithRel(rel string) []Link {
	var out []Link
	for _, l := range m.Links {
		if relEquals(l.Rel, rel) {
			out = append(out, l)
		}
	}
	return out
}

func newMetadata(resp *http.Response) ResourceMetadata {
	u := responseURL(resp)
	m := ResourceMetadata{
		URL:           u,
		StatusCode:    resp.StatusCode,
		ETag:          resp.Header.Get("ETag"),
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: -1,
		ContentRange:  resp.Header.Get("Content-Range"),
		Links:         ParseLinkHeader(u, resp.Header.Values("Link")...),
		Allow:         splitList(resp.Header.Values("Allow")),
		AcceptPatch:   splitList(resp.Header.Values("Accept-Patch")),
		Header:        resp.Header,
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
			m.ContentLength = n
		}
	} else if resp.ContentLength >= 0 && resp.Request != nil && resp.Request.Method != http.MethodHead {
		m.ContentLength = resp.ContentLength
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			m.LastModified = t
		}
	}
	for _, l := range m.Links {
		switch {
		case relEquals(l.Rel, RelLinkset) && m.Linkset == "":
			m.Linkset = l.Href
		case relEquals(l.Rel, RelUp) && m.Parent == "":
			m.Parent = l.Href
		case l.Rel == RelStorage && m.Storage == "":
			m.Storage = l.Href
		case relEquals(l.Rel, RelType):
			m.Types = append(m.Types, l.Href)
		}
	}
	return m
}

// Resource is a read data resource: its metadata and body.
type Resource struct {
	ResourceMetadata
	// Body is the representation (empty when NotModified).
	Body []byte
	// NotModified is true when a conditional read returned 304 Not Modified.
	NotModified bool
}

// Text returns the body as a string (LWS text content is UTF-8 by default).
func (r *Resource) Text() string { return string(r.Body) }

// JSON decodes the body into v.
func (r *Resource) JSON(v any) error { return json.Unmarshal(r.Body, v) }
