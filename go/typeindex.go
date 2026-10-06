// SPDX-License-Identifier: MIT

package lws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"regexp"
)

// TypeIndexPage is one page of a Type Index Service listing: the distinct
// resource types the client is authorised to see.
type TypeIndexPage struct {
	// TotalItems is the number of types across all pages, or -1 if omitted.
	TotalItems int64
	// Types holds the type IRIs on this page.
	Types                   []string
	First, Next, Prev, Last string
	Metadata                ResourceMetadata
	Raw                     json.RawMessage
}

// ReadTypeIndex retrieves one page of the type index (the service endpoint
// or a page URI from a previous page).
func (c *Client) ReadTypeIndex(ctx context.Context, url string, opts ...CallOption) (*TypeIndexPage, error) {
	o := applyCallOptions(opts)
	if o.accept == "" {
		o.accept = MediaLWSJSON
	}
	resp, body, err := c.execute(ctx, http.MethodGet, url, nil, "", o)
	if err != nil {
		return nil, err
	}
	var doc struct {
		TotalItems *int64 `json:"totalItems"`
		Items      []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, &ProtocolError{Message: "malformed type index", Err: err}
	}
	base := responseURL(resp)
	p := &TypeIndexPage{TotalItems: -1, Metadata: newMetadata(resp), Raw: body}
	if doc.TotalItems != nil {
		p.TotalItems = *doc.TotalItems
	}
	for _, it := range doc.Items {
		p.Types = append(p.Types, it.ID)
	}
	var cp ContainerPage
	cp.setPagination(ParseLinkHeader(base, resp.Header.Values("Link")...))
	p.First, p.Next, p.Prev, p.Last = cp.First, cp.Next, cp.Prev, cp.Last
	return p, nil
}

// ListTypes iterates over every type in the type index, following pagination
// links lazily.
func (c *Client) ListTypes(ctx context.Context, serviceURL string, opts ...CallOption) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		seen := map[string]bool{}
		for next := serviceURL; next != ""; {
			if seen[next] {
				yield("", protocolErr("pagination loop at %s", next))
				return
			}
			seen[next] = true
			page, err := c.ReadTypeIndex(ctx, next, opts...)
			if err != nil {
				yield("", err)
				return
			}
			for _, t := range page.Types {
				if !yield(t, nil) {
					return
				}
			}
			next = page.Next
		}
	}
}

// TypeQuery is an application/lws-query+json filter in conjunctive normal
// form: every group must match (AND); a group matches if any of its IRIs
// matches (OR). Build one by chaining:
//
//	q := lws.NewTypeQuery().
//		AnyOf("https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person").
//		AllOf(lws.TypeDataResource)
//
// A query with no groups matches every resource visible to the client.
// Builder errors (relative IRIs, empty groups) are reported by Validate and
// MarshalJSON.
type TypeQuery struct {
	keys   []string
	groups map[string][][]string
	err    error
}

// NewTypeQuery returns an empty query.
func NewTypeQuery() *TypeQuery { return &TypeQuery{groups: map[string][][]string{}} }

// AllOf requires each type (every IRI is its own AND group).
func (q *TypeQuery) AllOf(iris ...string) *TypeQuery { return q.RelationAllOf(RelType, iris...) }

// AnyOf adds one OR group of types.
func (q *TypeQuery) AnyOf(iris ...string) *TypeQuery { return q.RelationAnyOf(RelType, iris...) }

// RelationAllOf requires each target of an indexed descriptive relation.
func (q *TypeQuery) RelationAllOf(rel string, iris ...string) *TypeQuery {
	for _, iri := range iris {
		q.add(rel, []string{iri})
	}
	return q
}

// RelationAnyOf adds one OR group for an indexed descriptive relation.
func (q *TypeQuery) RelationAnyOf(rel string, iris ...string) *TypeQuery {
	if len(iris) == 0 {
		q.fail(fmt.Errorf("lws: empty OR group for %q", rel))
		return q
	}
	q.add(rel, append([]string(nil), iris...))
	return q
}

var absoluteIRI = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*:[^\s<>"{}|\\^` + "`" + `]+$`)

func (q *TypeQuery) add(rel string, group []string) {
	if q.groups == nil {
		q.groups = map[string][][]string{}
	}
	if rel == "" {
		q.fail(errors.New("lws: empty relation key"))
		return
	}
	for _, iri := range group {
		if !absoluteIRI.MatchString(iri) {
			q.fail(fmt.Errorf("lws: %q is not an absolute IRI", iri))
			return
		}
	}
	if _, ok := q.groups[rel]; !ok {
		q.keys = append(q.keys, rel)
	}
	q.groups[rel] = append(q.groups[rel], group)
}

func (q *TypeQuery) fail(err error) {
	if q.err == nil {
		q.err = err
	}
}

// Validate reports the first builder error.
func (q *TypeQuery) Validate() error { return q.err }

// MarshalJSON encodes the filter document (plain JSON, no @context). A
// one-IRI OR group is encoded as a plain string.
func (q *TypeQuery) MarshalJSON() ([]byte, error) {
	if q.err != nil {
		return nil, q.err
	}
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range q.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		key, _ := json.Marshal(k)
		b.Write(key)
		b.WriteByte(':')
		values := make([]any, 0, len(q.groups[k]))
		for _, g := range q.groups[k] {
			if len(g) == 1 {
				values = append(values, g[0])
			} else {
				values = append(values, g)
			}
		}
		v, err := json.Marshal(values)
		if err != nil {
			return nil, err
		}
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// SearchTypes runs a type search (HTTP QUERY with an
// application/lws-query+json body) and returns the first result page. The
// result is a synthetic ContainerPage; follow Next with SearchPage or use
// SearchAll.
func (c *Client) SearchTypes(ctx context.Context, serviceURL string, q *TypeQuery, opts ...CallOption) (*ContainerPage, error) {
	if q == nil {
		q = NewTypeQuery()
	}
	data, err := q.MarshalJSON()
	if err != nil {
		return nil, err
	}
	o := applyCallOptions(opts)
	if o.accept == "" {
		o.accept = MediaLWSJSON
	}
	resp, body, err := c.execute(ctx, "QUERY", serviceURL, bytes.NewReader(data), MediaLWSQueryJSON, o)
	if err != nil {
		return nil, err
	}
	return pageFromResponse(resp, body, false)
}

// SearchPage retrieves a subsequent search result page (an opaque page URI
// from a previous result). An expired page fails with ErrNotFound or
// ErrGone; restart the search.
func (c *Client) SearchPage(ctx context.Context, pageURL string, opts ...CallOption) (*ContainerPage, error) {
	return c.readPage(ctx, pageURL, false, applyCallOptions(opts))
}

// SearchAll runs a type search and iterates over every matching resource,
// following the opaque next links lazily.
func (c *Client) SearchAll(ctx context.Context, serviceURL string, q *TypeQuery, opts ...CallOption) iter.Seq2[ContainedResource, error] {
	return flattenPages(func(yield func(*ContainerPage, error) bool) {
		page, err := c.SearchTypes(ctx, serviceURL, q, opts...)
		seen := map[string]bool{}
		for {
			if err != nil {
				yield(nil, err)
				return
			}
			if !yield(page, nil) || page.Next == "" {
				return
			}
			if seen[page.Next] {
				yield(nil, protocolErr("pagination loop at %s", page.Next))
				return
			}
			seen[page.Next] = true
			page, err = c.SearchPage(ctx, page.Next, opts...)
		}
	})
}

// AcceptedQueryFormats asks the search endpoint (OPTIONS) which query
// formats it accepts, from its Accept-Query header.
func (c *Client) AcceptedQueryFormats(ctx context.Context, serviceURL string, opts ...CallOption) ([]string, error) {
	resp, _, err := c.execute(ctx, http.MethodOptions, serviceURL, nil, "", applyCallOptions(opts))
	if err != nil {
		return nil, err
	}
	return parseAcceptQuery(resp.Header.Values("Accept-Query")), nil
}
