// SPDX-License-Identifier: MIT

package lws

import (
	"context"
	"encoding/json"
	"iter"
	"net/http"
	"strconv"
	"time"
)

// ContainerPage is one page of a container representation (or of a
// container-shaped result such as a type search).
type ContainerPage struct {
	// ID is the absolute URI of the container; for a page of search results
	// without one, the page's own URL.
	ID    string
	Types TypeList
	// TotalItems is the number of members visible to the client across all
	// pages (it may be approximate), or -1 when the server omitted it.
	TotalItems int64
	// Items are the members on this page.
	Items []ContainedResource
	// First, Next, Prev and Last are the absolute pagination URIs from the
	// Link header (empty when absent). They are opaque: follow them as-is.
	First, Next, Prev, Last string
	Metadata                ResourceMetadata
	Raw                     json.RawMessage
}

// IsContainer reports whether the page describes a container.
func (p *ContainerPage) IsContainer() bool {
	return p.Types.Has(TypeContainer) || p.Metadata.IsContainer()
}

// ContainedResource describes one member of a container.
type ContainedResource struct {
	// ID is the absolute URI of the member.
	ID    string
	Types TypeList
	// Format is the media type (always present for data resources).
	Format string
	// Size in bytes, or -1 when absent.
	Size int64
	// Modified is the parsed modification time; zero when absent or
	// unparseable (see ModifiedRaw).
	Modified    time.Time
	ModifiedRaw string
	Raw         json.RawMessage
}

// IsContainer reports whether the member is a container.
func (r ContainedResource) IsContainer() bool { return r.Types.Has(TypeContainer) }

// IsDataResource reports whether the member is a data resource.
func (r ContainedResource) IsDataResource() bool { return r.Types.Has(TypeDataResource) }

// HasType reports whether the member has the given type.
func (r ContainedResource) HasType(t string) bool { return r.Types.Has(t) }

type containerJSON struct {
	ID         string            `json:"id"`
	Type       TypeList          `json:"type"`
	TotalItems *json.Number      `json:"totalItems"`
	Items      []json.RawMessage `json:"items"`
}

// ParseContainerPage parses a container representation. Relative ids are
// resolved against baseURL and pagination links are taken from linkHeaders.
func ParseContainerPage(data []byte, baseURL string, linkHeaders ...string) (*ContainerPage, error) {
	var doc containerJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, &ProtocolError{Message: "malformed container representation", Err: err}
	}
	id := resolveURL(baseURL, doc.ID)
	if id == "" {
		id = baseURL // the page's own URL when the body names no id, as for a page of search results
	}
	p := &ContainerPage{
		ID:         id,
		Types:      doc.Type,
		TotalItems: -1,
		Raw:        append(json.RawMessage(nil), data...),
	}
	if doc.TotalItems != nil {
		if n, err := doc.TotalItems.Int64(); err == nil {
			p.TotalItems = n
		} else if f, err := doc.TotalItems.Float64(); err == nil {
			p.TotalItems = int64(f)
		}
	}
	p.Items = make([]ContainedResource, 0, len(doc.Items))
	for _, raw := range doc.Items {
		item, err := parseContainedResource(raw, baseURL)
		if err != nil {
			return nil, err
		}
		p.Items = append(p.Items, item)
	}
	links := ParseLinkHeader(baseURL, linkHeaders...)
	p.setPagination(links)
	return p, nil
}

func (p *ContainerPage) setPagination(links []Link) {
	for _, l := range links {
		switch {
		case relEquals(l.Rel, RelFirst) && p.First == "":
			p.First = l.Href
		case relEquals(l.Rel, RelNext) && p.Next == "":
			p.Next = l.Href
		case relEquals(l.Rel, RelPrev) && p.Prev == "":
			p.Prev = l.Href
		case relEquals(l.Rel, "previous") && p.Prev == "":
			p.Prev = l.Href
		case relEquals(l.Rel, RelLast) && p.Last == "":
			p.Last = l.Href
		}
	}
}

func parseContainedResource(raw json.RawMessage, baseURL string) (ContainedResource, error) {
	var item struct {
		ID       string          `json:"id"`
		Type     TypeList        `json:"type"`
		Format   string          `json:"format"`
		Size     json.RawMessage `json:"size"`
		Modified json.RawMessage `json:"modified"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		return ContainedResource{}, &ProtocolError{Message: "malformed container item", Err: err}
	}
	r := ContainedResource{
		ID:     resolveURL(baseURL, item.ID),
		Types:  item.Type,
		Format: item.Format,
		Size:   -1,
		Raw:    append(json.RawMessage(nil), raw...),
	}
	if len(item.Size) > 0 {
		var n json.Number
		if json.Unmarshal(item.Size, &n) == nil {
			if v, err := n.Int64(); err == nil {
				r.Size = v
			} else if f, err := strconv.ParseFloat(string(n), 64); err == nil {
				r.Size = int64(f)
			}
		}
	}
	if len(item.Modified) > 0 {
		var s string
		if json.Unmarshal(item.Modified, &s) == nil {
			r.ModifiedRaw = s
			r.Modified = parseDateTime(s)
		}
	}
	return r, nil
}

// parseDateTime parses an ISO 8601 / RFC 3339 date-time; it returns the zero
// time if s cannot be parsed.
func parseDateTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ReadContainer retrieves one page of the container at url (the first page,
// or any page URI previously returned in First/Next/Prev/Last). It fails with
// a *ProtocolError if the response is not a container representation.
//
// Honoured options: Accept (default application/lws+json), IfNoneMatch, Header.
func (c *Client) ReadContainer(ctx context.Context, url string, opts ...CallOption) (*ContainerPage, error) {
	return c.readPage(ctx, url, true, applyCallOptions(opts))
}

func (c *Client) readPage(ctx context.Context, url string, requireContainer bool, o *callOptions) (*ContainerPage, error) {
	if o.accept == "" {
		o.accept = MediaLWSJSON
	}
	resp, body, err := c.execute(ctx, http.MethodGet, url, nil, "", o)
	if err != nil {
		return nil, err
	}
	return pageFromResponse(resp, body, requireContainer)
}

func pageFromResponse(resp *http.Response, body []byte, requireContainer bool) (*ContainerPage, error) {
	if !isContainerMediaType(resp.Header.Get("Content-Type")) {
		return nil, protocolErr("unexpected media type %q for a container listing", resp.Header.Get("Content-Type"))
	}
	base := responseURL(resp)
	page, err := ParseContainerPage(body, base, resp.Header.Values("Link")...)
	if err != nil {
		return nil, err
	}
	page.Metadata = newMetadata(resp)
	if requireContainer && !page.IsContainer() {
		return nil, protocolErr("%s is not a container", base)
	}
	return page, nil
}

// ListContainerPages iterates over every page of the container at url,
// following rel="next" links lazily.
func (c *Client) ListContainerPages(ctx context.Context, url string, opts ...CallOption) iter.Seq2[*ContainerPage, error] {
	return c.pages(ctx, url, true, opts)
}

// ListContainer iterates lazily over every member of the container at url
// across all pages. Iteration stops at the first error, which is yielded.
func (c *Client) ListContainer(ctx context.Context, url string, opts ...CallOption) iter.Seq2[ContainedResource, error] {
	return flattenPages(c.pages(ctx, url, true, opts))
}

func (c *Client) pages(ctx context.Context, url string, requireContainer bool, opts []CallOption) iter.Seq2[*ContainerPage, error] {
	return func(yield func(*ContainerPage, error) bool) {
		seen := map[string]bool{}
		next := url
		for next != "" {
			if seen[next] {
				yield(nil, protocolErr("pagination loop at %s", next))
				return
			}
			seen[next] = true
			page, err := c.readPage(ctx, next, requireContainer, applyCallOptions(opts))
			if err != nil {
				yield(nil, err)
				return
			}
			if !yield(page, nil) {
				return
			}
			next = page.Next
		}
	}
}

func flattenPages(pages iter.Seq2[*ContainerPage, error]) iter.Seq2[ContainedResource, error] {
	return func(yield func(ContainedResource, error) bool) {
		for page, err := range pages {
			if err != nil {
				yield(ContainedResource{}, err)
				return
			}
			for _, item := range page.Items {
				if !yield(item, nil) {
					return
				}
			}
		}
	}
}
