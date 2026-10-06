// SPDX-License-Identifier: MIT

package lws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Linkset is an RFC 9264 linkset (application/linkset+json): the metadata of
// an LWS resource.
type Linkset struct {
	Contexts []LinkContext
}

// LinkContext is one link context object of a linkset: an anchor and its
// relations, in document order.
type LinkContext struct {
	Anchor    string
	Relations []Relation
}

// Relation holds the targets of one relation type within a link context.
type Relation struct {
	Rel     string
	Targets []LinkTarget
}

// LinkTarget is one target object: an href plus target attributes (such as
// "type", "title", "hreflang" or "title*") with their JSON values.
type LinkTarget struct {
	Href       string
	Attributes map[string]any
}

// Attr returns a string-valued target attribute.
func (t LinkTarget) Attr(name string) string {
	s, _ := t.Attributes[name].(string)
	return s
}

// MarshalJSON encodes the target object.
func (t LinkTarget) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(t.Attributes)+1)
	for k, v := range t.Attributes {
		m[k] = v
	}
	m["href"] = t.Href
	return json.Marshal(m)
}

// UnmarshalJSON decodes a target object.
func (t *LinkTarget) UnmarshalJSON(data []byte) error {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	href, ok := m["href"].(string)
	if !ok {
		return errors.New("lws: linkset target without href")
	}
	delete(m, "href")
	t.Href = href
	t.Attributes = nil
	if len(m) > 0 {
		t.Attributes = m
	}
	return nil
}

// MarshalJSON encodes the context object, preserving relation order.
func (lc LinkContext) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	anchor, err := json.Marshal(lc.Anchor)
	if err != nil {
		return nil, err
	}
	b.WriteString(`"anchor":`)
	b.Write(anchor)
	for _, r := range lc.Relations {
		key, _ := json.Marshal(r.Rel)
		targets := r.Targets
		if targets == nil {
			targets = []LinkTarget{}
		}
		val, err := json.Marshal(targets)
		if err != nil {
			return nil, err
		}
		b.WriteByte(',')
		b.Write(key)
		b.WriteByte(':')
		b.Write(val)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// UnmarshalJSON decodes the context object, preserving relation order.
func (lc *LinkContext) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("lws: linkset context must be an object")
	}
	*lc = LinkContext{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := tok.(string)
		if key == "anchor" {
			if err := dec.Decode(&lc.Anchor); err != nil {
				return err
			}
			continue
		}
		var targets []LinkTarget
		if err := dec.Decode(&targets); err != nil {
			return fmt.Errorf("lws: linkset relation %q: %w", key, err)
		}
		lc.Relations = append(lc.Relations, Relation{Rel: key, Targets: targets})
	}
	_, err = dec.Token()
	return err
}

// MarshalJSON encodes {"linkset": [...]}.
func (ls Linkset) MarshalJSON() ([]byte, error) {
	ctxs := ls.Contexts
	if ctxs == nil {
		ctxs = []LinkContext{}
	}
	return json.Marshal(struct {
		Linkset []LinkContext `json:"linkset"`
	}{ctxs})
}

// UnmarshalJSON decodes {"linkset": [...]}.
func (ls *Linkset) UnmarshalJSON(data []byte) error {
	var doc struct {
		Linkset *[]LinkContext `json:"linkset"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	if doc.Linkset == nil {
		return errors.New(`lws: linkset document has no "linkset" member`)
	}
	ls.Contexts = *doc.Linkset
	return nil
}

// ParseLinkset parses an application/linkset+json document.
func ParseLinkset(data []byte) (*Linkset, error) {
	var ls Linkset
	if err := json.Unmarshal(data, &ls); err != nil {
		return nil, err
	}
	return &ls, nil
}

// Context returns the context object for anchor (nil if absent).
func (ls *Linkset) Context(anchor string) *LinkContext {
	for i := range ls.Contexts {
		if ls.Contexts[i].Anchor == anchor {
			return &ls.Contexts[i]
		}
	}
	return nil
}

// Links flattens the linkset into Links. Each Link carries the context as
// its "anchor" parameter and string-valued target attributes as parameters.
func (ls *Linkset) Links() []Link {
	var out []Link
	for _, c := range ls.Contexts {
		for _, r := range c.Relations {
			for _, t := range r.Targets {
				params := map[string]string{"anchor": c.Anchor}
				for k, v := range t.Attributes {
					if s, ok := v.(string); ok {
						params[k] = s
					}
				}
				out = append(out, Link{Href: t.Href, Rel: r.Rel, Params: params})
			}
		}
	}
	return out
}

// Targets returns the targets of rel across all contexts.
func (ls *Linkset) Targets(rel string) []LinkTarget {
	var out []LinkTarget
	for _, c := range ls.Contexts {
		out = append(out, c.Targets(rel)...)
	}
	return out
}

// TargetsFor returns the targets of rel for one anchor.
func (ls *Linkset) TargetsFor(anchor, rel string) []LinkTarget {
	if c := ls.Context(anchor); c != nil {
		return c.Targets(rel)
	}
	return nil
}

// Targets returns the targets of rel in this context.
func (lc *LinkContext) Targets(rel string) []LinkTarget {
	for _, r := range lc.Relations {
		if relEquals(r.Rel, rel) {
			return r.Targets
		}
	}
	return nil
}

// Add appends a link (creating the context and relation as needed).
// attrs may be nil.
func (ls *Linkset) Add(anchor, rel, href string, attrs map[string]any) {
	c := ls.Context(anchor)
	if c == nil {
		ls.Contexts = append(ls.Contexts, LinkContext{Anchor: anchor})
		c = &ls.Contexts[len(ls.Contexts)-1]
	}
	t := LinkTarget{Href: href, Attributes: attrs}
	for i := range c.Relations {
		if c.Relations[i].Rel == rel {
			c.Relations[i].Targets = append(c.Relations[i].Targets, t)
			return
		}
	}
	c.Relations = append(c.Relations, Relation{Rel: rel, Targets: []LinkTarget{t}})
}

// Remove deletes links of rel from the anchor's context: the target with the
// given href, or all targets when href is "". Empty relations are dropped.
// It reports whether anything was removed.
func (ls *Linkset) Remove(anchor, rel, href string) bool {
	c := ls.Context(anchor)
	if c == nil {
		return false
	}
	removed := false
	rels := c.Relations[:0]
	for _, r := range c.Relations {
		if r.Rel == rel {
			kept := r.Targets[:0]
			for _, t := range r.Targets {
				if href == "" || t.Href == href {
					removed = true
					continue
				}
				kept = append(kept, t)
			}
			r.Targets = kept
			if len(r.Targets) == 0 {
				continue
			}
		}
		rels = append(rels, r)
	}
	c.Relations = rels
	return removed
}

// LinksetDocument is a retrieved linkset resource.
type LinksetDocument struct {
	// URL is the URI of the linkset resource (use it for UpdateLinkset and
	// PatchLinkset).
	URL string
	// ETag of the linkset resource, for conditional updates.
	ETag        string
	Linkset     *Linkset
	Allow       []string
	AcceptPatch []string
	Metadata    ResourceMetadata
}

// ReadLinkset discovers the linkset of the resource at resourceURL (via a
// HEAD and its rel="linkset" link) and retrieves it.
func (c *Client) ReadLinkset(ctx context.Context, resourceURL string, opts ...CallOption) (*LinksetDocument, error) {
	lsURL, err := c.LinksetURL(ctx, resourceURL, opts...)
	if err != nil {
		return nil, err
	}
	return c.ReadLinksetAt(ctx, lsURL, opts...)
}

// ReadLinksetAt retrieves the linkset resource at linksetURL.
func (c *Client) ReadLinksetAt(ctx context.Context, linksetURL string, opts ...CallOption) (*LinksetDocument, error) {
	o := applyCallOptions(opts)
	if o.accept == "" {
		o.accept = MediaLinksetJSON
	}
	resp, body, err := c.execute(ctx, http.MethodGet, linksetURL, nil, "", o)
	if err != nil {
		return nil, err
	}
	ls, err := ParseLinkset(body)
	if err != nil {
		return nil, &ProtocolError{Message: "malformed linkset", Err: err}
	}
	m := newMetadata(resp)
	return &LinksetDocument{
		URL:         responseURL(resp),
		ETag:        m.ETag,
		Linkset:     ls,
		Allow:       m.Allow,
		AcceptPatch: m.AcceptPatch,
		Metadata:    m,
	}, nil
}

// UpdateLinkset replaces the whole linkset (HTTP PUT). Servers need not
// support it: an unsupported PUT fails with ErrMethodNotAllowed.
//
// Honoured options: IfMatch, Header.
func (c *Client) UpdateLinkset(ctx context.Context, linksetURL string, ls *Linkset, opts ...CallOption) (*UpdateResult, error) {
	data, err := json.Marshal(ls)
	if err != nil {
		return nil, err
	}
	return c.modify(ctx, http.MethodPut, linksetURL, bytes.NewReader(data), MediaLinksetJSON, applyCallOptions(opts))
}

// PatchLinkset applies a JSON Patch to the linkset (the primary metadata
// management mechanism). Use JSONPointer to address relation keys that are
// URIs.
//
// Honoured options: IfMatch, Header.
func (c *Client) PatchLinkset(ctx context.Context, linksetURL string, patch JSONPatch, opts ...CallOption) (*UpdateResult, error) {
	return c.Patch(ctx, linksetURL, patch, opts...)
}
