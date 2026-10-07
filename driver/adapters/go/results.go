// SPDX-License-Identifier: MIT

package main

import (
	"encoding/base64"
	"encoding/json"
	"iter"
	"regexp"
	"strings"

	lws "github.com/ebremer/lws-client/go"
)

// The shared result shapes of PROTOCOL.md section 3.1. Absent values are omitted; lists that
// are always present are never null.

func list[T any](xs []T) []T {
	if xs == nil {
		return []T{}
	}
	return xs
}

type linkJSON struct {
	Href   string            `json:"href"`
	Rel    string            `json:"rel"`
	Params map[string]string `json:"params"`
}

type metadataJSON struct {
	URL           string     `json:"url"`
	Status        int        `json:"status"`
	ETag          string     `json:"etag,omitempty"`
	LastModified  string     `json:"lastModified,omitempty"`
	ContentType   string     `json:"contentType,omitempty"`
	ContentLength *int64     `json:"contentLength,omitempty"`
	Links         []linkJSON `json:"links"`
	Linkset       string     `json:"linkset,omitempty"`
	Parent        string     `json:"parent,omitempty"`
	Storage       string     `json:"storage,omitempty"`
	Types         []string   `json:"types"`
	Allow         []string   `json:"allow"`
	AcceptPatch   []string   `json:"acceptPatch"`
}

func metadataResult(m *lws.ResourceMetadata) metadataJSON {
	links := make([]linkJSON, 0, len(m.Links))
	for _, l := range m.Links {
		params := map[string]string{}
		for k, v := range l.Params {
			params[k] = v
		}
		links = append(links, linkJSON{Href: l.Href, Rel: l.Rel, Params: params})
	}
	r := metadataJSON{
		URL:         m.URL,
		Status:      m.StatusCode,
		ETag:        m.ETag,
		ContentType: m.ContentType,
		Links:       links,
		Linkset:     m.Linkset,
		Parent:      m.Parent,
		Storage:     m.Storage,
		Types:       list([]string(m.Types)),
		Allow:       list(m.Allow),
		AcceptPatch: list(m.AcceptPatch),
	}
	if m.Header != nil {
		r.LastModified = m.Header.Get("Last-Modified")
	}
	if m.ContentLength >= 0 {
		n := m.ContentLength
		r.ContentLength = &n
	}
	return r
}

type itemJSON struct {
	ID       string   `json:"id"`
	Types    []string `json:"types"`
	Format   string   `json:"format,omitempty"`
	Size     *int64   `json:"size,omitempty"`
	Modified string   `json:"modified,omitempty"`
}

func itemResult(i lws.ContainedResource) itemJSON {
	r := itemJSON{ID: i.ID, Types: list([]string(i.Types)), Format: i.Format, Modified: i.ModifiedRaw}
	if i.Size >= 0 {
		n := i.Size
		r.Size = &n
	}
	return r
}

func itemsResult(items []lws.ContainedResource) []itemJSON {
	out := make([]itemJSON, 0, len(items))
	for _, i := range items {
		out = append(out, itemResult(i))
	}
	return out
}

type pageJSON struct {
	ID         string       `json:"id,omitempty"`
	Types      []string     `json:"types"`
	TotalItems *int64       `json:"totalItems,omitempty"`
	Items      []itemJSON   `json:"items"`
	First      string       `json:"first,omitempty"`
	Next       string       `json:"next,omitempty"`
	Prev       string       `json:"prev,omitempty"`
	Last       string       `json:"last,omitempty"`
	Metadata   metadataJSON `json:"metadata"`
}

func pageResult(p *lws.ContainerPage) pageJSON {
	r := pageJSON{
		ID: p.ID, Types: list([]string(p.Types)), Items: itemsResult(p.Items),
		First: p.First, Next: p.Next, Prev: p.Prev, Last: p.Last, Metadata: metadataResult(&p.Metadata),
	}
	if p.TotalItems >= 0 {
		n := p.TotalItems
		r.TotalItems = &n
	}
	return r
}

type updateJSON struct {
	Status   int          `json:"status"`
	ETag     string       `json:"etag,omitempty"`
	Metadata metadataJSON `json:"metadata"`
}

func updateResult(u *lws.UpdateResult) updateJSON {
	return updateJSON{Status: u.StatusCode, ETag: u.ETag, Metadata: metadataResult(&u.Metadata)}
}

type createdJSON struct {
	Location string       `json:"location"`
	Metadata metadataJSON `json:"metadata"`
}

func createdResult(c *lws.CreateResult) createdJSON {
	return createdJSON{Location: c.Location, Metadata: metadataResult(&c.Metadata)}
}

type serviceJSON struct {
	ID               string    `json:"id,omitempty"`
	Types            []string  `json:"types"`
	ServiceEndpoint  string    `json:"serviceEndpoint"`
	SubscriptionType *[]string `json:"subscriptionType,omitempty"`
}

type verificationMethodJSON struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Controller string `json:"controller,omitempty"`
}

type storageJSON struct {
	ID                  string                   `json:"id"`
	Types               []string                 `json:"types"`
	StorageRoot         string                   `json:"storageRoot,omitempty"`
	Services            []serviceJSON            `json:"services"`
	VerificationMethods []verificationMethodJSON `json:"verificationMethods"`
	Raw                 json.RawMessage          `json:"raw,omitempty"`
}

func storageResult(s *lws.StorageDescription) storageJSON {
	r := storageJSON{
		ID: s.ID, Types: list([]string(s.Types)), Raw: s.Raw,
		Services: []serviceJSON{}, VerificationMethods: []verificationMethodJSON{},
	}
	// storageRoot is omitted when the library's StorageRoot() fails.
	if root, err := s.StorageRoot(); err == nil {
		r.StorageRoot = root
	}
	for _, svc := range s.Services {
		sj := serviceJSON{ID: svc.ID, Types: list([]string(svc.Types)), ServiceEndpoint: svc.ServiceEndpoint}
		if _, ok := svc.Raw["subscriptionType"]; ok {
			types := list(svc.SubscriptionTypes())
			sj.SubscriptionType = &types
		}
		r.Services = append(r.Services, sj)
	}
	for _, vm := range s.VerificationMethods {
		r.VerificationMethods = append(r.VerificationMethods, verificationMethodJSON{ID: vm.ID, Type: vm.Type, Controller: vm.Controller})
	}
	return r
}

type subscriptionJSON struct {
	Subscription string          `json:"subscription"`
	Types        []string        `json:"types"`
	Expires      string          `json:"expires,omitempty"`
	Raw          json.RawMessage `json:"raw,omitempty"`
}

func subscriptionResult(s *lws.Subscription) subscriptionJSON {
	types := []string{}
	if s.Type != "" {
		types = append(types, s.Type)
	}
	return subscriptionJSON{Subscription: s.URL, Types: types, Expires: s.ExpiresRaw, Raw: s.Raw}
}

type bodyJSON struct {
	Text   *string `json:"text,omitempty"`
	Base64 *string `json:"base64,omitempty"`
}

var textual = regexp.MustCompile(`(?i)^(text/|application/(json|xml|[^;]*\+json|[^;]*\+xml)\b)`)

// bodyResult is {"text"} for a textual content type, {"base64"} otherwise or without one.
func bodyResult(data []byte, contentType string) bodyJSON {
	if contentType != "" && textual.MatchString(strings.TrimSpace(contentType)) {
		s := string(data)
		return bodyJSON{Text: &s}
	}
	s := base64.StdEncoding.EncodeToString(data)
	return bodyJSON{Base64: &s}
}

type listJSON struct {
	Items     []itemJSON `json:"items"`
	Truncated bool       `json:"truncated"`
}

// take pulls at most limit+1 items from a lazy sequence and returns the first limit, and
// whether there was one more.
func take[T any](seq iter.Seq2[T, error], limit int64) ([]T, bool, error) {
	items := []T{}
	for item, err := range seq {
		if err != nil {
			return nil, false, err
		}
		if int64(len(items)) == limit {
			return items, true, nil
		}
		items = append(items, item)
	}
	return items, false, nil
}

func listResult(seq iter.Seq2[lws.ContainedResource, error], limit int64) (any, error) {
	items, truncated, err := take(seq, limit)
	if err != nil {
		return nil, err
	}
	return listJSON{Items: itemsResult(items), Truncated: truncated}, nil
}
