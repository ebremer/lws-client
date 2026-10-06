// SPDX-License-Identifier: MIT

package lws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// StorageDescription describes a storage: its services, capabilities and
// verification methods. It is a specialisation of a W3C Controlled
// Identifier document (media type application/lws+cid).
type StorageDescription struct {
	// ID is the canonical URI of the storage.
	ID                  string
	Types               TypeList
	Services            []Service
	Capabilities        []Capability
	VerificationMethods []VerificationMethod
	// Authentication lists the verification methods (by reference or
	// embedded) usable for authentication, e.g. webhook signing keys.
	Authentication []VerificationRelationship
	// Raw is the original JSON document.
	Raw json.RawMessage
}

// Service is an entry of a storage description's "service" set.
type Service struct {
	ID    string
	Types TypeList
	// ServiceEndpoint is the absolute URI of the service.
	ServiceEndpoint string
	// Raw holds every member of the service object, including extension
	// members such as subscriptionType or conformsTo.
	Raw map[string]json.RawMessage
}

// HasType reports whether the service has the given type.
func (s Service) HasType(t string) bool { return s.Types.Has(t) }

// Property decodes the named member of the service object into v.
func (s Service) Property(name string, v any) error {
	raw, ok := s.Raw[name]
	if !ok {
		return errors.New("lws: service has no property " + name)
	}
	return json.Unmarshal(raw, v)
}

// Strings returns the named member as a list of strings (accepting a single
// string or an array).
func (s Service) Strings(name string) []string {
	var t TypeList
	if raw, ok := s.Raw[name]; ok {
		_ = json.Unmarshal(raw, &t)
	}
	return t
}

// SubscriptionTypes returns the "subscriptionType" member of a
// NotificationService.
func (s Service) SubscriptionTypes() []string { return s.Strings("subscriptionType") }

// ConformsTo returns the "conformsTo" member (access profiles).
func (s Service) ConformsTo() []string { return s.Strings("conformsTo") }

// Capability is an entry of a storage description's "capability" set.
type Capability struct {
	ID    string
	Types TypeList
	Raw   map[string]json.RawMessage
}

// HasType reports whether the capability has the given type.
func (c Capability) HasType(t string) bool { return c.Types.Has(t) }

// Property decodes the named member of the capability object into v.
func (c Capability) Property(name string, v any) error {
	raw, ok := c.Raw[name]
	if !ok {
		return errors.New("lws: capability has no property " + name)
	}
	return json.Unmarshal(raw, v)
}

// VerificationMethod is a Controlled Identifier verification method.
type VerificationMethod struct {
	// ID is the method identifier exactly as written (it may be relative,
	// e.g. "#key-1").
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	Controller   string          `json:"controller,omitempty"`
	PublicKeyJWK *JWK            `json:"publicKeyJwk,omitempty"`
	Raw          json.RawMessage `json:"-"`
}

// VerificationRelationship is an entry of a verification relationship such as
// "authentication": either a reference to a verification method or an
// embedded one.
type VerificationRelationship struct {
	Reference string
	Embedded  *VerificationMethod
}

// ParseStorageDescription parses a storage description. Relative service
// endpoints are resolved against baseURL (which may be empty). It fails with
// a *ProtocolError if the document's type does not include "Storage".
func ParseStorageDescription(data []byte, baseURL string) (*StorageDescription, error) {
	var doc struct {
		ID                 string            `json:"id"`
		Type               TypeList          `json:"type"`
		Service            json.RawMessage   `json:"service"`
		Capability         json.RawMessage   `json:"capability"`
		VerificationMethod json.RawMessage   `json:"verificationMethod"`
		Authentication     []json.RawMessage `json:"authentication"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, &ProtocolError{Message: "malformed storage description", Err: err}
	}
	if !doc.Type.Has(TypeStorage) {
		return nil, protocolErr("storage description type %v does not include Storage", []string(doc.Type))
	}
	base := baseURL
	if doc.ID != "" {
		base = resolveURL(baseURL, doc.ID)
	}
	sd := &StorageDescription{ID: resolveURL(baseURL, doc.ID), Types: doc.Type, Raw: append(json.RawMessage(nil), data...)}
	for _, raw := range objectList(doc.Service) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, &ProtocolError{Message: "malformed service", Err: err}
		}
		s := Service{Raw: m}
		_ = json.Unmarshal(m["id"], &s.ID)
		_ = json.Unmarshal(m["type"], &s.Types)
		s.ServiceEndpoint = resolveURL(base, endpointString(m["serviceEndpoint"]))
		sd.Services = append(sd.Services, s)
	}
	for _, raw := range objectList(doc.Capability) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, &ProtocolError{Message: "malformed capability", Err: err}
		}
		cp := Capability{Raw: m}
		_ = json.Unmarshal(m["id"], &cp.ID)
		_ = json.Unmarshal(m["type"], &cp.Types)
		sd.Capabilities = append(sd.Capabilities, cp)
	}
	for _, raw := range objectList(doc.VerificationMethod) {
		vm, err := parseVerificationMethod(raw)
		if err != nil {
			return nil, err
		}
		sd.VerificationMethods = append(sd.VerificationMethods, *vm)
	}
	for _, raw := range doc.Authentication {
		raw = bytes.TrimSpace(raw)
		if len(raw) > 0 && raw[0] == '"' {
			var ref string
			_ = json.Unmarshal(raw, &ref)
			sd.Authentication = append(sd.Authentication, VerificationRelationship{Reference: ref})
			continue
		}
		vm, err := parseVerificationMethod(raw)
		if err != nil {
			return nil, err
		}
		sd.Authentication = append(sd.Authentication, VerificationRelationship{Embedded: vm})
	}
	return sd, nil
}

func parseVerificationMethod(raw json.RawMessage) (*VerificationMethod, error) {
	var vm VerificationMethod
	if err := json.Unmarshal(raw, &vm); err != nil {
		return nil, &ProtocolError{Message: "malformed verification method", Err: err}
	}
	vm.Raw = append(json.RawMessage(nil), raw...)
	return &vm, nil
}

// objectList accepts a JSON object or an array of objects.
func objectList(raw json.RawMessage) []json.RawMessage {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if raw[0] == '{' {
		return []json.RawMessage{raw}
	}
	var list []json.RawMessage
	_ = json.Unmarshal(raw, &list)
	return list
}

// endpointString extracts a URI from a serviceEndpoint value (a string, or
// the first string of an array).
func endpointString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil && len(list) > 0 {
		return list[0]
	}
	return ""
}

// StorageRoot returns the URI of the storage root container. It fails with
// a *ProtocolError if the description has no StorageRoot service.
func (sd *StorageDescription) StorageRoot() (string, error) {
	if s, ok := sd.Service(ServiceStorageRoot); ok && s.ServiceEndpoint != "" {
		return s.ServiceEndpoint, nil
	}
	return "", protocolErr("storage description %s has no StorageRoot service", sd.ID)
}

// Service returns the first service with the given type.
func (sd *StorageDescription) Service(typ string) (Service, bool) {
	for _, s := range sd.Services {
		if s.HasType(typ) {
			return s, true
		}
	}
	return Service{}, false
}

// ServicesOfType returns every service with the given type.
func (sd *StorageDescription) ServicesOfType(typ string) []Service {
	var out []Service
	for _, s := range sd.Services {
		if s.HasType(typ) {
			out = append(out, s)
		}
	}
	return out
}

// Capability returns the first capability with the given type.
func (sd *StorageDescription) Capability(typ string) (Capability, bool) {
	for _, c := range sd.Capabilities {
		if c.HasType(typ) {
			return c, true
		}
	}
	return Capability{}, false
}

// NotificationService returns the NotificationService, if advertised.
func (sd *StorageDescription) NotificationService() (Service, bool) {
	return sd.Service(ServiceNotification)
}

// AccessRequestService returns the AccessRequestService, if advertised.
func (sd *StorageDescription) AccessRequestService() (Service, bool) {
	return sd.Service(ServiceAccessRequest)
}

// AccessGrantService returns the AccessGrantService, if advertised.
func (sd *StorageDescription) AccessGrantService() (Service, bool) {
	return sd.Service(ServiceAccessGrant)
}

// TypeIndexService returns the TypeIndexService, if advertised.
func (sd *StorageDescription) TypeIndexService() (Service, bool) {
	return sd.Service(ServiceTypeIndex)
}

// TypeSearchService returns the TypeSearchService, if advertised.
func (sd *StorageDescription) TypeSearchService() (Service, bool) {
	return sd.Service(ServiceTypeSearch)
}

// VerificationMethod finds a verification method by full id, by fragment
// ("#key-1" or "key-1"), or by an id that resolves (against the storage id)
// to the given id.
func (sd *StorageDescription) VerificationMethod(idOrFragment string) (*VerificationMethod, bool) {
	for i := range sd.VerificationMethods {
		if sd.idMatches(sd.VerificationMethods[i].ID, idOrFragment) {
			return &sd.VerificationMethods[i], true
		}
	}
	return nil, false
}

// IsAuthenticationMethod reports whether the verification method id is
// referenced (or embedded) in the authentication relationship.
func (sd *StorageDescription) IsAuthenticationMethod(id string) bool {
	for _, a := range sd.Authentication {
		ref := a.Reference
		if a.Embedded != nil {
			ref = a.Embedded.ID
		}
		if ref != "" && (sd.idMatches(ref, id) || sd.idMatches(id, ref)) {
			return true
		}
	}
	return false
}

// idMatches reports whether the method identifier candidate (as written in
// the document) denotes want (a full id, "#frag" or "frag").
func (sd *StorageDescription) idMatches(candidate, want string) bool {
	if candidate == want {
		return true
	}
	absCandidate := resolveURL(sd.ID, candidate)
	absWant := want
	if !strings.Contains(want, ":") {
		w := want
		if !strings.HasPrefix(w, "#") {
			w = "#" + w
		}
		absWant = resolveURL(sd.ID, w)
	}
	return absCandidate == absWant
}

// GetStorageDescription retrieves and parses the storage description at
// storageURL.
func (c *Client) GetStorageDescription(ctx context.Context, storageURL string, opts ...CallOption) (*StorageDescription, error) {
	o := applyCallOptions(opts)
	if o.accept == "" {
		o.accept = MediaLWSCID + ", " + MediaLDJSON + ";q=0.9, " + MediaJSON + ";q=0.8"
	}
	resp, body, err := c.execute(ctx, http.MethodGet, storageURL, nil, "", o)
	if err != nil {
		return nil, err
	}
	return ParseStorageDescription(body, responseURL(resp))
}

// DiscoverStorage finds the storage that contains resourceURL (via the
// rel="https://www.w3.org/ns/lws#storage" link of a HEAD response, falling
// back to GET when HEAD is not allowed) and retrieves its description.
func (c *Client) DiscoverStorage(ctx context.Context, resourceURL string, opts ...CallOption) (*StorageDescription, error) {
	storage, err := c.storageLink(ctx, resourceURL, opts)
	if err != nil {
		return nil, err
	}
	return c.GetStorageDescription(ctx, storage, opts...)
}

func (c *Client) storageLink(ctx context.Context, resourceURL string, opts []CallOption) (string, error) {
	m, err := c.Head(ctx, resourceURL, opts...)
	if err != nil {
		var he *HTTPError
		if !errors.As(err, &he) {
			return "", err
		}
		// A 401 may still advertise the storage; a 405/501 means HEAD is not
		// supported, so fall back to GET.
		if l, ok := findLink(ParseLinkHeader(he.URL, he.Header.Values("Link")...), RelStorage); ok {
			return l.Href, nil
		}
		if he.StatusCode != http.StatusMethodNotAllowed && he.StatusCode != http.StatusNotImplemented {
			return "", err
		}
		r, gerr := c.Read(ctx, resourceURL, opts...)
		if gerr != nil {
			return "", gerr
		}
		m = &r.ResourceMetadata
	}
	if m.Storage == "" {
		return "", protocolErr("%s has no %s link", resourceURL, RelStorage)
	}
	return m.Storage, nil
}

// LinksetURL returns the URI of the resource's linkset (rel="linkset").
func (c *Client) LinksetURL(ctx context.Context, resourceURL string, opts ...CallOption) (string, error) {
	m, err := c.Head(ctx, resourceURL, opts...)
	if err != nil {
		return "", err
	}
	if m.Linkset == "" {
		return "", protocolErr("%s has no linkset link", resourceURL)
	}
	return m.Linkset, nil
}
