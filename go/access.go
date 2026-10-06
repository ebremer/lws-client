// SPDX-License-Identifier: MIT

package lws

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"net/http"
	"time"
)

// AccessTarget selects the resources an access policy applies to.
type AccessTarget struct {
	// Type is the target matcher, e.g. "StorageResource", "Container",
	// "DataResource" or a full IRI.
	Type string `json:"type"`
	// Values identify the target resources.
	Values []string `json:"value"`
}

// Constraint is an ODRL constraint qualifying an access policy.
type Constraint struct {
	LeftOperand string `json:"leftOperand"`
	Operator    string `json:"operator"`
	// RightOperand is a string, an array of strings or another JSON value.
	RightOperand any `json:"rightOperand"`
}

// PurposeConstraint restricts access to a purpose (purpose eq uri).
func PurposeConstraint(uri string) Constraint {
	return Constraint{OperandPurpose, OperatorEq, uri}
}

// PurposeAnyOf restricts access to any of the purposes.
func PurposeAnyOf(uris ...string) Constraint {
	return Constraint{OperandPurpose, OperatorIsAnyOf, uris}
}

// ClientConstraint restricts access to one client application.
func ClientConstraint(clientID string) Constraint {
	return Constraint{OperandClient, OperatorEq, clientID}
}

// FormatConstraint restricts access to resources of one media type.
func FormatConstraint(mediaType string) Constraint {
	return Constraint{OperandFormat, OperatorEq, mediaType}
}

// FormatAnyOf restricts access to resources of any of the media types.
func FormatAnyOf(mediaTypes ...string) Constraint {
	return Constraint{OperandFormat, OperatorIsAnyOf, mediaTypes}
}

// TypeConstraint restricts access to resources of one type.
func TypeConstraint(typeIRI string) Constraint {
	return Constraint{OperandType, OperatorEq, typeIRI}
}

// TypeAnyOf restricts access to resources of any of the types.
func TypeAnyOf(typeIRIs ...string) Constraint {
	return Constraint{OperandType, OperatorIsAnyOf, typeIRIs}
}

// NotBefore limits access to times at or after t (dateTime gteq).
func NotBefore(t time.Time) Constraint {
	return Constraint{OperandDateTime, OperatorGteq, t.UTC().Format(time.RFC3339)}
}

// NotAfter limits access to times at or before t (dateTime lteq).
func NotAfter(t time.Time) Constraint {
	return Constraint{OperandDateTime, OperatorLteq, t.UTC().Format(time.RFC3339)}
}

// AccessPolicy is one entry of an access request's or grant's "access" set
// (the LWS Access Profile, based on ODRL).
type AccessPolicy struct {
	Types       TypeList      `json:"type"`
	Actions     []string      `json:"action"`
	Assignee    string        `json:"assignee"`
	Target      *AccessTarget `json:"target,omitempty"`
	Constraints []Constraint  `json:"constraint,omitempty"`
}

// NewAccessPolicy returns a policy of type AccessPolicy for assignee with the
// given actions (ActionRead, ActionModify, ActionCreate, ActionDelete).
func NewAccessPolicy(assignee string, actions ...string) AccessPolicy {
	return AccessPolicy{Types: TypeList{TypeAccessPolicy}, Actions: actions, Assignee: assignee}
}

// WithTarget returns a copy of the policy targeting values with the given
// matcher type (e.g. "StorageResource").
func (p AccessPolicy) WithTarget(matcher string, values ...string) AccessPolicy {
	p.Target = &AccessTarget{Type: matcher, Values: values}
	return p
}

// WithConstraints returns a copy of the policy with constraints appended.
func (p AccessPolicy) WithConstraints(cs ...Constraint) AccessPolicy {
	p.Constraints = append(append([]Constraint(nil), p.Constraints...), cs...)
	return p
}

func (p AccessPolicy) validate() error {
	if len(p.Actions) == 0 {
		return errors.New("lws: access policy needs at least one action")
	}
	if p.Assignee == "" {
		return errors.New("lws: access policy needs an assignee")
	}
	if !p.Types.Has(TypeAccessPolicy) {
		return errors.New("lws: access policy type must include AccessPolicy")
	}
	return nil
}

// accessDocument is the shared shape of access requests and grants.
type accessDocument struct {
	Types   TypeList
	Storage string
	Inbox   string
	Access  []AccessPolicy
	Raw     json.RawMessage
}

func (d accessDocument) marshal(requiredType string) ([]byte, error) {
	if err := d.validate(requiredType); err != nil {
		return nil, err
	}
	types := d.Types
	if len(types) == 0 {
		types = TypeList{requiredType}
	}
	doc := map[string]any{
		"@context": []string{LWSContext},
		"type":     types,
		"storage":  d.Storage,
		"access":   d.Access,
	}
	if d.Inbox != "" {
		doc["inbox"] = d.Inbox
	}
	return json.Marshal(doc)
}

func (d accessDocument) validate(requiredType string) error {
	if len(d.Types) > 0 && !d.Types.Has(requiredType) {
		return errors.New("lws: type must include " + requiredType)
	}
	if d.Storage == "" {
		return errors.New("lws: storage is required")
	}
	if len(d.Access) == 0 {
		return errors.New("lws: at least one access policy is required")
	}
	for _, p := range d.Access {
		if err := p.validate(); err != nil {
			return err
		}
	}
	return nil
}

func unmarshalAccess(data []byte, requiredType string) (accessDocument, error) {
	var doc struct {
		Type    TypeList       `json:"type"`
		Storage string         `json:"storage"`
		Inbox   string         `json:"inbox"`
		Access  []AccessPolicy `json:"access"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return accessDocument{}, err
	}
	if !doc.Type.Has(requiredType) {
		return accessDocument{}, protocolErr("document type %v does not include %s", []string(doc.Type), requiredType)
	}
	return accessDocument{Types: doc.Type, Storage: doc.Storage, Inbox: doc.Inbox, Access: doc.Access,
		Raw: append(json.RawMessage(nil), data...)}, nil
}

// AccessRequest is a request by an agent for access to resources.
type AccessRequest struct {
	// Types defaults to ["AccessRequest"].
	Types   TypeList
	Storage string
	// Inbox optionally receives notifications about the request.
	Inbox  string
	Access []AccessPolicy
	// Raw is the document as received (unset for locally built requests).
	Raw json.RawMessage
}

// NewAccessRequest returns an access request for storage.
func NewAccessRequest(storage string, policies ...AccessPolicy) *AccessRequest {
	return &AccessRequest{Types: TypeList{TypeAccessRequest}, Storage: storage, Access: policies}
}

// Validate checks the required members.
func (r *AccessRequest) Validate() error {
	return accessDocument{r.Types, r.Storage, r.Inbox, r.Access, nil}.validate(TypeAccessRequest)
}

// MarshalJSON encodes the application/lws+json document.
func (r AccessRequest) MarshalJSON() ([]byte, error) {
	return accessDocument{r.Types, r.Storage, r.Inbox, r.Access, nil}.marshal(TypeAccessRequest)
}

// UnmarshalJSON decodes an access request.
func (r *AccessRequest) UnmarshalJSON(data []byte) error {
	d, err := unmarshalAccess(data, TypeAccessRequest)
	if err != nil {
		return err
	}
	*r = AccessRequest{Types: d.Types, Storage: d.Storage, Inbox: d.Inbox, Access: d.Access, Raw: d.Raw}
	return nil
}

// AccessGrant is an authorization by a storage controller granting access
// to resources. A grant is a record, not a token: the server adjusts its
// access policies when grants are created or revoked.
type AccessGrant struct {
	// Types defaults to ["AccessGrant"].
	Types   TypeList
	Storage string
	Inbox   string
	Access  []AccessPolicy
	Raw     json.RawMessage
}

// NewAccessGrant returns an access grant for storage.
func NewAccessGrant(storage string, policies ...AccessPolicy) *AccessGrant {
	return &AccessGrant{Types: TypeList{TypeAccessGrant}, Storage: storage, Access: policies}
}

// Validate checks the required members.
func (g *AccessGrant) Validate() error {
	return accessDocument{g.Types, g.Storage, g.Inbox, g.Access, nil}.validate(TypeAccessGrant)
}

// MarshalJSON encodes the application/lws+json document.
func (g AccessGrant) MarshalJSON() ([]byte, error) {
	return accessDocument{g.Types, g.Storage, g.Inbox, g.Access, nil}.marshal(TypeAccessGrant)
}

// UnmarshalJSON decodes an access grant.
func (g *AccessGrant) UnmarshalJSON(data []byte) error {
	d, err := unmarshalAccess(data, TypeAccessGrant)
	if err != nil {
		return err
	}
	*g = AccessGrant{Types: d.Types, Storage: d.Storage, Inbox: d.Inbox, Access: d.Access, Raw: d.Raw}
	return nil
}

func (c *Client) postAccess(ctx context.Context, serviceURL string, doc json.Marshaler, opts []CallOption) (string, error) {
	data, err := doc.MarshalJSON()
	if err != nil {
		return "", err
	}
	resp, _, err := c.executeJSON(ctx, http.MethodPost, serviceURL, json.RawMessage(data), MediaLWSJSON, applyCallOptions(opts))
	if err != nil {
		return "", err
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", protocolErr("access endpoint response has no Location header")
	}
	return resolveURL(responseURL(resp), loc), nil
}

func (c *Client) getAccess(ctx context.Context, url string, v json.Unmarshaler, opts []CallOption) error {
	o := applyCallOptions(opts)
	if o.accept == "" {
		o.accept = MediaLWSJSON
	}
	_, body, err := c.execute(ctx, http.MethodGet, url, nil, "", o)
	if err != nil {
		return err
	}
	if err := v.UnmarshalJSON(body); err != nil {
		var pe *ProtocolError
		if errors.As(err, &pe) {
			return err
		}
		return &ProtocolError{Message: "malformed access document", Err: err}
	}
	return nil
}

// RequestAccess submits an access request to the AccessRequestService
// endpoint serviceURL and returns the URL of the created request.
func (c *Client) RequestAccess(ctx context.Context, serviceURL string, req *AccessRequest, opts ...CallOption) (string, error) {
	return c.postAccess(ctx, serviceURL, req, opts)
}

// ListAccessRequests iterates over the access requests listed by the
// endpoint.
func (c *Client) ListAccessRequests(ctx context.Context, serviceURL string, opts ...CallOption) iter.Seq2[ContainedResource, error] {
	return flattenPages(c.pages(ctx, serviceURL, false, opts))
}

// GetAccessRequest retrieves an access request.
func (c *Client) GetAccessRequest(ctx context.Context, url string, opts ...CallOption) (*AccessRequest, error) {
	var r AccessRequest
	if err := c.getAccess(ctx, url, &r, opts); err != nil {
		return nil, err
	}
	return &r, nil
}

// CancelAccessRequest deletes an access request.
func (c *Client) CancelAccessRequest(ctx context.Context, url string, opts ...CallOption) error {
	return c.Delete(ctx, url, opts...)
}

// GrantAccess creates an access grant at the AccessGrantService endpoint
// serviceURL and returns the URL of the grant.
func (c *Client) GrantAccess(ctx context.Context, serviceURL string, grant *AccessGrant, opts ...CallOption) (string, error) {
	return c.postAccess(ctx, serviceURL, grant, opts)
}

// ListAccessGrants iterates over the access grants listed by the endpoint.
func (c *Client) ListAccessGrants(ctx context.Context, serviceURL string, opts ...CallOption) iter.Seq2[ContainedResource, error] {
	return flattenPages(c.pages(ctx, serviceURL, false, opts))
}

// GetAccessGrant retrieves an access grant.
func (c *Client) GetAccessGrant(ctx context.Context, url string, opts ...CallOption) (*AccessGrant, error) {
	var g AccessGrant
	if err := c.getAccess(ctx, url, &g, opts); err != nil {
		return nil, err
	}
	return &g, nil
}

// RevokeAccessGrant deletes (revokes) an access grant.
func (c *Client) RevokeAccessGrant(ctx context.Context, url string, opts ...CallOption) error {
	return c.Delete(ctx, url, opts...)
}
