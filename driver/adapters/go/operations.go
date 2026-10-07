// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"net/http"
	"time"

	lws "github.com/ebremer/lws-client/go"
)

// adapter holds the client every operation uses; configure replaces it.
type adapter struct {
	client *lws.Client
}

type operation func(a *adapter, x args) (any, error)

// operations implements every operation of PROTOCOL.md section 4, in its order.
var operations = []struct {
	name string
	run  operation
}{
	{"configure", (*adapter).configure},
	{"discover_storage", (*adapter).discoverStorage},
	{"get_storage_description", (*adapter).getStorageDescription},
	{"head", (*adapter).head},
	{"read", (*adapter).read},
	{"read_container", (*adapter).readContainer},
	{"list_container", (*adapter).listContainer},
	{"create", (*adapter).create},
	{"create_container", (*adapter).createContainer},
	{"update", (*adapter).update},
	{"patch", (*adapter).patch},
	{"delete", (*adapter).delete},
	{"linkset_url", (*adapter).linksetURL},
	{"read_linkset", (*adapter).readLinkset},
	{"update_linkset", (*adapter).updateLinkset},
	{"patch_linkset", (*adapter).patchLinkset},
	{"subscribe", (*adapter).subscribe},
	{"list_subscriptions", (*adapter).listSubscriptions},
	{"get_subscription", (*adapter).getSubscription},
	{"unsubscribe", (*adapter).unsubscribe},
	{"verify_notification", (*adapter).verifyNotification},
	{"request_access", (*adapter).requestAccess},
	{"get_access_request", (*adapter).getAccessRequest},
	{"list_access_requests", (*adapter).listAccessRequests},
	{"cancel_access_request", (*adapter).cancelAccessRequest},
	{"grant_access", (*adapter).grantAccess},
	{"get_access_grant", (*adapter).getAccessGrant},
	{"list_access_grants", (*adapter).listAccessGrants},
	{"revoke_access_grant", (*adapter).revokeAccessGrant},
	{"read_type_index", (*adapter).readTypeIndex},
	{"list_types", (*adapter).listTypes},
	{"search_types", (*adapter).searchTypes},
	{"search_all", (*adapter).searchAll},
	{"accepted_query_formats", (*adapter).acceptedQueryFormats},
	{"shutdown", (*adapter).shutdown},
}

// Requests carry no deadline of their own: timeoutSeconds is the client's option.
var ctx = context.Background()

// ---------------------------------------------------------------------------------------------
// configure

type configureJSON struct {
	Library string `json:"library"`
	Agent   string `json:"agent,omitempty"`
	Kid     string `json:"kid,omitempty"`
}

func (a *adapter) configure(x args) (any, error) {
	auth := args{"type": json.RawMessage(`"none"`)}
	if raw, ok := x.raw("auth"); ok {
		obj, ok := objectOf(raw)
		if !ok {
			return nil, invalid("argument 'auth' must be an object")
		}
		auth = obj
	}
	var exchange lws.TokenExchangeOptions
	allowInsecure, ok, err := x.optBool("allowInsecureHttp")
	if err != nil {
		return nil, err
	}
	if ok {
		exchange.AllowInsecureHTTP = allowInsecure
	}
	result := configureJSON{Library: library}
	var authenticator lws.Authenticator
	typ, _, err := auth.optString("type")
	if err != nil {
		return nil, err
	}
	switch typ {
	case "none":
	case "bearer":
		token, err := auth.str("token")
		if err != nil {
			return nil, err
		}
		realm, _, err := auth.optString("realm")
		if err != nil {
			return nil, err
		}
		authenticator = lws.NewBearerTokenAuthenticator(token, realm)
	case "openid":
		idToken, err := auth.str("idToken")
		if err != nil {
			return nil, err
		}
		authenticator = lws.NewTokenExchangeAuthenticator(lws.NewOpenIDCredentials(idToken), &exchange)
	case "selfSigned":
		agent, err := auth.str("agent")
		if err != nil {
			return nil, err
		}
		raw, err := auth.object("privateJwk")
		if err != nil {
			return nil, err
		}
		jwk, err := lws.ParseJWK(raw)
		if err != nil {
			return nil, invalid("argument 'privateJwk' is not a JWK: %v", err)
		}
		members, _ := objectOf(raw)
		kid, ok, err := auth.optString("kid")
		if err != nil {
			return nil, err
		}
		if !ok {
			if kid, ok, _ = members.optString("kid"); !ok {
				return nil, invalid("selfSigned needs 'kid', or a 'kid' in the private JWK")
			}
		}
		key, err := jwk.PrivateKey()
		if err != nil {
			return nil, invalid("argument 'privateJwk': %v", err)
		}
		credentials, err := lws.NewSelfSignedCredentials(agent, key, kid, nil)
		if err != nil {
			return nil, invalid("selfSigned: %v", err)
		}
		authenticator = lws.NewTokenExchangeAuthenticator(credentials, &exchange)
		result.Agent, result.Kid = agent, kid
	case "didKey":
		algorithm, ok, err := auth.optString("algorithm")
		if err != nil {
			return nil, err
		}
		if !ok {
			algorithm = "ES256"
		}
		var key crypto.Signer
		switch algorithm {
		case "ES256":
			k, err := lws.GenerateP256Key()
			if err != nil {
				return nil, err
			}
			key = k
		case "EdDSA":
			k, err := lws.GenerateEd25519Key()
			if err != nil {
				return nil, err
			}
			key = k
		default:
			return nil, invalid("unknown algorithm '%s'", algorithm)
		}
		credentials, err := lws.NewDIDKeyCredentials(key, nil)
		if err != nil {
			return nil, err
		}
		authenticator = lws.NewTokenExchangeAuthenticator(credentials, &exchange)
		result.Agent, result.Kid = credentials.Agent(), credentials.KeyID()
	default:
		return nil, invalid("unknown auth type '%s'", typ)
	}

	var options []lws.Option
	if authenticator != nil {
		options = append(options, lws.WithAuthenticator(authenticator))
	}
	userAgent, ok, err := x.optString("userAgent")
	if err != nil {
		return nil, err
	}
	if ok {
		options = append(options, lws.WithUserAgent(userAgent))
	}
	timeout, ok, err := x.optNumber("timeoutSeconds")
	if err != nil {
		return nil, err
	}
	if ok {
		if timeout < 0 {
			return nil, invalid("argument 'timeoutSeconds' must not be negative")
		}
		options = append(options, lws.WithTimeout(time.Duration(timeout*float64(time.Second))))
	}
	headers, ok, err := x.optObject("headers")
	if err != nil {
		return nil, err
	}
	if ok {
		members, _ := orderedObject(headers)
		for _, m := range members {
			var value string
			if len(m.value) == 0 || jsonKind(m.value) != "string" || json.Unmarshal(m.value, &value) != nil {
				return nil, invalid("header '%s' must be a string", m.name)
			}
			options = append(options, lws.WithHeader(m.name, value))
		}
	}
	a.client = lws.NewClient(options...)
	return result, nil
}

// ---------------------------------------------------------------------------------------------
// Discovery and reading

func (a *adapter) discoverStorage(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	s, err := a.client.DiscoverStorage(ctx, u)
	if err != nil {
		return nil, err
	}
	return storageResult(s), nil
}

func (a *adapter) getStorageDescription(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	s, err := a.client.GetStorageDescription(ctx, u)
	if err != nil {
		return nil, err
	}
	return storageResult(s), nil
}

func (a *adapter) head(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	m, err := a.client.Head(ctx, u)
	if err != nil {
		return nil, err
	}
	return metadataResult(m), nil
}

type readJSON struct {
	Metadata     metadataJSON `json:"metadata"`
	NotModified  bool         `json:"notModified"`
	ContentRange string       `json:"contentRange,omitempty"`
	Body         bodyJSON     `json:"body"`
}

func (a *adapter) read(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	var options []lws.CallOption
	accept, ok, err := x.optString("accept")
	if err != nil {
		return nil, err
	}
	if ok {
		options = append(options, lws.Accept(accept))
	}
	start, hasStart, err := x.optInt("rangeStart")
	if err != nil {
		return nil, err
	}
	end, hasEnd, err := x.optInt("rangeEnd")
	if err != nil {
		return nil, err
	}
	switch {
	case hasStart && hasEnd:
		options = append(options, lws.ByteRange(start, end))
	case hasStart:
		options = append(options, lws.ByteRange(start, -1)) // a negative end means "to the end"
	case hasEnd:
		return nil, invalid("rangeEnd needs rangeStart")
	}
	ifNoneMatch, ok, err := x.optString("ifNoneMatch")
	if err != nil {
		return nil, err
	}
	if ok {
		options = append(options, lws.IfNoneMatch(ifNoneMatch))
	}
	prefer, ok, err := x.optString("prefer")
	if err != nil {
		return nil, err
	}
	if ok {
		options = append(options, lws.Prefer(prefer))
	}
	r, err := a.client.Read(ctx, u, options...)
	if err != nil {
		return nil, err
	}
	return readJSON{
		Metadata:     metadataResult(&r.ResourceMetadata),
		NotModified:  r.NotModified,
		ContentRange: r.ContentRange,
		Body:         bodyResult(r.Body, r.ContentType),
	}, nil
}

func (a *adapter) readContainer(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	p, err := a.client.ReadContainer(ctx, u)
	if err != nil {
		return nil, err
	}
	return pageResult(p), nil
}

func (a *adapter) listContainer(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	limit, err := x.limit()
	if err != nil {
		return nil, err
	}
	return listResult(a.client.ListContainer(ctx, u), limit)
}

// ---------------------------------------------------------------------------------------------
// Writing

// conditions returns the ifMatch (and, when allowed, ifNoneMatch) options.
func conditions(x args, ifNoneMatch bool) ([]lws.CallOption, error) {
	var options []lws.CallOption
	ifMatch, ok, err := x.optString("ifMatch")
	if err != nil {
		return nil, err
	}
	if ok {
		options = append(options, lws.IfMatch(ifMatch))
	}
	if ifNoneMatch {
		v, ok, err := x.optString("ifNoneMatch")
		if err != nil {
			return nil, err
		}
		if ok {
			options = append(options, lws.IfNoneMatch(v))
		}
	}
	return options, nil
}

func (a *adapter) create(x args) (any, error) {
	container, err := x.url("container")
	if err != nil {
		return nil, err
	}
	contentType, hasContentType, err := x.optString("contentType")
	if err != nil {
		return nil, err
	}
	data, contentType, err := bodyOf(x, contentType, hasContentType)
	if err != nil {
		return nil, err
	}
	var options []lws.CallOption
	slug, ok, err := x.optString("slug")
	if err != nil {
		return nil, err
	}
	if ok {
		options = append(options, lws.Slug(slug))
	}
	types, ok, err := x.optStrings("types")
	if err != nil {
		return nil, err
	}
	if ok {
		options = append(options, lws.Types(types...))
	}
	if raw, ok, err := x.typed("links", "array"); err != nil {
		return nil, err
	} else if ok {
		var elements []json.RawMessage
		_ = json.Unmarshal(raw, &elements)
		links := make([]lws.Link, 0, len(elements))
		for _, e := range elements {
			l, ok := objectOf(e)
			if !ok {
				return nil, invalid("a link must be an object with href and rel")
			}
			href, err := l.str("href")
			if err != nil {
				return nil, invalid("a link must be an object with href and rel")
			}
			rel, err := l.str("rel")
			if err != nil {
				return nil, invalid("a link must be an object with href and rel")
			}
			links = append(links, lws.NewLink(href, rel))
		}
		options = append(options, lws.Links(links...))
	}
	c, err := a.client.Create(ctx, container, bytes.NewReader(data), contentType, options...)
	if err != nil {
		return nil, err
	}
	return createdResult(c), nil
}

func (a *adapter) createContainer(x args) (any, error) {
	parent, err := x.url("parent")
	if err != nil {
		return nil, err
	}
	var options []lws.CallOption
	slug, ok, err := x.optString("slug")
	if err != nil {
		return nil, err
	}
	if ok {
		options = append(options, lws.Slug(slug))
	}
	c, err := a.client.CreateContainer(ctx, parent, options...)
	if err != nil {
		return nil, err
	}
	return createdResult(c), nil
}

func (a *adapter) update(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	if _, ok := x.raw("body"); !ok {
		return nil, invalid("missing argument 'body'")
	}
	contentType, hasContentType, err := x.optString("contentType")
	if err != nil {
		return nil, err
	}
	data, contentType, err := bodyOf(x, contentType, hasContentType)
	if err != nil {
		return nil, err
	}
	options, err := conditions(x, true)
	if err != nil {
		return nil, err
	}
	r, err := a.client.Update(ctx, u, bytes.NewReader(data), contentType, options...)
	if err != nil {
		return nil, err
	}
	return updateResult(r), nil
}

// patchOf rebuilds an RFC 6902 operations array with the library's JSONPatch builder. Values
// are passed as their exact JSON.
func patchOf(x args) (lws.JSONPatch, error) {
	raw, ok := x.raw("patch")
	if !ok || jsonKind(raw) != "array" {
		return nil, invalid("argument 'patch' must be an array of operations")
	}
	var operations []json.RawMessage
	if err := json.Unmarshal(raw, &operations); err != nil {
		return nil, invalid("argument 'patch' must be an array of operations")
	}
	patch := lws.JSONPatch{}
	for _, opRaw := range operations {
		op, ok := objectOf(opRaw)
		if !ok {
			return nil, invalid("a patch operation must be an object with an op")
		}
		name, err := op.str("op")
		if err != nil {
			return nil, invalid("a patch operation must be an object with an op")
		}
		member := func(m string) (string, error) {
			s, err := op.str(m)
			if err != nil {
				return "", invalid("patch operation '%s' needs a string '%s'", name, m)
			}
			return s, nil
		}
		value := func() (json.RawMessage, error) {
			v, ok := op["value"] // null is a value
			if !ok {
				return nil, invalid("patch operation '%s' needs a 'value'", name)
			}
			return v, nil
		}
		path, err := member("path")
		if err != nil {
			return nil, err
		}
		switch name {
		case "add", "replace", "test":
			v, err := value()
			if err != nil {
				return nil, err
			}
			switch name {
			case "add":
				patch = patch.Add(path, v)
			case "replace":
				patch = patch.Replace(path, v)
			default:
				patch = patch.Test(path, v)
			}
		case "remove":
			patch = patch.Remove(path)
		case "move", "copy":
			from, err := member("from")
			if err != nil {
				return nil, err
			}
			if name == "move" {
				patch = patch.Move(from, path)
			} else {
				patch = patch.Copy(from, path)
			}
		default:
			return nil, invalid("unknown patch operation '%s'", name)
		}
	}
	return patch, nil
}

func (a *adapter) patch(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	patch, err := patchOf(x)
	if err != nil {
		return nil, err
	}
	options, err := conditions(x, false)
	if err != nil {
		return nil, err
	}
	r, err := a.client.Patch(ctx, u, patch, options...)
	if err != nil {
		return nil, err
	}
	return updateResult(r), nil
}

func (a *adapter) delete(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	options, err := conditions(x, false)
	if err != nil {
		return nil, err
	}
	recursive, _, err := x.optBool("recursive")
	if err != nil {
		return nil, err
	}
	if recursive {
		options = append(options, lws.Recursive())
	}
	if err := a.client.Delete(ctx, u, options...); err != nil {
		return nil, err
	}
	return struct{}{}, nil
}

// ---------------------------------------------------------------------------------------------
// Linksets

func (a *adapter) linksetURL(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	l, err := a.client.LinksetURL(ctx, u)
	if err != nil {
		return nil, err
	}
	return map[string]string{"linkset": l}, nil
}

type linksetDocumentJSON struct {
	URL         string          `json:"url"`
	ETag        string          `json:"etag,omitempty"`
	Linkset     json.RawMessage `json:"linkset"`
	Allow       []string        `json:"allow"`
	AcceptPatch []string        `json:"acceptPatch"`
}

func (a *adapter) readLinkset(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	doc, err := a.client.ReadLinkset(ctx, u)
	if err != nil {
		return nil, err
	}
	linkset, err := json.Marshal(doc.Linkset)
	if err != nil {
		return nil, err
	}
	return linksetDocumentJSON{URL: doc.URL, ETag: doc.ETag, Linkset: linkset, Allow: list(doc.Allow), AcceptPatch: list(doc.AcceptPatch)}, nil
}

func (a *adapter) updateLinkset(x args) (any, error) {
	linksetURL, err := x.url("linksetUrl")
	if err != nil {
		return nil, err
	}
	raw, err := x.object("linkset")
	if err != nil {
		return nil, err
	}
	linkset, err := lws.ParseLinkset(raw)
	if err != nil {
		return nil, invalid("argument 'linkset' is not a linkset document: %v", err)
	}
	options, err := conditions(x, false)
	if err != nil {
		return nil, err
	}
	r, err := a.client.UpdateLinkset(ctx, linksetURL, linkset, options...)
	if err != nil {
		return nil, err
	}
	return updateResult(r), nil
}

func (a *adapter) patchLinkset(x args) (any, error) {
	linksetURL, err := x.url("linksetUrl")
	if err != nil {
		return nil, err
	}
	patch, err := patchOf(x)
	if err != nil {
		return nil, err
	}
	options, err := conditions(x, false)
	if err != nil {
		return nil, err
	}
	r, err := a.client.PatchLinkset(ctx, linksetURL, patch, options...)
	if err != nil {
		return nil, err
	}
	return updateResult(r), nil
}

// ---------------------------------------------------------------------------------------------
// Notifications

func (a *adapter) subscribe(x args) (any, error) {
	serviceURL, err := x.url("serviceUrl")
	if err != nil {
		return nil, err
	}
	topics, err := x.strings("topics")
	if err != nil {
		return nil, err
	}
	inbox, err := x.str("inbox")
	if err != nil {
		return nil, err
	}
	request := lws.WebhookSubscriptionRequest{Topics: topics, Inbox: inbox}
	expires, ok, err := x.optString("expires")
	if err != nil {
		return nil, err
	}
	if ok {
		t, err := time.Parse(time.RFC3339, expires)
		if err != nil {
			return nil, invalid("argument 'expires' must be an RFC 3339 date-time: %v", err)
		}
		request.Expires = t
	}
	s, err := a.client.Subscribe(ctx, serviceURL, request)
	if err != nil {
		return nil, err
	}
	return subscriptionResult(s), nil
}

func (a *adapter) listSubscriptions(x args) (any, error) {
	serviceURL, err := x.url("serviceUrl")
	if err != nil {
		return nil, err
	}
	limit, err := x.limit()
	if err != nil {
		return nil, err
	}
	return listResult(a.client.ListSubscriptions(ctx, serviceURL), limit)
}

func (a *adapter) getSubscription(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	s, err := a.client.GetSubscription(ctx, u)
	if err != nil {
		return nil, err
	}
	return subscriptionResult(s), nil
}

func (a *adapter) unsubscribe(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	if err := a.client.Unsubscribe(ctx, u); err != nil {
		return nil, err
	}
	return struct{}{}, nil
}

type activityJSON struct {
	ID          string   `json:"id,omitempty"`
	Types       []string `json:"types"`
	Object      string   `json:"object"`
	ObjectTypes []string `json:"objectTypes"`
}

type verifiedJSON struct {
	Storage    string          `json:"storage"`
	KeyID      string          `json:"keyid"`
	Activities []activityJSON  `json:"activities"`
	Raw        json.RawMessage `json:"raw,omitempty"`
}

func (a *adapter) verifyNotification(x args) (any, error) {
	rawHeaders, err := x.object("headers")
	if err != nil {
		return nil, err
	}
	members, _ := orderedObject(rawHeaders)
	header := http.Header{}
	for _, m := range members {
		if len(m.value) == 0 {
			continue
		}
		switch jsonKind(m.value) {
		case "null":
		case "string":
			var v string
			_ = json.Unmarshal(m.value, &v)
			header.Add(m.name, v)
		case "array":
			var vs []string
			if err := json.Unmarshal(m.value, &vs); err != nil {
				return nil, invalid("header '%s' must be a list of strings", m.name)
			}
			for _, v := range vs {
				header.Add(m.name, v)
			}
		default:
			return nil, invalid("header '%s' must be a list of strings", m.name)
		}
	}
	method, err := x.str("method")
	if err != nil {
		return nil, err
	}
	inbox, err := x.str("url")
	if err != nil {
		return nil, err
	}
	encoded, err := x.str("bodyBase64")
	if err != nil {
		return nil, err
	}
	body, err := decodeBase64(encoded)
	if err != nil {
		return nil, invalid("argument 'bodyBase64' is not valid base64: %v", err)
	}
	trusted, _, err := x.optStrings("trustedStorages")
	if err != nil {
		return nil, err
	}
	verifier := lws.NewWebhookVerifier(&lws.WebhookVerifierOptions{Client: a.client, TrustedStorages: trusted})
	v, err := verifier.Verify(ctx, method, inbox, header, body)
	if err != nil {
		return nil, err
	}
	activities := []activityJSON{}
	for _, act := range v.Notification.Activities {
		activities = append(activities, activityJSON{
			ID: act.ID, Types: list([]string(act.Types)), Object: act.Object.ID, ObjectTypes: list([]string(act.Object.Types)),
		})
	}
	return verifiedJSON{Storage: v.Storage, KeyID: v.KeyID, Activities: activities, Raw: v.Notification.Raw}, nil
}

// ---------------------------------------------------------------------------------------------
// Access requests and grants

type locationJSON struct {
	Location string `json:"location"`
}

type documentJSON struct {
	Document json.RawMessage `json:"document"`
}

func (a *adapter) requestAccess(x args) (any, error) {
	serviceURL, err := x.url("serviceUrl")
	if err != nil {
		return nil, err
	}
	raw, err := x.object("request")
	if err != nil {
		return nil, err
	}
	var request lws.AccessRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		return nil, invalid("argument 'request' is not an access request: %v", err)
	}
	if err := request.Validate(); err != nil {
		return nil, invalid("argument 'request': %v", err)
	}
	location, err := a.client.RequestAccess(ctx, serviceURL, &request)
	if err != nil {
		return nil, err
	}
	return locationJSON{location}, nil
}

func (a *adapter) getAccessRequest(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	r, err := a.client.GetAccessRequest(ctx, u)
	if err != nil {
		return nil, err
	}
	return documentJSON{r.Raw}, nil
}

func (a *adapter) listAccessRequests(x args) (any, error) {
	serviceURL, err := x.url("serviceUrl")
	if err != nil {
		return nil, err
	}
	limit, err := x.limit()
	if err != nil {
		return nil, err
	}
	return listResult(a.client.ListAccessRequests(ctx, serviceURL), limit)
}

func (a *adapter) cancelAccessRequest(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	if err := a.client.CancelAccessRequest(ctx, u); err != nil {
		return nil, err
	}
	return struct{}{}, nil
}

func (a *adapter) grantAccess(x args) (any, error) {
	serviceURL, err := x.url("serviceUrl")
	if err != nil {
		return nil, err
	}
	raw, err := x.object("grant")
	if err != nil {
		return nil, err
	}
	var grant lws.AccessGrant
	if err := json.Unmarshal(raw, &grant); err != nil {
		return nil, invalid("argument 'grant' is not an access grant: %v", err)
	}
	if err := grant.Validate(); err != nil {
		return nil, invalid("argument 'grant': %v", err)
	}
	location, err := a.client.GrantAccess(ctx, serviceURL, &grant)
	if err != nil {
		return nil, err
	}
	return locationJSON{location}, nil
}

func (a *adapter) getAccessGrant(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	g, err := a.client.GetAccessGrant(ctx, u)
	if err != nil {
		return nil, err
	}
	return documentJSON{g.Raw}, nil
}

func (a *adapter) listAccessGrants(x args) (any, error) {
	serviceURL, err := x.url("serviceUrl")
	if err != nil {
		return nil, err
	}
	limit, err := x.limit()
	if err != nil {
		return nil, err
	}
	return listResult(a.client.ListAccessGrants(ctx, serviceURL), limit)
}

func (a *adapter) revokeAccessGrant(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	if err := a.client.RevokeAccessGrant(ctx, u); err != nil {
		return nil, err
	}
	return struct{}{}, nil
}

// ---------------------------------------------------------------------------------------------
// Type index and type search

// queryOf rebuilds an application/lws-query+json document with the library's TypeQuery builder:
// a string group is allOf(iri) and an array group anyOf(iris...), on the key's relation, in order.
func queryOf(x args) (*lws.TypeQuery, error) {
	raw, err := x.object("query")
	if err != nil {
		return nil, err
	}
	members, ok := orderedObject(raw)
	if !ok {
		return nil, invalid("argument 'query' must be an object")
	}
	q := lws.NewTypeQuery()
	for _, m := range members {
		if len(m.value) == 0 || jsonKind(m.value) != "array" {
			return nil, invalid("query member '%s' must be a list of groups", m.name)
		}
		var groups []json.RawMessage
		if err := json.Unmarshal(m.value, &groups); err != nil {
			return nil, invalid("query member '%s' must be a list of groups", m.name)
		}
		for _, g := range groups {
			var iri string
			var iris []string
			switch {
			case json.Unmarshal(g, &iri) == nil:
				q.RelationAllOf(m.name, iri)
			case json.Unmarshal(g, &iris) == nil && iris != nil:
				q.RelationAnyOf(m.name, iris...)
			default:
				return nil, invalid("a group of query member '%s' must be an IRI or a list of IRIs", m.name)
			}
		}
	}
	// The builder records its errors (a relative IRI, an empty OR group) for MarshalJSON.
	if err := q.Validate(); err != nil {
		return nil, invalid("argument 'query': %v", err)
	}
	return q, nil
}

type typeIndexJSON struct {
	TotalItems *int64   `json:"totalItems,omitempty"`
	Types      []string `json:"types"`
	First      string   `json:"first,omitempty"`
	Next       string   `json:"next,omitempty"`
	Prev       string   `json:"prev,omitempty"`
	Last       string   `json:"last,omitempty"`
}

func (a *adapter) readTypeIndex(x args) (any, error) {
	u, err := x.url("url")
	if err != nil {
		return nil, err
	}
	p, err := a.client.ReadTypeIndex(ctx, u)
	if err != nil {
		return nil, err
	}
	r := typeIndexJSON{Types: list(p.Types), First: p.First, Next: p.Next, Prev: p.Prev, Last: p.Last}
	if p.TotalItems >= 0 {
		n := p.TotalItems
		r.TotalItems = &n
	}
	return r, nil
}

type typesJSON struct {
	Types     []string `json:"types"`
	Truncated bool     `json:"truncated"`
}

func (a *adapter) listTypes(x args) (any, error) {
	serviceURL, err := x.url("serviceUrl")
	if err != nil {
		return nil, err
	}
	limit, err := x.limit()
	if err != nil {
		return nil, err
	}
	types, truncated, err := take(a.client.ListTypes(ctx, serviceURL), limit)
	if err != nil {
		return nil, err
	}
	return typesJSON{Types: types, Truncated: truncated}, nil
}

func (a *adapter) searchTypes(x args) (any, error) {
	serviceURL, err := x.url("serviceUrl")
	if err != nil {
		return nil, err
	}
	q, err := queryOf(x)
	if err != nil {
		return nil, err
	}
	p, err := a.client.SearchTypes(ctx, serviceURL, q)
	if err != nil {
		return nil, err
	}
	return pageResult(p), nil
}

func (a *adapter) searchAll(x args) (any, error) {
	serviceURL, err := x.url("serviceUrl")
	if err != nil {
		return nil, err
	}
	q, err := queryOf(x)
	if err != nil {
		return nil, err
	}
	limit, err := x.limit()
	if err != nil {
		return nil, err
	}
	return listResult(a.client.SearchAll(ctx, serviceURL, q), limit)
}

func (a *adapter) acceptedQueryFormats(x args) (any, error) {
	serviceURL, err := x.url("serviceUrl")
	if err != nil {
		return nil, err
	}
	formats, err := a.client.AcceptedQueryFormats(ctx, serviceURL)
	if err != nil {
		return nil, err
	}
	return map[string][]string{"formats": list(formats)}, nil
}

func (a *adapter) shutdown(args) (any, error) {
	return struct{}{}, nil
}
