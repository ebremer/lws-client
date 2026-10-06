// SPDX-License-Identifier: MIT

package lws

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fixture loads a shared conformance fixture into v.
func fixture(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "conformance", "fixtures", filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("decoding fixture %s: %v", name, err)
	}
}

// jsonEqual compares two values as JSON documents.
func jsonEqual(t *testing.T, got, want any) bool {
	t.Helper()
	norm := func(v any) any {
		var b []byte
		switch x := v.(type) {
		case []byte:
			b = x
		case json.RawMessage:
			b = x
		default:
			var err error
			if b, err = json.Marshal(v); err != nil {
				t.Fatalf("marshal: %v", err)
			}
		}
		var out any
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		return out
	}
	return reflect.DeepEqual(norm(got), norm(want))
}

func TestFixtureLinkHeaders(t *testing.T) {
	var f struct {
		Cases []struct {
			Name     string
			Base     string
			Headers  []string
			Expected []struct {
				Href   string
				Rel    string
				Params map[string]string
			}
		}
	}
	fixture(t, "link-headers.json", &f)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got := ParseLinkHeader(c.Base, c.Headers...)
			if len(got) != len(c.Expected) {
				t.Fatalf("got %d links %+v, want %d", len(got), got, len(c.Expected))
			}
			for i, w := range c.Expected {
				g := got[i]
				if g.Href != w.Href || g.Rel != w.Rel {
					t.Errorf("link %d = %s %s, want %s %s", i, g.Href, g.Rel, w.Href, w.Rel)
				}
				if len(g.Params) != len(w.Params) {
					t.Errorf("link %d params = %v, want %v", i, g.Params, w.Params)
				}
				for k, v := range w.Params {
					if g.Params[k] != v {
						t.Errorf("link %d param %s = %q, want %q", i, k, g.Params[k], v)
					}
				}
			}
			// Serialising and re-parsing must preserve every link.
			if len(got) > 0 {
				again := ParseLinkHeader(c.Base, FormatLinks(got))
				if len(again) != len(got) {
					t.Fatalf("round trip lost links: %v", again)
				}
				for i := range got {
					if again[i].Href != got[i].Href || again[i].Rel != got[i].Rel || !reflect.DeepEqual(again[i].Params, got[i].Params) {
						t.Errorf("round trip %d: %+v != %+v", i, again[i], got[i])
					}
				}
			}
		})
	}
}

func TestFixtureWWWAuthenticate(t *testing.T) {
	var f struct {
		Cases []struct {
			Name     string
			Headers  []string
			Expected []struct {
				Scheme  string
				Token68 string
				Params  map[string]string
			}
		}
	}
	fixture(t, "www-authenticate.json", &f)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got := ParseChallenges(c.Headers...)
			if len(got) != len(c.Expected) {
				t.Fatalf("got %d challenges %+v, want %d", len(got), got, len(c.Expected))
			}
			for i, w := range c.Expected {
				g := got[i]
				if !strings.EqualFold(g.Scheme, w.Scheme) || g.Token68 != w.Token68 {
					t.Errorf("challenge %d = %q/%q, want %q/%q", i, g.Scheme, g.Token68, w.Scheme, w.Token68)
				}
				if len(g.Params) != len(w.Params) {
					t.Errorf("challenge %d params = %v, want %v", i, g.Params, w.Params)
				}
				for k, v := range w.Params {
					if g.Params[k] != v {
						t.Errorf("challenge %d param %s = %q, want %q", i, k, g.Params[k], v)
					}
				}
			}
		})
	}
}

func sfBareJSON(v any) map[string]any {
	switch x := v.(type) {
	case string:
		return map[string]any{"string": x}
	case SFToken:
		return map[string]any{"token": string(x)}
	case int64:
		return map[string]any{"integer": x}
	case float64:
		return map[string]any{"decimal": x}
	case bool:
		return map[string]any{"boolean": x}
	case []byte:
		return map[string]any{"bytes": base64.StdEncoding.EncodeToString(x)}
	}
	return nil
}

func sfParamsJSON(p SFParams) map[string]any {
	m := map[string]any{}
	for _, x := range p {
		m[x.Name] = sfBareJSON(x.Value)
	}
	return m
}

func sfMemberJSON(m SFMember) map[string]any {
	if m.List != nil {
		items := []any{}
		for _, it := range m.List.Items {
			items = append(items, map[string]any{"item": sfBareJSON(it.Value), "params": sfParamsJSON(it.Params)})
		}
		return map[string]any{"innerList": items, "params": sfParamsJSON(m.List.Params)}
	}
	return map[string]any{"item": sfBareJSON(m.Item.Value), "params": sfParamsJSON(m.Item.Params)}
}

func TestFixtureStructuredFields(t *testing.T) {
	var f struct {
		Cases []struct {
			Name       string
			Input      string
			Error      bool
			Expected   map[string]json.RawMessage
			Serialized map[string]string
		}
	}
	fixture(t, "structured-fields.json", &f)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			d, err := ParseSFDictionary(c.Input)
			if c.Error {
				if err == nil {
					t.Fatalf("expected error, got %+v", d)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(d) != len(c.Expected) {
				t.Fatalf("got %d members, want %d", len(d), len(c.Expected))
			}
			for name, want := range c.Expected {
				m, ok := d.Get(name)
				if !ok {
					t.Fatalf("missing member %s", name)
				}
				if !jsonEqual(t, sfMemberJSON(m), want) {
					got, _ := json.Marshal(sfMemberJSON(m))
					t.Errorf("member %s = %s, want %s", name, got, want)
				}
			}
			for name, want := range c.Serialized {
				m, _ := d.Get(name)
				if m.List == nil || m.List.String() != want {
					t.Errorf("serialized %s = %v, want %s", name, m.List, want)
				}
			}
		})
	}
}

func TestFixtureJSONPatch(t *testing.T) {
	var f struct {
		PointerEscapes []struct{ Segment, Escaped string }
		Pointers       []struct {
			Segments []string
			Pointer  string
		}
		Patch struct {
			Operations json.RawMessage
		}
	}
	fixture(t, "json-patch.json", &f)
	for _, e := range f.PointerEscapes {
		if got := EscapePointerSegment(e.Segment); got != e.Escaped {
			t.Errorf("escape(%q) = %q, want %q", e.Segment, got, e.Escaped)
		}
		if got := UnescapePointerSegment(e.Escaped); got != e.Segment {
			t.Errorf("unescape(%q) = %q, want %q", e.Escaped, got, e.Segment)
		}
	}
	for _, p := range f.Pointers {
		if got := JSONPointer(p.Segments...); got != p.Pointer {
			t.Errorf("pointer(%v) = %q, want %q", p.Segments, got, p.Pointer)
		}
	}
	patch := JSONPatch{}.
		Add("/linkset/0/license", []map[string]string{{"href": "https://creativecommons.org/licenses/by/4.0/"}}).
		Remove("/linkset/0/describedby/0").
		Replace("/name", "Alice").
		Move("/a", "/b").
		Copy("/b", "/c").
		Test("/age", 30)
	if !jsonEqual(t, patch, f.Patch.Operations) {
		got, _ := json.Marshal(patch)
		t.Errorf("patch = %s\nwant %s", got, f.Patch.Operations)
	}
	var back JSONPatch
	if err := json.Unmarshal(f.Patch.Operations, &back); err != nil || len(back) != 6 || back[3].From != "/a" {
		t.Errorf("decode patch: %v %+v", err, back)
	}
	// "value": null must be kept for add.
	nullPatch, _ := json.Marshal(JSONPatch{}.Add("/x", nil))
	if string(nullPatch) != `[{"op":"add","path":"/x","value":null}]` {
		t.Errorf("null value patch = %s", nullPatch)
	}
}

func TestFixtureTypeQueries(t *testing.T) {
	var f struct {
		Cases []struct {
			Name  string
			Steps []struct {
				Key   string
				AllOf []string
				AnyOf *[]string
			}
			JSON  json.RawMessage
			Error bool
		}
	}
	fixture(t, "type-queries.json", &f)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			q := NewTypeQuery()
			for _, s := range c.Steps {
				if s.AnyOf != nil {
					q.RelationAnyOf(s.Key, *s.AnyOf...)
				} else {
					q.RelationAllOf(s.Key, s.AllOf...)
				}
			}
			data, err := q.MarshalJSON()
			if c.Error {
				if err == nil || q.Validate() == nil {
					t.Fatalf("expected error, got %s", data)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !jsonEqual(t, data, c.JSON) {
				t.Errorf("got %s, want %s", data, c.JSON)
			}
		})
	}
}

func TestFixtureDIDKey(t *testing.T) {
	var f struct {
		Vectors []struct {
			Name      string
			PublicJWK JWK `json:"publicJwk"`
			DID       string
			Kid       string
		}
	}
	fixture(t, "did-key.json", &f)
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			pub, err := v.PublicJWK.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			did, err := DIDKeyFromPublicKey(pub)
			if err != nil {
				t.Fatal(err)
			}
			if did != v.DID {
				t.Errorf("did = %s, want %s", did, v.DID)
			}
			if kid := DIDKeyVerificationMethod(did); kid != v.Kid {
				t.Errorf("kid = %s, want %s", kid, v.Kid)
			}
			back, err := PublicKeyFromDIDKey(v.Kid)
			if err != nil {
				t.Fatal(err)
			}
			j, _ := JWKFromPublicKey(back)
			if j.X != v.PublicJWK.X || j.Y != v.PublicJWK.Y || j.Crv != v.PublicJWK.Crv {
				t.Errorf("decoded key %+v, want %+v", j, v.PublicJWK)
			}
		})
	}
}

func TestFixtureJWT(t *testing.T) {
	var f struct {
		Vectors []struct {
			Name      string
			PublicJWK JWK `json:"publicJwk"`
			JWT       string
			Claims    map[string]any
		}
	}
	fixture(t, "jwt.json", &f)
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			pub, err := v.PublicJWK.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			_, claims, err := VerifyJWT(v.JWT, pub)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(claims, v.Claims) {
				t.Errorf("claims = %v, want %v", claims, v.Claims)
			}
			// The subject is a did:key whose key must be the signing key.
			didPub, err := PublicKeyFromDIDKey(claims["sub"].(string))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := VerifyJWT(v.JWT, didPub); err != nil {
				t.Errorf("verify with did:key key: %v", err)
			}
			tampered := v.JWT[:len(v.JWT)-4] + "AAAA"
			if _, _, err := VerifyJWT(tampered, pub); err == nil {
				t.Error("tampered JWT verified")
			}
		})
	}
}

func TestFixtureKeys(t *testing.T) {
	for _, name := range []string{"p256", "ed25519", "p256-unlisted"} {
		var f struct {
			PrivateJWK JWK `json:"privateJwk"`
			PublicJWK  JWK `json:"publicJwk"`
		}
		fixture(t, "keys/"+name+".json", &f)
		priv, err := f.PrivateJWK.PrivateKey()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		jwk, err := JWKFromPrivateKey(priv)
		if err != nil || jwk.D != f.PrivateJWK.D || jwk.X != f.PrivateJWK.X {
			t.Errorf("%s: private JWK round trip %+v %v", name, jwk, err)
		}
		token, err := SignJWT(map[string]any{"typ": "JWT"}, map[string]any{"sub": "x"}, priv)
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := f.PublicJWK.PublicKey()
		if _, _, err := VerifyJWT(token, pub); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A private key that does not match its public half is rejected.
	var a, b struct {
		PrivateJWK JWK `json:"privateJwk"`
	}
	fixture(t, "keys/p256.json", &a)
	fixture(t, "keys/p256-unlisted.json", &b)
	mixed := a.PrivateJWK
	mixed.D = b.PrivateJWK.D
	if _, err := mixed.PrivateKey(); err == nil {
		t.Error("mismatched private key accepted")
	}
}

func loadWebhookDescription(t *testing.T) *StorageDescription {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "conformance", "fixtures", "webhook", "storage-description.json"))
	if err != nil {
		t.Fatal(err)
	}
	sd, err := ParseStorageDescription(data, "")
	if err != nil {
		t.Fatal(err)
	}
	return sd
}

func TestFixtureWebhooks(t *testing.T) {
	var index struct{ Vectors []string }
	fixture(t, "webhook/index.json", &index)
	if len(index.Vectors) != 13 {
		t.Fatalf("expected 13 webhook vectors, found %d", len(index.Vectors))
	}
	sd := loadWebhookDescription(t)
	for _, name := range index.Vectors {
		var v struct {
			Name          string
			Method        string
			URL           string
			Now           int64
			Headers       map[string]string
			Body          string
			SignatureBase string
			Expected      struct {
				Valid        bool
				Keyid        string
				Reason       string
				Notification struct {
					Storage    string
					Activities []struct {
						Types    []string
						ObjectID string
						Target   string
					}
				}
			}
		}
		fixture(t, "webhook/"+name, &v)
		t.Run(v.Name, func(t *testing.T) {
			fetches := 0
			verifier := NewWebhookVerifier(&WebhookVerifierOptions{
				Clock: func() time.Time { return time.Unix(v.Now, 0) },
				FetchStorageDescription: func(_ context.Context, id string) (*StorageDescription, error) {
					fetches++
					if id != "https://storage.example/" {
						return nil, errors.New("unexpected storage " + id)
					}
					return sd, nil
				},
			})
			header := http.Header{}
			for k, val := range v.Headers {
				header.Set(k, val)
			}
			got, err := verifier.Verify(context.Background(), v.Method, v.URL, header, []byte(v.Body))
			if !v.Expected.Valid {
				var se *SignatureVerificationError
				if err == nil || !errors.As(err, &se) {
					t.Fatalf("expected SignatureVerificationError (%s), got %v", v.Expected.Reason, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("verification failed: %v", err)
			}
			if got.KeyID != v.Expected.Keyid || got.Storage != "https://storage.example/" {
				t.Errorf("keyid %s storage %s", got.KeyID, got.Storage)
			}
			n := got.Notification
			if n.Storage != v.Expected.Notification.Storage || len(n.Activities) != len(v.Expected.Notification.Activities) {
				t.Fatalf("notification %+v", n)
			}
			for i, a := range v.Expected.Notification.Activities {
				g := n.Activities[i]
				if !reflect.DeepEqual([]string(g.Types), a.Types) || g.Object.ID != a.ObjectID || g.Target != a.Target {
					t.Errorf("activity %d = %+v, want %+v", i, g, a)
				}
			}
			// The signature base must match the fixture exactly.
			inputs, _ := ParseSFDictionary(v.Headers["signature-input"])
			m := inputs[0]
			comps := []string{}
			for _, it := range m.List.Items {
				comps = append(comps, it.Value.(string))
			}
			target, _ := url.Parse(v.URL)
			base, err := signatureBase(comps, m.List, v.Method, target, header)
			if err != nil || base != v.SignatureBase {
				t.Errorf("signature base mismatch:\n%s\nwant\n%s", base, v.SignatureBase)
			}
			// A second verification uses the cached description.
			if _, err := verifier.Verify(context.Background(), v.Method, v.URL, header, []byte(v.Body)); err != nil || fetches != 1 {
				t.Errorf("cached verification: %v (fetches %d)", err, fetches)
			}
		})
	}
}

func TestWebhookTrustedStorages(t *testing.T) {
	var v struct {
		Method, URL, Body string
		Now               int64
		Headers           map[string]string
	}
	fixture(t, "webhook/p256-valid.json", &v)
	sd := loadWebhookDescription(t)
	header := http.Header{}
	for k, val := range v.Headers {
		header.Set(k, val)
	}
	for _, tc := range []struct {
		trusted []string
		ok      bool
	}{{nil, true}, {[]string{"https://storage.example/"}, true}, {[]string{"https://other.example/"}, false}} {
		verifier := NewWebhookVerifier(&WebhookVerifierOptions{
			TrustedStorages: tc.trusted,
			Clock:           func() time.Time { return time.Unix(v.Now, 0) },
			FetchStorageDescription: func(context.Context, string) (*StorageDescription, error) {
				return sd, nil
			},
		})
		_, err := verifier.Verify(context.Background(), v.Method, v.URL, header, []byte(v.Body))
		if (err == nil) != tc.ok {
			t.Errorf("trusted=%v: err=%v", tc.trusted, err)
		}
	}
}

// fixtureTransport serves canned responses keyed by URL and records requests.
type fixtureTransport struct {
	responses map[string]cannedResponse
	requests  []*http.Request
	bodies    [][]byte
}

type cannedResponse struct {
	status int
	header http.Header
	body   []byte
}

func (f *fixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	f.requests = append(f.requests, req)
	f.bodies = append(f.bodies, body)
	r, ok := f.responses[req.URL.String()]
	if !ok {
		return &http.Response{StatusCode: 404, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	}
	return &http.Response{StatusCode: r.status, Header: r.header.Clone(), Body: io.NopCloser(bytes.NewReader(r.body)), Request: req}, nil
}

// canned converts a fixture's {status, headers, body} into a response.
func canned(t *testing.T, status int, headers map[string]json.RawMessage, body json.RawMessage) cannedResponse {
	t.Helper()
	h := http.Header{}
	for k, raw := range headers {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			h.Add(k, s)
			continue
		}
		var list []string
		if err := json.Unmarshal(raw, &list); err != nil {
			t.Fatalf("header %s: %v", k, err)
		}
		for _, v := range list {
			h.Add(k, v)
		}
	}
	if status == 0 {
		status = 200
	}
	return cannedResponse{status: status, header: h, body: body}
}

func fixtureClient(ft *fixtureTransport) *Client {
	return NewClient(WithHTTPClient(&http.Client{Transport: ft}))
}

type responseFixture struct {
	URL      string
	Status   int
	Headers  map[string]json.RawMessage
	Body     json.RawMessage
	Expected json.RawMessage
}

func TestFixtureStorageDescription(t *testing.T) {
	var f struct {
		responseFixture
		Invalid struct {
			NotStorage json.RawMessage
			NoRoot     json.RawMessage
		}
	}
	fixture(t, "responses/storage-description.json", &f)
	var want struct {
		ID                            string
		Types                         []string
		StorageRoot                   string
		NotificationService           string
		NotificationSubscriptionTypes []string
		TypeIndexService              string
		TypeSearchService             string
		AccessRequestService          string
		AccessGrantService            string
		ServiceCount                  int
		CapabilityTypes               []string
		CustomService                 struct{ Type, ID, ServiceEndpoint string }
	}
	_ = json.Unmarshal(f.Expected, &want)
	ft := &fixtureTransport{responses: map[string]cannedResponse{f.URL: canned(t, f.Status, f.Headers, f.Body)}}
	sd, err := fixtureClient(ft).GetStorageDescription(context.Background(), f.URL)
	if err != nil {
		t.Fatal(err)
	}
	if accept := ft.requests[0].Header.Get("Accept"); !strings.HasPrefix(accept, MediaLWSCID) {
		t.Errorf("Accept = %q", accept)
	}
	root, err := sd.StorageRoot()
	if err != nil || root != want.StorageRoot || sd.ID != want.ID || !reflect.DeepEqual([]string(sd.Types), want.Types) {
		t.Errorf("storage %s root %s %v", sd.ID, root, err)
	}
	svc := func(s Service, ok bool) string { return s.ServiceEndpoint }
	if svc(sd.NotificationService()) != want.NotificationService ||
		svc(sd.TypeIndexService()) != want.TypeIndexService ||
		svc(sd.TypeSearchService()) != want.TypeSearchService ||
		svc(sd.AccessRequestService()) != want.AccessRequestService ||
		svc(sd.AccessGrantService()) != want.AccessGrantService {
		t.Errorf("service endpoints wrong: %+v", sd.Services)
	}
	ns, _ := sd.NotificationService()
	if !reflect.DeepEqual(ns.SubscriptionTypes(), want.NotificationSubscriptionTypes) {
		t.Errorf("subscription types %v", ns.SubscriptionTypes())
	}
	if len(sd.Services) != want.ServiceCount {
		t.Errorf("services = %d", len(sd.Services))
	}
	var capTypes []string
	for _, c := range sd.Capabilities {
		capTypes = append(capTypes, c.Types...)
	}
	if !reflect.DeepEqual(capTypes, want.CapabilityTypes) {
		t.Errorf("capabilities %v", capTypes)
	}
	cs, ok := sd.Service(want.CustomService.Type)
	if !ok || cs.ID != want.CustomService.ID || cs.ServiceEndpoint != want.CustomService.ServiceEndpoint {
		t.Errorf("custom service %+v", cs)
	}
	var format map[string][]string
	if c, ok := sd.Capability("https://feature.example/PatchSupport"); !ok || c.Property("format", &format) != nil || len(format) != 2 {
		t.Errorf("capability property: %v", format)
	}
	if _, err := ParseStorageDescription(f.Invalid.NotStorage, ""); err == nil {
		t.Error("non-Storage document accepted")
	} else {
		var pe *ProtocolError
		if !errors.As(err, &pe) {
			t.Errorf("want ProtocolError, got %T", err)
		}
	}
	noRoot, err := ParseStorageDescription(f.Invalid.NoRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noRoot.StorageRoot(); err == nil {
		t.Error("missing StorageRoot not reported")
	}
}

func TestFixtureContainerPage(t *testing.T) {
	var f responseFixture
	fixture(t, "responses/container-page.json", &f)
	var want struct {
		ID, Etag, Linkset, Parent, Storage, First, Next, Last string
		Prev                                                  *string
		IsContainer                                           bool
		TotalItems                                            int64
		Items                                                 []struct {
			ID                          string
			IsContainer, IsDataResource bool
			Format                      *string
			Size                        *int64
			Modified                    *string
			ModifiedRaw                 string
			Types                       []string
			HasType                     string
		}
	}
	_ = json.Unmarshal(f.Expected, &want)
	ft := &fixtureTransport{responses: map[string]cannedResponse{f.URL: canned(t, f.Status, f.Headers, f.Body)}}
	page, err := fixtureClient(ft).ReadContainer(context.Background(), f.URL)
	if err != nil {
		t.Fatal(err)
	}
	if ft.requests[0].Header.Get("Accept") != MediaLWSJSON {
		t.Errorf("Accept = %q", ft.requests[0].Header.Get("Accept"))
	}
	if page.ID != want.ID || page.IsContainer() != want.IsContainer || page.TotalItems != want.TotalItems ||
		page.Metadata.ETag != want.Etag || page.Metadata.Linkset != want.Linkset || page.Metadata.Parent != want.Parent ||
		page.Metadata.Storage != want.Storage || page.First != want.First || page.Next != want.Next ||
		page.Last != want.Last || page.Prev != "" {
		t.Errorf("page = %+v", page)
	}
	if len(page.Items) != len(want.Items) {
		t.Fatalf("items = %d", len(page.Items))
	}
	for i, w := range want.Items {
		g := page.Items[i]
		if g.ID != w.ID || g.IsContainer() != w.IsContainer || g.IsDataResource() != w.IsDataResource ||
			!reflect.DeepEqual([]string(g.Types), w.Types) {
			t.Errorf("item %d = %+v, want %+v", i, g, w)
		}
		if (w.Format == nil && g.Format != "") || (w.Format != nil && g.Format != *w.Format) {
			t.Errorf("item %d format %q", i, g.Format)
		}
		if (w.Size == nil && g.Size != -1) || (w.Size != nil && g.Size != *w.Size) {
			t.Errorf("item %d size %d", i, g.Size)
		}
		if w.Modified != nil {
			if g.Modified.UTC().Format(time.RFC3339) != *w.Modified {
				t.Errorf("item %d modified %v", i, g.Modified)
			}
		} else if !g.Modified.IsZero() {
			t.Errorf("item %d modified should be zero, got %v", i, g.Modified)
		}
		if w.ModifiedRaw != "" && g.ModifiedRaw != w.ModifiedRaw {
			t.Errorf("item %d modifiedRaw %q", i, g.ModifiedRaw)
		}
		if w.HasType != "" && !g.HasType(w.HasType) {
			t.Errorf("item %d lacks type %s", i, w.HasType)
		}
	}
}

func TestFixtureLinkset(t *testing.T) {
	var f responseFixture
	fixture(t, "responses/linkset.json", &f)
	var want struct {
		URL, Etag, Anchor   string
		Allow, AcceptPatch  []string
		Contexts, LinkCount int
		Targets             map[string][]string
		AfterAdd            struct {
			Operation      struct{ Anchor, Rel, Href string }
			LicenseTargets []string
		}
	}
	_ = json.Unmarshal(f.Expected, &want)
	ft := &fixtureTransport{responses: map[string]cannedResponse{f.URL: canned(t, f.Status, f.Headers, f.Body)}}
	doc, err := fixtureClient(ft).ReadLinksetAt(context.Background(), f.URL)
	if err != nil {
		t.Fatal(err)
	}
	if doc.URL != want.URL || doc.ETag != want.Etag || !reflect.DeepEqual(doc.Allow, want.Allow) ||
		!reflect.DeepEqual(doc.AcceptPatch, want.AcceptPatch) {
		t.Errorf("doc = %+v", doc)
	}
	ls := doc.Linkset
	if len(ls.Contexts) != want.Contexts || ls.Contexts[0].Anchor != want.Anchor || len(ls.Links()) != want.LinkCount {
		t.Errorf("linkset = %+v", ls)
	}
	for rel, hrefs := range want.Targets {
		var got []string
		for _, tg := range ls.Targets(rel) {
			got = append(got, tg.Href)
		}
		if !reflect.DeepEqual(got, hrefs) {
			t.Errorf("targets(%s) = %v, want %v", rel, got, hrefs)
		}
	}
	if !jsonEqual(t, ls, f.Body) {
		out, _ := json.Marshal(ls)
		t.Errorf("round trip = %s", out)
	}
	if ls.Targets("describedby")[0].Attr("type") != "application/schema+json" {
		t.Error("target attribute lost")
	}
	op := want.AfterAdd.Operation
	ls.Add(op.Anchor, op.Rel, op.Href, nil)
	var got []string
	for _, tg := range ls.TargetsFor(op.Anchor, op.Rel) {
		got = append(got, tg.Href)
	}
	if !reflect.DeepEqual(got, want.AfterAdd.LicenseTargets) {
		t.Errorf("after add = %v", got)
	}
	if !ls.Remove(op.Anchor, op.Rel, "") || len(ls.Targets(op.Rel)) != 0 {
		t.Error("remove failed")
	}
}

func TestFixtureNotification(t *testing.T) {
	var f struct {
		Single, Batch, Invalid        json.RawMessage
		SingleExpected, BatchExpected json.RawMessage
	}
	fixture(t, "responses/notification.json", &f)
	type act struct {
		ID, ObjectID, Target, Origin, Actor, Published string
		Types, ObjectTypes                             []string
		IsCreate, IsUpdate, IsDelete                   bool
	}
	check := func(data, exp json.RawMessage) {
		var want struct {
			Storage    string
			Activities []act
		}
		_ = json.Unmarshal(exp, &want)
		n, err := ParseNotification(data)
		if err != nil {
			t.Fatal(err)
		}
		if n.Storage != want.Storage || len(n.Activities) != len(want.Activities) {
			t.Fatalf("notification = %+v", n)
		}
		for i, w := range want.Activities {
			g := n.Activities[i]
			if g.ID != w.ID || g.Object.ID != w.ObjectID || g.Target != w.Target || g.Origin != w.Origin || g.Actor != w.Actor ||
				!reflect.DeepEqual([]string(g.Types), w.Types) {
				t.Errorf("activity %d = %+v, want %+v", i, g, w)
			}
			if w.ObjectTypes != nil && !reflect.DeepEqual([]string(g.Object.Types), w.ObjectTypes) {
				t.Errorf("object types %v", g.Object.Types)
			}
			if w.Published != "" && g.Published.UTC().Format(time.RFC3339) != w.Published {
				t.Errorf("published %v", g.Published)
			}
			if (w.IsCreate && !g.IsCreate()) || (w.IsUpdate && !g.IsUpdate()) || (w.IsDelete && !g.IsDelete()) {
				t.Errorf("activity predicates wrong for %+v", g)
			}
		}
	}
	check(f.Single, f.SingleExpected)
	check(f.Batch, f.BatchExpected)
	if _, err := ParseNotification(f.Invalid); err == nil {
		t.Error("invalid notification accepted")
	}
}

func TestFixtureAccess(t *testing.T) {
	var f struct{ Request, Grant json.RawMessage }
	fixture(t, "responses/access.json", &f)
	var req AccessRequest
	if err := json.Unmarshal(f.Request, &req); err != nil {
		t.Fatal(err)
	}
	if req.Storage != "https://storage.example/" || req.Inbox != "https://id.example/agent/inbox/" ||
		len(req.Access) != 1 || req.Access[0].Assignee != "https://id.example/agent" ||
		len(req.Access[0].Constraints) != 2 || req.Access[0].Target.Values[0] != "https://storage.example/root/projects/" {
		t.Errorf("request = %+v", req)
	}
	if !jsonEqual(t, req, f.Request) {
		out, _ := json.Marshal(req)
		t.Errorf("request round trip = %s", out)
	}
	var grant AccessGrant
	if err := json.Unmarshal(f.Grant, &grant); err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, grant, f.Grant) {
		out, _ := json.Marshal(grant)
		t.Errorf("grant round trip = %s", out)
	}
	if !reflect.DeepEqual(grant.Access[0].Constraints[0].RightOperand, []any{"image/jpeg", "image/png"}) {
		t.Errorf("rightOperand = %#v", grant.Access[0].Constraints[0].RightOperand)
	}
	// Builder expectation.
	built := NewAccessRequest("https://storage.example/",
		NewAccessPolicy("https://id.example/agent", ActionRead, ActionCreate).
			WithTarget("StorageResource", "https://storage.example/root/projects/").
			WithConstraints(PurposeConstraint("https://purpose.example/collaboration"),
				NotAfter(time.Date(2026, 6, 9, 10, 0, 0, 0, time.UTC))))
	built.Inbox = "https://id.example/agent/inbox/"
	if !jsonEqual(t, built, f.Request) {
		out, _ := json.Marshal(built)
		t.Errorf("built request = %s", out)
	}
	// Wrong type is rejected.
	if err := json.Unmarshal(f.Grant, &req); err == nil {
		t.Error("grant decoded as request")
	}
	if err := NewAccessRequest("", NewAccessPolicy("a", ActionRead)).Validate(); err == nil {
		t.Error("missing storage accepted")
	}
	if _, err := json.Marshal(NewAccessGrant("https://s/", NewAccessPolicy("https://a"))); err == nil {
		t.Error("policy without actions accepted")
	}
}

func TestFixtureTypeIndex(t *testing.T) {
	var f struct {
		TypeIndex responseFixture
		Search    responseFixture
	}
	fixture(t, "responses/type-index.json", &f)
	ft := &fixtureTransport{responses: map[string]cannedResponse{
		f.TypeIndex.URL: canned(t, 200, f.TypeIndex.Headers, f.TypeIndex.Body),
		f.Search.URL:    canned(t, 200, f.Search.Headers, f.Search.Body),
	}}
	c := fixtureClient(ft)
	ti, err := c.ReadTypeIndex(context.Background(), f.TypeIndex.URL)
	if err != nil {
		t.Fatal(err)
	}
	var wantTI struct {
		TotalItems int64
		Types      []string
		Next       string
	}
	_ = json.Unmarshal(f.TypeIndex.Expected, &wantTI)
	if ti.TotalItems != wantTI.TotalItems || !reflect.DeepEqual(ti.Types, wantTI.Types) || ti.Next != wantTI.Next {
		t.Errorf("type index = %+v", ti)
	}
	page, err := c.SearchTypes(context.Background(), f.Search.URL, NewTypeQuery().AllOf("https://schema.org/Person"))
	if err != nil {
		t.Fatal(err)
	}
	req := ft.requests[len(ft.requests)-1]
	if req.Method != "QUERY" || req.Header.Get("Content-Type") != MediaLWSQueryJSON || req.Header.Get("Accept") != MediaLWSJSON {
		t.Errorf("search request %s %v", req.Method, req.Header)
	}
	if string(ft.bodies[len(ft.bodies)-1]) != `{"type":["https://schema.org/Person"]}` {
		t.Errorf("search body %s", ft.bodies[len(ft.bodies)-1])
	}
	var wantS struct {
		TotalItems int64
		IDs        []string `json:"ids"`
		Next       string
	}
	_ = json.Unmarshal(f.Search.Expected, &wantS)
	var ids []string
	for _, it := range page.Items {
		ids = append(ids, it.ID)
	}
	if page.TotalItems != wantS.TotalItems || !reflect.DeepEqual(ids, wantS.IDs) || page.Next != wantS.Next {
		t.Errorf("search page = %+v", page)
	}
}

func TestFixtureOAuth(t *testing.T) {
	var f struct {
		Metadata      json.RawMessage
		MetadataURLs  []struct{ Issuer, URL string } `json:"metadataUrls"`
		TokenResponse struct {
			Body              TokenResponse
			ExpectedExpiresIn int64
		}
		TokenResponseNoExpiry struct {
			Body        TokenResponse
			ExpectedExp int64
		}
		ErrorResponse struct {
			Status int
			Body   json.RawMessage
		}
		RealmChecks []struct {
			Realm, URL string
			Contained  bool
		}
	}
	fixture(t, "responses/oauth.json", &f)
	for _, m := range f.MetadataURLs {
		got, err := AuthorizationServerMetadataURL(m.Issuer)
		if err != nil || got != m.URL {
			t.Errorf("metadata URL(%s) = %s %v, want %s", m.Issuer, got, err, m.URL)
		}
	}
	for _, r := range f.RealmChecks {
		if got := RealmContains(r.Realm, r.URL); got != r.Contained {
			t.Errorf("RealmContains(%s, %s) = %v", r.Realm, r.URL, got)
		}
	}
	now := time.Unix(1735686000, 0)
	if exp := tokenExpiry(&f.TokenResponse.Body, now); exp.Sub(now) != time.Duration(f.TokenResponse.ExpectedExpiresIn)*time.Second {
		t.Errorf("expiry = %v", exp)
	}
	if exp := tokenExpiry(&f.TokenResponseNoExpiry.Body, now); exp.Unix() != f.TokenResponseNoExpiry.ExpectedExp {
		t.Errorf("JWT expiry = %v", exp.Unix())
	}

	// Metadata fetch and token errors through a canned transport.
	mdURL := "https://authorization.example/.well-known/lws-configuration"
	ft := &fixtureTransport{responses: map[string]cannedResponse{
		mdURL:                                 {status: 200, header: http.Header{"Content-Type": {"application/json"}}, body: f.Metadata},
		"https://authorization.example/token": {status: f.ErrorResponse.Status, header: http.Header{"Content-Type": {"application/json"}}, body: f.ErrorResponse.Body},
	}}
	hc := &http.Client{Transport: ft}
	md, err := FetchAuthorizationServerMetadata(context.Background(), hc, "https://authorization.example")
	if err != nil || md.TokenEndpoint != "https://authorization.example/token" || len(md.SubjectTokenTypesSupported) != 2 {
		t.Fatalf("metadata = %+v %v", md, err)
	}
	if _, err := FetchAuthorizationServerMetadata(context.Background(), hc, "https://authorization.example/other"); err == nil {
		t.Error("expected failure for unknown issuer")
	}
	_, err = ExchangeToken(context.Background(), hc, md.TokenEndpoint, "https://storage.example/", "tok", TokenTypeJWT)
	var ae *AuthenticationError
	if !errors.As(err, &ae) || ae.Code != "invalid_request" || ae.Description != "resource is not a known storage" || ae.StatusCode != 400 {
		t.Errorf("token error = %#v", err)
	}
}

func TestFixtureProblemDetails(t *testing.T) {
	var f responseFixture
	fixture(t, "responses/problem-details.json", &f)
	var want struct {
		Type, Title, Detail, Instance string
		Extension                     map[string]json.RawMessage
	}
	_ = json.Unmarshal(f.Expected, &want)
	u := "https://storage.example/alice/notes/"
	ft := &fixtureTransport{responses: map[string]cannedResponse{u: canned(t, f.Status, f.Headers, f.Body)}}
	err := fixtureClient(ft).Delete(context.Background(), u)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v", err)
	}
	var he *HTTPError
	if !errors.As(err, &he) || he.Problem == nil {
		t.Fatalf("no problem details: %#v", err)
	}
	p := he.Problem
	if p.Type != want.Type || p.Title != want.Title || p.Detail != want.Detail || p.Instance != want.Instance || p.Status != 409 {
		t.Errorf("problem = %+v", p)
	}
	if string(p.Extensions["itemCount"]) != string(want.Extension["itemCount"]) {
		t.Errorf("extension = %s", p.Extensions["itemCount"])
	}
	if !strings.Contains(err.Error(), "Container not empty") {
		t.Errorf("message = %s", err)
	}
}

func TestFixtureSubscription(t *testing.T) {
	var f struct {
		Input struct {
			Topics         []string
			Inbox, Expires string
		}
		ExpectedRequestBody json.RawMessage
		Response            responseFixture
		Expected            struct{ Type, Subscription, Expires string }
	}
	fixture(t, "responses/subscription.json", &f)
	svc := "https://notification.example/subscriptions"
	ft := &fixtureTransport{responses: map[string]cannedResponse{svc: canned(t, f.Response.Status, f.Response.Headers, f.Response.Body)}}
	exp, _ := time.Parse(time.RFC3339, f.Input.Expires)
	sub, err := fixtureClient(ft).Subscribe(context.Background(), svc, WebhookSubscriptionRequest{Topics: f.Input.Topics, Inbox: f.Input.Inbox, Expires: exp})
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, ft.bodies[0], f.ExpectedRequestBody) {
		t.Errorf("request body = %s", ft.bodies[0])
	}
	if ft.requests[0].Method != http.MethodPost || ft.requests[0].Header.Get("Content-Type") != MediaLWSJSON {
		t.Errorf("request %s %v", ft.requests[0].Method, ft.requests[0].Header)
	}
	if sub.Type != f.Expected.Type || sub.URL != f.Expected.Subscription || sub.ExpiresRaw != f.Expected.Expires || !sub.Expires.Equal(exp) {
		t.Errorf("subscription = %+v", sub)
	}
}
