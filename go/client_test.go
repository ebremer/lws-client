// SPDX-License-Identifier: MIT

package lws

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var ctx = context.Background()

func didKeyAuth(t *testing.T) (*TokenExchangeAuthenticator, *SelfSignedCredentials) {
	t.Helper()
	key, err := GenerateP256Key()
	if err != nil {
		t.Fatal(err)
	}
	creds, err := NewDIDKeyCredentials(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	return NewTokenExchangeAuthenticator(creds, nil), creds
}

func TestDiscoverAndCRUD(t *testing.T) {
	s := newMemServer(t)
	c := NewClient(WithUserAgent("test-agent/1"), WithHeader("X-Default", "d"))

	sd, err := c.DiscoverStorage(ctx, s.URL("/root/"))
	if err != nil {
		t.Fatal(err)
	}
	root, _ := sd.StorageRoot()
	if sd.ID != s.URL("/") || root != s.URL("/root/") {
		t.Fatalf("storage %s root %s", sd.ID, root)
	}
	if ar, _ := sd.AccessRequestService(); ar.ServiceEndpoint != s.URL("/access/requests/") {
		t.Errorf("relative service endpoint not resolved: %s", ar.ServiceEndpoint)
	}
	if h := s.headers[0]; h.Get("User-Agent") != "test-agent/1" || h.Get("X-Default") != "d" {
		t.Errorf("headers = %v", h)
	}

	cont, err := c.CreateContainer(ctx, root, Slug("notes"))
	if err != nil {
		t.Fatal(err)
	}
	if cont.Location != s.URL("/root/notes/") || !cont.Metadata.IsContainer() || cont.Metadata.Parent != root {
		t.Fatalf("container = %+v", cont)
	}
	if ct := s.headers[len(s.headers)-1]; !strings.Contains(strings.Join(ct.Values("Link"), ","), TypeContainer) || ct.Get("Slug") != "notes" {
		t.Errorf("create container headers %v", ct)
	}

	created, err := c.Create(ctx, cont.Location, strings.NewReader("Hello, LWS!"), "text/plain", Slug("héllo 100%.txt"), Header("X-Call", "1"))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.headers[len(s.headers)-1].Get("Slug"); got != "h%C3%A9llo 100%25.txt" {
		t.Errorf("slug header = %q", got)
	}
	if s.headers[len(s.headers)-1].Get("X-Call") != "1" {
		t.Error("per-call header missing")
	}
	h := created.Location
	if !strings.HasPrefix(h, s.URL("/root/notes/")) || created.Metadata.Linkset == "" || !created.Metadata.IsDataResource() {
		t.Fatalf("created = %+v", created)
	}

	res, err := c.Read(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	if res.Text() != "Hello, LWS!" || res.ETag == "" || !res.IsDataResource() || res.Parent != cont.Location ||
		res.Storage != s.URL("/") || res.ContentType != "text/plain" || res.ContentLength != 11 || res.LastModified.IsZero() {
		t.Fatalf("read = %+v", res.ResourceMetadata)
	}
	if !strings.Contains(strings.Join(res.AcceptPatch, ","), MediaJSONPatch) {
		t.Errorf("accept-patch %v", res.AcceptPatch)
	}

	nm, err := c.Read(ctx, h, IfNoneMatch(res.ETag))
	if err != nil || !nm.NotModified || len(nm.Body) != 0 {
		t.Fatalf("conditional read = %+v, %v", nm, err)
	}

	up, err := c.Update(ctx, h, strings.NewReader("Hello again"), "text/plain", IfMatch(res.ETag))
	if err != nil || up.StatusCode != 204 || up.ETag == "" || up.ETag == res.ETag {
		t.Fatalf("update = %+v, %v", up, err)
	}
	_, err = c.Update(ctx, h, strings.NewReader("stale"), "text/plain", IfMatch(res.ETag))
	if !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("stale update err = %v", err)
	}

	meta, err := c.Head(ctx, h)
	if err != nil || meta.ETag != up.ETag {
		t.Fatalf("head = %+v %v", meta, err)
	}

	pj, err := c.CreateJSON(ctx, cont.Location, map[string]any{"name": "Alice", "age": 30}, Slug("profile.json"), Types("https://schema.org/Person"))
	if err != nil {
		t.Fatal(err)
	}
	if !pj.Metadata.Types.Has("https://schema.org/Person") {
		t.Errorf("types = %v", pj.Metadata.Types)
	}
	if _, err := c.Patch(ctx, pj.Location, JSONPatch{}.Replace("/age", 31).Add("/city", "Boston")); err != nil {
		t.Fatal(err)
	}
	if hdr := s.headers[len(s.headers)-1]; hdr.Get("Content-Type") != MediaJSONPatch {
		t.Errorf("patch content type %q", hdr.Get("Content-Type"))
	}
	pr, _ := c.Read(ctx, pj.Location)
	var person map[string]any
	if err := pr.JSON(&person); err != nil || person["age"] != float64(31) || person["city"] != "Boston" {
		t.Errorf("patched = %v %v", person, err)
	}
	if _, err := c.PatchRaw(ctx, pj.Location, strings.NewReader("x"), "application/sparql-update"); !errors.Is(err, ErrUnsupportedMediaType) {
		t.Errorf("unsupported patch err = %v", err)
	} else {
		var he *HTTPError
		errors.As(err, &he)
		if len(he.AcceptPatch()) != 1 {
			t.Errorf("accept-patch on 415 = %v", he.AcceptPatch())
		}
	}

	err = c.Delete(ctx, cont.Location)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("non-recursive delete err = %v", err)
	}
	var he *HTTPError
	if !errors.As(err, &he) || he.Problem == nil || he.Problem.Title != "Container not empty" {
		t.Errorf("problem = %+v", he)
	}
	if err := c.Delete(ctx, cont.Location, Recursive()); err != nil {
		t.Fatal(err)
	}
	if hdr := s.headers[len(s.headers)-1]; hdr.Get("Depth") != "infinity" {
		t.Errorf("Depth = %q", hdr.Get("Depth"))
	}
	if _, err := c.Read(ctx, h); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read after delete err = %v", err)
	}
}

func TestRangeAndStream(t *testing.T) {
	s := newMemServer(t)
	c := NewClient()
	cr, err := c.Create(ctx, s.URL("/root/"), strings.NewReader("0123456789"), "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Read(ctx, cr.Location, ByteRange(2, 5))
	if err != nil || r.StatusCode != 206 || r.Text() != "2345" || r.ContentRange != "bytes 2-5/10" {
		t.Fatalf("range read = %+v %q %v", r.ResourceMetadata, r.Text(), err)
	}
	if got := s.headers[len(s.headers)-1].Get("Range"); got != "bytes=2-5" {
		t.Errorf("Range = %q", got)
	}
	st, err := c.ReadStream(ctx, cr.Location)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(st.Body)
	st.Body.Close()
	if string(b) != "0123456789" {
		t.Errorf("stream = %q", b)
	}
	for _, tc := range []struct {
		opt  CallOption
		want string
	}{{ByteRange(5, -1), "bytes=5-"}, {ByteRange(-3, 0), "bytes=-3"}} {
		o := applyCallOptions([]CallOption{tc.opt})
		if o.rangeHeader != tc.want {
			t.Errorf("range = %q want %q", o.rangeHeader, tc.want)
		}
	}
}

func TestPagination(t *testing.T) {
	s := newMemServer(t)
	c := NewClient()
	for i := 0; i < 12; i++ {
		if _, err := c.Create(ctx, s.URL("/root/"), strings.NewReader("x"), "text/plain", Slug(fmt.Sprintf("item-%02d", i))); err != nil {
			t.Fatal(err)
		}
	}
	page, err := c.ReadContainer(ctx, s.URL("/root/"))
	if err != nil {
		t.Fatal(err)
	}
	if page.TotalItems != 12 || len(page.Items) != 5 || page.Next != s.URL("/root/?page=2") || page.First == "" || page.Last != s.URL("/root/?page=3") {
		t.Fatalf("page = %+v", page)
	}
	if page.Items[0].ID != s.URL("/root/item-00") || page.Items[0].Size != 1 || page.Items[0].Format != "text/plain" || page.Items[0].Modified.IsZero() {
		t.Errorf("item = %+v", page.Items[0])
	}
	var ids []string
	for item, err := range c.ListContainer(ctx, s.URL("/root/")) {
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, item.ID)
	}
	if len(ids) != 12 || ids[11] != s.URL("/root/item-11") {
		t.Fatalf("listed %d: %v", len(ids), ids)
	}
	pages := 0
	for p, err := range c.ListContainerPages(ctx, s.URL("/root/")) {
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if pages == 3 && (p.Next != "" || p.Prev == "") {
			t.Errorf("last page links: %+v", p)
		}
	}
	if pages != 3 {
		t.Errorf("pages = %d", pages)
	}
	// Breaking early stops fetching further pages.
	before := s.count(http.MethodGet, "/root/")
	for range c.ListContainer(ctx, s.URL("/root/")) {
		break
	}
	if got := s.count(http.MethodGet, "/root/") - before; got != 1 {
		t.Errorf("early break fetched %d pages", got)
	}
	// Media type equivalence: application/json is accepted.
	if _, err := c.ReadContainer(ctx, s.URL("/root/"), Accept(MediaJSON)); err != nil {
		t.Errorf("json listing: %v", err)
	}
	// A data resource is not a container.
	if _, err := c.ReadContainer(ctx, s.URL("/root/item-00")); err == nil {
		t.Error("data resource read as container")
	} else {
		var pe *ProtocolError
		if !errors.As(err, &pe) {
			t.Errorf("want ProtocolError, got %v", err)
		}
	}
}

func TestLinksetOperations(t *testing.T) {
	s := newMemServer(t)
	c := NewClient()
	cr, err := c.CreateJSON(ctx, s.URL("/root/"), map[string]int{"a": 1}, Slug("p.json"),
		Links(NewLink("https://example.org/schema", "describedby")))
	if err != nil {
		t.Fatal(err)
	}
	lsURL, err := c.LinksetURL(ctx, cr.Location)
	if err != nil || lsURL != cr.Location+".meta" {
		t.Fatalf("linkset url %s %v", lsURL, err)
	}
	doc, err := c.ReadLinkset(ctx, cr.Location)
	if err != nil {
		t.Fatal(err)
	}
	if doc.URL != lsURL || doc.ETag == "" || len(doc.Linkset.Targets("describedby")) != 1 || !contains(doc.Allow, "PATCH") {
		t.Fatalf("linkset doc = %+v", doc)
	}
	patch := JSONPatch{}.Add(JSONPointer("linkset", "0", "https://example.org/rel/reviewer"), []map[string]string{{"href": "https://id.example/bob"}})
	if _, err := c.PatchLinkset(ctx, doc.URL, patch, IfMatch(doc.ETag)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PatchLinkset(ctx, doc.URL, patch, IfMatch(doc.ETag)); !errors.Is(err, ErrPreconditionFailed) {
		t.Errorf("stale linkset patch err = %v", err)
	}
	doc2, _ := c.ReadLinkset(ctx, cr.Location)
	if tg := doc2.Linkset.Targets("https://example.org/rel/reviewer"); len(tg) != 1 || tg[0].Href != "https://id.example/bob" {
		t.Fatalf("patched linkset = %+v", doc2.Linkset)
	}
	ls := doc2.Linkset
	ls.Remove(ls.Contexts[0].Anchor, "describedby", "")
	ls.Add(ls.Contexts[0].Anchor, "license", "https://creativecommons.org/licenses/by/4.0/", map[string]any{"title": "CC BY"})
	if _, err := c.UpdateLinkset(ctx, doc2.URL, ls, IfMatch(doc2.ETag)); err != nil {
		t.Fatal(err)
	}
	doc3, _ := c.ReadLinkset(ctx, cr.Location)
	if len(doc3.Linkset.Targets("describedby")) != 0 || doc3.Linkset.Targets("license")[0].Attr("title") != "CC BY" {
		t.Errorf("replaced linkset = %+v", doc3.Linkset)
	}
	// Content + links in one update with Prefer: set-linkset.
	if _, err := c.Update(ctx, cr.Location, strings.NewReader(`{"a":2}`), MediaJSON, SetLinkset(),
		Links(NewLink("https://example.org/other", "describedby"))); err != nil {
		t.Fatal(err)
	}
	hdr := s.headers[len(s.headers)-1]
	if hdr.Get("Prefer") != PreferSetLinkset || !strings.Contains(hdr.Get("Link"), "describedby") {
		t.Errorf("update headers = %v", hdr)
	}
	doc4, _ := c.ReadLinkset(ctx, cr.Location)
	if tg := doc4.Linkset.Targets("describedby"); len(tg) != 1 || tg[0].Href != "https://example.org/other" {
		t.Errorf("set-linkset result = %+v", doc4.Linkset)
	}
}

func TestTokenExchangeFlow(t *testing.T) {
	s := newMemServer(t)
	s.requireAuth = true
	auth, creds := didKeyAuth(t)
	c := NewClient(WithAuthenticator(auth))

	sd, err := c.DiscoverStorage(ctx, s.URL("/root/"))
	if err != nil {
		t.Fatal(err)
	}
	if s.challenges != 1 || s.tokenRequests != 1 {
		t.Fatalf("challenges %d token requests %d", s.challenges, s.tokenRequests)
	}
	f := s.lastTokenForm
	if f.Get("grant_type") != GrantTypeTokenExchange || f.Get("resource") != s.URL("/") || f.Get("subject_token_type") != TokenTypeJWT {
		t.Errorf("token form = %v", f)
	}
	hdr, claims, _ := DecodeJWT(f.Get("subject_token"))
	if claims["sub"] != creds.Agent() || hdr["kid"] != creds.KeyID() || hdr["alg"] != "ES256" || hdr["typ"] != "JWT" {
		t.Errorf("credential header %v claims %v", hdr, claims)
	}
	root, _ := sd.StorageRoot()
	// Proactive reuse: no further 401s or token requests.
	for i := 0; i < 3; i++ {
		if _, err := c.ReadContainer(ctx, root); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Create(ctx, root, strings.NewReader("hi"), "text/plain"); err != nil {
		t.Fatal(err)
	}
	if s.challenges != 1 || s.tokenRequests != 1 {
		t.Errorf("after reuse: challenges %d token requests %d", s.challenges, s.tokenRequests)
	}
	// The server forgets its tokens: the client re-exchanges once.
	s.mu.Lock()
	s.tokens = map[string]string{}
	s.mu.Unlock()
	if _, err := c.ReadContainer(ctx, root); err != nil {
		t.Fatal(err)
	}
	if s.challenges != 2 || s.tokenRequests != 2 {
		t.Errorf("after revocation: challenges %d token requests %d", s.challenges, s.tokenRequests)
	}
	// The storage description itself is public; no token is sent to other
	// realms (an unrelated server).
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("token leaked to another origin")
		}
	}))
	defer other.Close()
	if _, err := c.Head(ctx, other.URL+"/x"); err != nil {
		t.Fatal(err)
	}
}

func TestTokenExchangeConcurrent(t *testing.T) {
	s := newMemServer(t)
	s.requireAuth = true
	auth, _ := didKeyAuth(t)
	c := NewClient(WithAuthenticator(auth))
	var wg sync.WaitGroup
	var failures atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Head(ctx, s.URL("/root/")); err != nil {
				failures.Add(1)
			}
		}()
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d requests failed", failures.Load())
	}
	if s.tokenRequests != 1 {
		t.Errorf("token requests = %d, want 1 (single flight)", s.tokenRequests)
	}
}

func TestStreamingBodyPreflight(t *testing.T) {
	s := newMemServer(t)
	s.requireAuth = true
	auth, _ := didKeyAuth(t)
	c := NewClient(WithAuthenticator(auth))
	body := io.MultiReader(strings.NewReader("stream"), strings.NewReader("ed")) // not replayable
	cr, err := c.Create(ctx, s.URL("/root/"), body, "text/plain", Slug("s.txt"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Read(ctx, cr.Location)
	if err != nil || r.Text() != "streamed" {
		t.Fatalf("read = %q %v", r.Text(), err)
	}
	if s.count(http.MethodHead, "/root/") != 2 {
		t.Errorf("expected a HEAD preflight (and its retry), got %d", s.count(http.MethodHead, "/root/"))
	}
}

// challengeServer returns a server that always answers 401 with the given
// WWW-Authenticate header and serves AS metadata md (if not nil).
func challengeServer(t *testing.T, challenge func(base string) string, md func(base string) map[string]any) (*httptest.Server, *int32) {
	var mdRequests int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/lws-configuration" && md != nil {
			atomic.AddInt32(&mdRequests, 1)
			writeJSON(w, 200, MediaJSON, md(srv.URL))
			return
		}
		if r.URL.Path == "/token" {
			writeJSON(w, 200, MediaJSON, map[string]any{"access_token": "t", "token_type": "Bearer"})
			return
		}
		w.Header().Set("WWW-Authenticate", challenge(srv.URL))
		w.WriteHeader(401)
	}))
	t.Cleanup(srv.Close)
	return srv, &mdRequests
}

func TestTokenExchangeRejections(t *testing.T) {
	goodMD := func(base string) map[string]any {
		return map[string]any{"issuer": base, "token_endpoint": base + "/token"}
	}
	cases := []struct {
		name      string
		challenge func(string) string
		md        func(string) map[string]any
		opts      *TokenExchangeOptions
		wantAuth  bool
		wantMD    int32
	}{
		{"realm-mismatch", func(b string) string { return `Bearer as_uri="` + b + `", realm="https://other.example/"` }, goodMD, nil, true, 0},
		{"insecure-as", func(b string) string { return `Bearer as_uri="http://as.example", realm="` + b + `/"` }, goodMD, nil, true, 0},
		{"filter", func(b string) string { return `Bearer as_uri="` + b + `", realm="` + b + `/"` }, goodMD,
			&TokenExchangeOptions{AuthorizationServerFilter: func(string, string) bool { return false }}, true, 0},
		{"issuer-mismatch", func(b string) string { return `Bearer as_uri="` + b + `", realm="` + b + `/"` },
			func(b string) map[string]any {
				return map[string]any{"issuer": "https://evil.example", "token_endpoint": b + "/token"}
			}, nil, true, 1},
		{"unsupported-token-type", func(b string) string { return `Bearer as_uri="` + b + `", realm="` + b + `/"` },
			func(b string) map[string]any {
				return map[string]any{"issuer": b, "token_endpoint": b + "/token", "subject_token_types_supported": []string{TokenTypeSAML2}}
			}, nil, true, 1},
		{"no-lws-challenge", func(string) string { return `Basic realm="x"` }, goodMD, nil, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, mdRequests := challengeServer(t, tc.challenge, tc.md)
			key, _ := GenerateEd25519Key()
			creds, _ := NewDIDKeyCredentials(key, nil)
			c := NewClient(WithAuthenticator(NewTokenExchangeAuthenticator(creds, tc.opts)))
			_, err := c.Head(ctx, srv.URL+"/r")
			var ae *AuthenticationError
			if tc.wantAuth {
				if !errors.As(err, &ae) {
					t.Fatalf("want AuthenticationError, got %v", err)
				}
			} else {
				var he *HTTPError
				if !errors.Is(err, ErrUnauthorized) || !errors.As(err, &he) || len(he.Challenges) != 1 || he.Challenges[0].Realm() != "x" {
					t.Fatalf("want 401 HTTPError with challenges, got %v", err)
				}
			}
			if got := atomic.LoadInt32(mdRequests); got != tc.wantMD {
				t.Errorf("metadata requests = %d, want %d", got, tc.wantMD)
			}
		})
	}
}

func TestRedirectDropsToken(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
		w.WriteHeader(204)
	}))
	defer other.Close()
	s := newMemServer(t)
	s.requireAuth = true
	auth, _ := didKeyAuth(t)
	c := NewClient(WithAuthenticator(auth))
	if _, err := c.Head(ctx, s.URL("/root/")); err != nil {
		t.Fatal(err)
	}
	// A server inside the realm redirecting outside of it.
	redirector := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/target", http.StatusFound)
	})
	s.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			if r.Header.Get("Authorization") == "" {
				t.Error("token not sent inside the realm")
			}
			redirector(w, r)
			return
		}
		s.ServeHTTP(w, r)
	})
	if _, err := c.Head(ctx, s.URL("/redirect")); err != nil {
		t.Fatal(err)
	}
	if leaked.Load() {
		t.Error("Authorization forwarded across realms on redirect")
	}
}

func TestOpenIDAndSAMLCredentials(t *testing.T) {
	for _, tc := range []struct {
		provider  CredentialProvider
		tokenType string
		token     string
	}{
		{NewOpenIDCredentials("id-token-123"), TokenTypeIDToken, "id-token-123"},
		{NewOpenIDCredentialsFunc(func(_ context.Context, cc CredentialContext) (string, error) { return "fresh-for-" + cc.Issuer, nil }), TokenTypeIDToken, "fresh-for-"},
		{NewSAMLCredentials(EncodeSAMLAssertion([]byte("<saml:Assertion/>"))), TokenTypeSAML2, "PHNhbWw6QXNzZXJ0aW9uLz4"},
	} {
		s := newMemServer(t)
		s.requireAuth = true
		c := NewClient(WithAuthenticator(NewTokenExchangeAuthenticator(tc.provider, nil)))
		if _, err := c.Head(ctx, s.URL("/root/")); err != nil {
			t.Fatal(err)
		}
		f := s.lastTokenForm
		if f.Get("subject_token_type") != tc.tokenType || !strings.HasPrefix(f.Get("subject_token"), tc.token) {
			t.Errorf("form = %v", f)
		}
	}
}

func TestBearerTokenAuthenticator(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
		w.WriteHeader(204)
	}))
	defer srv.Close()
	c := NewClient(WithAuthenticator(NewBearerTokenAuthenticator("abc", srv.URL+"/scoped/")))
	_, _ = c.Head(ctx, srv.URL+"/scoped/x")
	_, _ = c.Head(ctx, srv.URL+"/elsewhere")
	if got[0] != "Bearer abc" || got[1] != "" {
		t.Errorf("authorization headers = %q", got)
	}
	n := 0
	c2 := NewClient(WithAuthenticator(NewBearerTokenSource(func(context.Context) (string, error) {
		n++
		return fmt.Sprintf("t%d", n), nil
	}, "")))
	_, _ = c2.Head(ctx, srv.URL+"/a")
	_, _ = c2.Head(ctx, srv.URL+"/b")
	if got[2] != "Bearer t1" || got[3] != "Bearer t2" {
		t.Errorf("token source headers = %q", got[2:])
	}
}

func TestErrorMapping(t *testing.T) {
	statuses := map[int]error{
		400: ErrBadRequest, 401: ErrUnauthorized, 403: ErrForbidden, 404: ErrNotFound, 405: ErrMethodNotAllowed,
		406: ErrNotAcceptable, 409: ErrConflict, 410: ErrGone, 412: ErrPreconditionFailed, 415: ErrUnsupportedMediaType,
		422: ErrUnprocessableContent, 501: ErrNotImplemented, 507: ErrInsufficientStorage,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var code int
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/"), "%d", &code)
		w.Header().Set("Allow", "GET, HEAD")
		w.Header().Set("Accept-Query", `application/lws-query+json, "application/sparql-query"`)
		w.WriteHeader(code)
		_, _ = w.Write([]byte("oops"))
	}))
	defer srv.Close()
	c := NewClient()
	for code, sentinel := range statuses {
		_, err := c.Read(ctx, fmt.Sprintf("%s/%d", srv.URL, code))
		if !errors.Is(err, sentinel) {
			t.Errorf("%d: err = %v", code, err)
		}
		for other, s := range statuses {
			if other != code && errors.Is(err, s) {
				t.Errorf("%d also matches %v", code, s)
			}
		}
		var he *HTTPError
		if !errors.As(err, &he) || he.StatusCode != code || he.Body != "oops" || he.Method != "GET" {
			t.Errorf("%d: %#v", code, he)
		}
	}
	_, err := c.Read(ctx, srv.URL+"/500")
	var he *HTTPError
	if !errors.As(err, &he) || he.StatusCode != 500 {
		t.Errorf("500: %v", err)
	}
	_, err = c.Read(ctx, srv.URL+"/405")
	errors.As(err, &he)
	if strings.Join(he.Allow(), ",") != "GET,HEAD" {
		t.Errorf("allow = %v", he.Allow())
	}
	if q := he.AcceptQuery(); len(q) != 2 || q[1] != "application/sparql-query" {
		t.Errorf("accept-query = %v", q)
	}
}

func TestProtocolErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/no-location":
			w.WriteHeader(201)
		case "/html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html/>"))
		case "/no-storage":
			w.WriteHeader(200)
		case "/head-not-allowed":
			if r.Method == http.MethodHead {
				w.WriteHeader(405)
				return
			}
			w.Header().Set("Link", `</sd>; rel="https://www.w3.org/ns/lws#storage"`)
			w.WriteHeader(200)
		case "/sd":
			writeJSON(w, 200, MediaLWSCID, map[string]any{"id": "/sd", "type": "Storage", "service": map[string]any{"type": "StorageRoot", "serviceEndpoint": "/root/"}})
		case "/sub":
			writeJSON(w, 201, MediaLWSJSON, map[string]any{"type": "Other"})
		}
	}))
	defer srv.Close()
	c := NewClient()
	var pe *ProtocolError
	if _, err := c.Create(ctx, srv.URL+"/no-location", strings.NewReader("x"), "text/plain"); !errors.As(err, &pe) {
		t.Errorf("missing Location: %v", err)
	}
	if _, err := c.ReadContainer(ctx, srv.URL+"/html"); !errors.As(err, &pe) {
		t.Errorf("html container: %v", err)
	}
	if _, err := c.DiscoverStorage(ctx, srv.URL+"/no-storage"); !errors.As(err, &pe) {
		t.Errorf("no storage link: %v", err)
	}
	sd, err := c.DiscoverStorage(ctx, srv.URL+"/head-not-allowed")
	if err != nil {
		t.Fatalf("GET fallback: %v", err)
	}
	if root, _ := sd.StorageRoot(); sd.ID != srv.URL+"/sd" || root != srv.URL+"/root/" {
		t.Errorf("single-object service: %s %s", sd.ID, root)
	}
	if _, err := c.Subscribe(ctx, srv.URL+"/sub", WebhookSubscriptionRequest{Topics: []string{"a"}, Inbox: "b"}); !errors.As(err, &pe) {
		t.Errorf("subscription without URL: %v", err)
	}
}

func TestNotificationsAPI(t *testing.T) {
	s := newMemServer(t)
	c := NewClient()
	sd, err := c.GetStorageDescription(ctx, s.URL("/"))
	if err != nil {
		t.Fatal(err)
	}
	sub, err := c.SubscribeWebhook(ctx, sd, WebhookSubscriptionRequest{
		Topics:  []string{s.URL("/root/")},
		Inbox:   "https://receiver.example/inbox",
		Expires: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sub.URL, s.URL("/notifications/sub-")) || sub.ExpiresRaw != "2030-01-02T03:04:05Z" {
		t.Fatalf("subscription = %+v", sub)
	}
	got, err := c.GetSubscription(ctx, sub.URL)
	if err != nil || got.URL != sub.URL || got.Type != SubscriptionWebhook {
		t.Fatalf("get = %+v %v", got, err)
	}
	var listed []string
	for item, err := range c.ListSubscriptions(ctx, s.URL("/notifications/")) {
		if err != nil {
			t.Fatal(err)
		}
		listed = append(listed, item.ID)
	}
	if len(listed) != 1 || listed[0] != sub.URL {
		t.Errorf("listed = %v", listed)
	}
	if err := c.Unsubscribe(ctx, sub.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetSubscription(ctx, sub.URL); !errors.Is(err, ErrNotFound) {
		t.Errorf("after unsubscribe: %v", err)
	}
	noWebhook := &StorageDescription{ID: "x", Services: []Service{{Types: TypeList{ServiceNotification}, ServiceEndpoint: "y"}}}
	if _, err := c.SubscribeWebhook(ctx, noWebhook, WebhookSubscriptionRequest{}); err == nil {
		t.Error("subscribed without WebhookSubscription support")
	}
}

func TestAccessAPI(t *testing.T) {
	s := newMemServer(t)
	c := NewClient()
	sd, _ := c.GetStorageDescription(ctx, s.URL("/"))
	reqSvc, _ := sd.AccessRequestService()
	grantSvc, _ := sd.AccessGrantService()
	policy := NewAccessPolicy("did:key:zAgent", ActionRead).
		WithTarget("StorageResource", s.URL("/root/")).
		WithConstraints(PurposeConstraint("https://purpose.example/collaboration"), ClientConstraint("https://app.example/id"))
	req := NewAccessRequest(sd.ID, policy)
	req.Inbox = "https://id.example/inbox/"
	reqURL, err := c.RequestAccess(ctx, reqSvc.ServiceEndpoint, req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.GetAccessRequest(ctx, reqURL)
	if err != nil || got.Storage != sd.ID || got.Inbox != req.Inbox || got.Access[0].Assignee != "did:key:zAgent" || len(got.Raw) == 0 {
		t.Fatalf("request = %+v %v", got, err)
	}
	n := 0
	for item, err := range c.ListAccessRequests(ctx, reqSvc.ServiceEndpoint) {
		if err != nil {
			t.Fatal(err)
		}
		if item.ID == reqURL {
			n++
		}
	}
	if n != 1 {
		t.Error("request not listed")
	}
	grantURL, err := c.GrantAccess(ctx, grantSvc.ServiceEndpoint, NewAccessGrant(sd.ID, policy))
	if err != nil {
		t.Fatal(err)
	}
	g, err := c.GetAccessGrant(ctx, grantURL)
	if err != nil || !g.Types.Has(TypeAccessGrant) {
		t.Fatalf("grant = %+v %v", g, err)
	}
	for _, err := range c.ListAccessGrants(ctx, grantSvc.ServiceEndpoint) {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.GetAccessRequest(ctx, grantURL); err == nil {
		t.Error("grant read as request")
	}
	if err := c.RevokeAccessGrant(ctx, grantURL); err != nil {
		t.Fatal(err)
	}
	if err := c.CancelAccessRequest(ctx, reqURL); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetAccessGrant(ctx, grantURL); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoked grant: %v", err)
	}
	if _, err := c.RequestAccess(ctx, reqSvc.ServiceEndpoint, NewAccessRequest(sd.ID)); err == nil {
		t.Error("request without policies sent")
	}
}

func TestTypeIndexAndSearch(t *testing.T) {
	s := newMemServer(t)
	c := NewClient()
	for i := 0; i < 7; i++ {
		typ := "https://schema.org/Person"
		if i%2 == 1 {
			typ = "https://schema.org/Event"
		}
		if _, err := c.CreateJSON(ctx, s.URL("/root/"), map[string]int{"i": i}, Types(typ, fmt.Sprintf("https://example.org/T%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	var types []string
	for typ, err := range c.ListTypes(ctx, s.URL("/types/index")) {
		if err != nil {
			t.Fatal(err)
		}
		types = append(types, typ)
	}
	if len(types) != 11 || !contains(types, "https://schema.org/Person") || !contains(types, TypeContainer) {
		t.Errorf("types (%d) = %v", len(types), types)
	}
	formats, err := c.AcceptedQueryFormats(ctx, s.URL("/types/search"))
	if err != nil || len(formats) != 1 || formats[0] != MediaLWSQueryJSON {
		t.Errorf("formats = %v %v", formats, err)
	}
	q := NewTypeQuery().AllOf("https://schema.org/Person", TypeDataResource)
	page, err := c.SearchTypes(ctx, s.URL("/types/search"), q)
	if err != nil {
		t.Fatal(err)
	}
	if page.TotalItems != 4 || page.Types.Has("ContainerPage") == false {
		t.Errorf("search page = %+v", page)
	}
	var found []string
	for item, err := range c.SearchAll(ctx, s.URL("/types/search"), NewTypeQuery().AnyOf("https://schema.org/Person", "https://schema.org/Event")) {
		if err != nil {
			t.Fatal(err)
		}
		if !item.HasType(TypeDataResource) {
			t.Errorf("item %+v", item)
		}
		found = append(found, item.ID)
	}
	if len(found) != 7 {
		t.Errorf("searchAll found %d", len(found))
	}
	if s.count("QUERY", "/types/search") != 2 || s.count(http.MethodGet, "/types/search") != 1 {
		t.Errorf("QUERY %d GET %d", s.count("QUERY", "/types/search"), s.count(http.MethodGet, "/types/search"))
	}
	if _, err := c.SearchPage(ctx, s.URL("/types/search?cursor=expired&page=2")); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired cursor: %v", err)
	}
	if _, err := c.SearchTypes(ctx, s.URL("/types/search"), NewTypeQuery().AnyOf()); err == nil {
		t.Error("empty OR group sent")
	}
	// 415 exposes Accept-Query.
	_, _, err = c.execute(ctx, "QUERY", s.URL("/types/search"), strings.NewReader("x"), "application/sparql-query", applyCallOptions(nil))
	var he *HTTPError
	if !errors.As(err, &he) || !errors.Is(err, ErrUnsupportedMediaType) || he.AcceptQuery()[0] != MediaLWSQueryJSON {
		t.Errorf("415: %v", err)
	}
}

func TestSelfSignedCredentials(t *testing.T) {
	now := time.Unix(1790000000, 0)
	clock := func() time.Time { return now }
	p256, _ := GenerateP256Key()
	ed, _ := GenerateEd25519Key()
	for _, key := range []crypto.Signer{p256, ed} {
		creds, err := NewSelfSignedCredentials("https://id.example/agent", key, "key-1", &SelfSignedOptions{Clock: clock, Lifetime: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		tok, err := creds.Token("https://as.example")
		if err != nil {
			t.Fatal(err)
		}
		hdr, claims, err := VerifyJWT(tok, key.Public())
		if err != nil {
			t.Fatal(err)
		}
		if hdr["kid"] != "key-1" || hdr["typ"] != "JWT" || hdr["alg"] != creds.Algorithm() {
			t.Errorf("header = %v", hdr)
		}
		if claims["sub"] != "https://id.example/agent" || claims["iss"] != claims["sub"] || claims["client_id"] != claims["sub"] ||
			claims["iat"] != float64(now.Unix()) || claims["exp"] != float64(now.Unix()+60) || claims["jti"] == "" {
			t.Errorf("claims = %v", claims)
		}
		if aud, _ := claims["aud"].([]any); len(aud) != 1 || aud[0] != "https://as.example" {
			t.Errorf("aud = %v", claims["aud"])
		}
		// Cached per audience.
		again, _ := creds.Token("https://as.example")
		other, _ := creds.Token("https://as2.example")
		if again != tok || other == tok {
			t.Error("credential cache misbehaves")
		}
		jwk, _ := JWKFromPublicKey(key.Public())
		doc := NewControlledIdentifierDocument("https://id.example/agent", *jwk, "key-1")
		b, _ := json.Marshal(doc)
		if !strings.Contains(string(b), `"id":"https://id.example/agent#key-1"`) || !strings.Contains(string(b), `"kid":"key-1"`) ||
			!strings.Contains(string(b), CIDContext) || strings.Contains(string(b), `"d"`) {
			t.Errorf("cid document = %s", b)
		}
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := NewSelfSignedCredentials("https://id.example/agent", p384, "k", nil); err == nil {
		t.Error("P-384 self-signed credentials accepted")
	}
	dk, err := NewDIDKeyCredentials(ed, nil)
	if err != nil || !strings.HasPrefix(dk.Agent(), "did:key:z6Mk") || dk.KeyID() != DIDKeyVerificationMethod(dk.Agent()) || dk.Algorithm() != "EdDSA" {
		t.Errorf("did:key credentials %v %v", dk, err)
	}
}

func TestSlugEncoding(t *testing.T) {
	for in, want := range map[string]string{"plain.txt": "plain.txt", "café 100%": "caf%C3%A9 100%25", "a\nb": "a%0Ab"} {
		if got := encodeSlug(in); got != want {
			t.Errorf("encodeSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLinkSerialization(t *testing.T) {
	l := Link{Href: "https://example.org/x", Rel: "describedby", Params: map[string]string{"type": "text/turtle", "title": `say "hi"`}}
	if got := l.String(); got != `<https://example.org/x>; rel="describedby"; title="say \"hi\""; type="text/turtle"` {
		t.Errorf("link = %s", got)
	}
	if NewLink("a", "b").Type() != "" || l.Anchor() != "" {
		t.Error("accessors")
	}
}
