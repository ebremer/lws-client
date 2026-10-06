// SPDX-License-Identifier: MIT

package lws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestInterop runs the cross-language interop scenario
// (conformance/scenario.md) against the mock server named by the
// LWS_TEST_SERVER environment variable, e.g.
//
//	node testing/mock-server/server.mjs --port 8787
//	LWS_TEST_SERVER=http://localhost:8787 go test -run TestInterop -v
func TestInterop(t *testing.T) {
	base := strings.TrimSuffix(os.Getenv("LWS_TEST_SERVER"), "/")
	if base == "" {
		t.Skip("LWS_TEST_SERVER not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	step := func(name string) { t.Logf("step: %s", name) }

	// 1. Authenticate + discover.
	step("authenticate and discover")
	key, err := GenerateP256Key()
	if err != nil {
		t.Fatal(err)
	}
	creds, err := NewDIDKeyCredentials(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(WithAuthenticator(NewTokenExchangeAuthenticator(creds, nil)))
	sd, err := c.DiscoverStorage(ctx, base+"/root/")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	root, err := sd.StorageRoot()
	if err != nil || root != base+"/root/" || sd.ID != base+"/" {
		t.Fatalf("storage %s root %s %v", sd.ID, root, err)
	}
	notifySvc, ok1 := sd.NotificationService()
	reqSvc, ok2 := sd.AccessRequestService()
	grantSvc, ok3 := sd.AccessGrantService()
	indexSvc, ok4 := sd.TypeIndexService()
	searchSvc, ok5 := sd.TypeSearchService()
	if !(ok1 && ok2 && ok3 && ok4 && ok5) {
		t.Fatalf("services missing: %+v", sd.Services)
	}

	// 2. Container.
	step("create container")
	cont, err := c.CreateContainer(ctx, root, Slug(fmt.Sprintf("interop-go-%d", time.Now().UnixMilli())))
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	C := cont.Location
	if !cont.Metadata.IsContainer() {
		t.Errorf("created container metadata %+v", cont.Metadata)
	}

	// 3. Text resource.
	step("create text")
	hc, err := c.Create(ctx, C, strings.NewReader("Hello, LWS!"), "text/plain", Slug("hello.txt"))
	if err != nil {
		t.Fatalf("create text: %v", err)
	}
	H := hc.Location

	// 4. Read.
	step("read")
	res, err := c.Read(ctx, H)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if res.Text() != "Hello, LWS!" || res.ETag == "" || !res.IsDataResource() || res.Parent != C || res.Linkset == "" || res.Storage != base+"/" {
		t.Fatalf("read metadata %+v body %q", res.ResourceMetadata, res.Text())
	}

	// 5. Conditional read.
	step("conditional read")
	nm, err := c.Read(ctx, H, IfNoneMatch(res.ETag))
	if err != nil || !nm.NotModified {
		t.Fatalf("conditional read: %+v %v", nm, err)
	}

	// 6. Update + stale update.
	step("update")
	if _, err := c.Update(ctx, H, strings.NewReader("Hello again"), "text/plain", IfMatch(res.ETag)); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, err := c.Update(ctx, H, strings.NewReader("stale"), "text/plain", IfMatch(res.ETag)); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("stale update: %v", err)
	}

	// 7. JSON + patch.
	step("create and patch JSON")
	pc, err := c.CreateJSON(ctx, C, map[string]any{"name": "Alice", "age": 30}, Slug("profile.json"), Types("https://schema.org/Person"))
	if err != nil {
		t.Fatalf("create json: %v", err)
	}
	P := pc.Location
	if _, err := c.Patch(ctx, P, JSONPatch{}.Replace("/age", 31).Add("/city", "Boston")); err != nil {
		t.Fatalf("patch: %v", err)
	}
	pr, err := c.Read(ctx, P)
	if err != nil {
		t.Fatal(err)
	}
	var person map[string]any
	if err := pr.JSON(&person); err != nil || person["name"] != "Alice" || person["age"] != float64(31) || person["city"] != "Boston" {
		t.Fatalf("patched JSON %v %v", person, err)
	}

	// 8. Linkset.
	step("linkset")
	ls, err := c.ReadLinkset(ctx, P)
	if err != nil {
		t.Fatalf("read linkset: %v", err)
	}
	path := JSONPointer("linkset", "0", "describedby")
	var value any = []map[string]string{{"href": "https://example.org/shapes/person"}}
	if len(ls.Linkset.Contexts) > 0 && len(ls.Linkset.Contexts[0].Targets("describedby")) > 0 {
		path, value = JSONPointer("linkset", "0", "describedby", "-"), map[string]string{"href": "https://example.org/shapes/person"}
	}
	if _, err := c.PatchLinkset(ctx, ls.URL, JSONPatch{}.Add(path, value), IfMatch(ls.ETag)); err != nil {
		t.Fatalf("patch linkset: %v", err)
	}
	ls2, err := c.ReadLinkset(ctx, P)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tg := range ls2.Linkset.Targets("describedby") {
		found = found || tg.Href == "https://example.org/shapes/person"
	}
	if !found {
		t.Fatalf("describedby link missing: %+v", ls2.Linkset)
	}

	// 9. Pagination.
	step("pagination")
	for i := 0; i < 6; i++ {
		if _, err := c.Create(ctx, C, strings.NewReader(fmt.Sprintf("item %d", i)), "text/plain", Slug(fmt.Sprintf("item-%d.txt", i))); err != nil {
			t.Fatalf("create item: %v", err)
		}
	}
	page, err := c.ReadContainer(ctx, C)
	if err != nil {
		t.Fatal(err)
	}
	if page.TotalItems != 8 || page.Next == "" {
		t.Fatalf("first page totalItems %d next %q", page.TotalItems, page.Next)
	}
	var members []string
	for item, err := range c.ListContainer(ctx, C) {
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, item.ID)
	}
	if len(members) != 8 || !contains(members, H) || !contains(members, P) {
		t.Fatalf("members %v", members)
	}

	// 10. Type index / search.
	step("type index and search")
	var types []string
	for typ, err := range c.ListTypes(ctx, indexSvc.ServiceEndpoint) {
		if err != nil {
			t.Fatal(err)
		}
		types = append(types, typ)
	}
	if !contains(types, "https://schema.org/Person") {
		t.Fatalf("types %v", types)
	}
	var hits []string
	for item, err := range c.SearchAll(ctx, searchSvc.ServiceEndpoint, NewTypeQuery().AllOf("https://schema.org/Person")) {
		if err != nil {
			t.Fatal(err)
		}
		hits = append(hits, item.ID)
	}
	if !contains(hits, P) {
		t.Fatalf("search hits %v", hits)
	}
	formats, err := c.AcceptedQueryFormats(ctx, searchSvc.ServiceEndpoint)
	if err != nil || !contains(formats, MediaLWSQueryJSON) {
		t.Fatalf("formats %v %v", formats, err)
	}

	// 11. Notifications.
	step("notifications")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	inbox := fmt.Sprintf("http://%s/inbox", ln.Addr())
	verifier := NewWebhookVerifier(&WebhookVerifierOptions{TrustedStorages: []string{sd.ID}})
	got := make(chan *VerifiedNotification, 16)
	verifyErrs := make(chan error, 16)
	mux := http.NewServeMux()
	mux.HandleFunc("/inbox", func(w http.ResponseWriter, r *http.Request) {
		n, err := verifier.VerifyRequest(r, inbox)
		if err != nil {
			verifyErrs <- err
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		got <- n
		w.WriteHeader(http.StatusNoContent)
	})
	inboxSrv := &http.Server{Handler: mux}
	go inboxSrv.Serve(ln)
	defer inboxSrv.Close()

	sub, err := c.SubscribeWebhook(ctx, sd, WebhookSubscriptionRequest{Topics: []string{C}, Inbox: inbox})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if _, err := c.Update(ctx, H, strings.NewReader("Hello, subscribers"), "text/plain"); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	received := false
	for !received {
		select {
		case n := <-got:
			for _, a := range n.Notification.Activities {
				if a.IsUpdate() && a.Object.ID == H {
					received = true
				}
			}
		case err := <-verifyErrs:
			t.Fatalf("webhook verification failed: %v", err)
		case <-deadline:
			t.Fatal("no Update notification within 5 s")
		}
	}
	listed := false
	for item, err := range c.ListSubscriptions(ctx, notifySvc.ServiceEndpoint) {
		if err != nil {
			t.Fatal(err)
		}
		listed = listed || item.ID == sub.URL
	}
	if !listed {
		t.Errorf("subscription %s not listed", sub.URL)
	}
	if err := c.Unsubscribe(ctx, sub.URL); err != nil {
		t.Fatalf("unsubscribe: %v", err)
	}

	// 12. Access requests and grants.
	step("access requests and grants")
	policy := NewAccessPolicy(creds.Agent(), ActionRead).
		WithTarget("StorageResource", C).
		WithConstraints(PurposeConstraint("https://purpose.example/collaboration"))
	reqURL, err := c.RequestAccess(ctx, reqSvc.ServiceEndpoint, NewAccessRequest(sd.ID, policy))
	if err != nil {
		t.Fatalf("request access: %v", err)
	}
	ar, err := c.GetAccessRequest(ctx, reqURL)
	if err != nil || ar.Storage != sd.ID || ar.Access[0].Assignee != creds.Agent() || ar.Access[0].Target.Values[0] != C {
		t.Fatalf("access request %+v %v", ar, err)
	}
	listedReq := false
	for item, err := range c.ListAccessRequests(ctx, reqSvc.ServiceEndpoint) {
		if err != nil {
			t.Fatal(err)
		}
		listedReq = listedReq || item.ID == reqURL
	}
	if !listedReq {
		t.Errorf("access request not listed")
	}
	grantURL, err := c.GrantAccess(ctx, grantSvc.ServiceEndpoint, NewAccessGrant(sd.ID, policy))
	if err != nil {
		t.Fatalf("grant access: %v", err)
	}
	if g, err := c.GetAccessGrant(ctx, grantURL); err != nil || !g.Types.Has(TypeAccessGrant) {
		t.Fatalf("access grant %+v %v", g, err)
	}
	if err := c.RevokeAccessGrant(ctx, grantURL); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := c.CancelAccessRequest(ctx, reqURL); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	// Ed25519 credentials work too.
	edKey, _ := GenerateEd25519Key()
	edCreds, _ := NewDIDKeyCredentials(edKey, nil)
	edClient := NewClient(WithAuthenticator(NewTokenExchangeAuthenticator(edCreds, nil)))
	if _, err := edClient.Head(ctx, root); err != nil {
		t.Fatalf("Ed25519 credentials: %v", err)
	}

	// HTTPS agent (lws10-authn-ssi-cid): publish a controlled identifier
	// document inside the storage and authenticate as that agent.
	step("controlled identifier agent")
	agentDoc, err := c.CreateJSON(ctx, C, map[string]any{}, Slug("agent"))
	if err != nil {
		t.Fatal(err)
	}
	agentKey, _ := GenerateP256Key()
	agentJWK, _ := JWKFromPublicKey(agentKey.Public())
	cid := NewControlledIdentifierDocument(agentDoc.Location, *agentJWK, "key-1")
	cidJSON, _ := json.Marshal(cid)
	if _, err := c.Update(ctx, agentDoc.Location, bytes.NewReader(cidJSON), MediaJSON); err != nil {
		t.Fatal(err)
	}
	agentCreds, err := NewSelfSignedCredentials(agentDoc.Location, agentKey, "key-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	agentClient := NewClient(WithAuthenticator(NewTokenExchangeAuthenticator(agentCreds, nil)))
	if _, err := agentClient.Head(ctx, root); err != nil {
		t.Fatalf("HTTPS agent credentials: %v", err)
	}

	// 13. Delete.
	step("delete")
	if err := c.Delete(ctx, C); !errors.Is(err, ErrConflict) {
		t.Fatalf("non-recursive delete: %v", err)
	}
	if err := c.Delete(ctx, C, Recursive()); err != nil {
		t.Fatalf("recursive delete: %v", err)
	}
	if _, err := c.Read(ctx, H); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read after delete: %v", err)
	}
}
