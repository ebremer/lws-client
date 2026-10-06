// SPDX-License-Identifier: MIT

package lws_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	lws "github.com/ebremer/lws-client/go"
)

func Example() {
	ctx := context.Background()
	key, _ := lws.GenerateP256Key()
	creds, _ := lws.NewDIDKeyCredentials(key, nil)
	client := lws.NewClient(lws.WithAuthenticator(lws.NewTokenExchangeAuthenticator(creds, nil)))

	storage, err := client.DiscoverStorage(ctx, "https://storage.example/root/")
	if err != nil {
		log.Fatal(err)
	}
	root, _ := storage.StorageRoot()
	created, err := client.Create(ctx, root, strings.NewReader("Hello, LWS!"), "text/plain", lws.Slug("hello.txt"))
	if err != nil {
		log.Fatal(err)
	}
	for item, err := range client.ListContainer(ctx, root) {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(item.ID, item.Format)
	}
	res, _ := client.Read(ctx, created.Location)
	_, err = client.Update(ctx, created.Location, strings.NewReader("Hi"), "text/plain", lws.IfMatch(res.ETag))
	if errors.Is(err, lws.ErrPreconditionFailed) {
		fmt.Println("modified concurrently")
	}
}

func ExampleParseLinkHeader() {
	links := lws.ParseLinkHeader("https://storage.example/alice/notes/list.txt",
		`</alice/notes/>; rel="up", <https://www.w3.org/ns/lws#DataResource>; rel="type"`)
	for _, l := range links {
		fmt.Println(l.Rel, l.Href)
	}
	// Output:
	// up https://storage.example/alice/notes/
	// type https://www.w3.org/ns/lws#DataResource
}

func ExampleParseChallenges() {
	ch := lws.ParseChallenges(`Bearer as_uri="https://authorization.example", realm="https://storage.example/storage_1", error="invalid_token"`)
	fmt.Println(ch[0].AsURI(), ch[0].Realm(), ch[0].Error())
	// Output: https://authorization.example https://storage.example/storage_1 invalid_token
}

func ExampleJSONPatch() {
	patch := lws.JSONPatch{}.
		Replace("/age", 31).
		Add(lws.JSONPointer("linkset", "0", "https://example.org/rel", "-"), map[string]string{"href": "https://example.org/x"})
	out, _ := json.Marshal(patch)
	fmt.Println(string(out))
	// Output: [{"op":"replace","path":"/age","value":31},{"op":"add","path":"/linkset/0/https:~1~1example.org~1rel/-","value":{"href":"https://example.org/x"}}]
}

func ExampleTypeQuery() {
	q := lws.NewTypeQuery().
		AnyOf("https://schema.org/Person", "http://xmlns.com/foaf/0.1/Person").
		AllOf(lws.TypeDataResource)
	out, _ := json.Marshal(q)
	fmt.Println(string(out))
	// Output: {"type":[["https://schema.org/Person","http://xmlns.com/foaf/0.1/Person"],"https://www.w3.org/ns/lws#DataResource"]}
}

func ExampleDIDKeyFromPublicKey() {
	jwk := lws.JWK{Kty: "EC", Crv: "P-256",
		X: "fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI", Y: "hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU"}
	pub, _ := jwk.PublicKey()
	did, _ := lws.DIDKeyFromPublicKey(pub)
	fmt.Println(did)
	// Output: did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169
}

func ExampleNewAccessRequest() {
	req := lws.NewAccessRequest("https://storage.example/",
		lws.NewAccessPolicy("https://id.example/agent", lws.ActionRead).
			WithTarget("StorageResource", "https://storage.example/root/projects/").
			WithConstraints(lws.PurposeConstraint("https://purpose.example/collaboration")))
	out, _ := json.Marshal(req)
	fmt.Println(string(out))
	// Output: {"@context":["https://www.w3.org/ns/lws/v1"],"access":[{"type":["AccessPolicy"],"action":["read"],"assignee":"https://id.example/agent","target":{"type":"StorageResource","value":["https://storage.example/root/projects/"]},"constraint":[{"leftOperand":"purpose","operator":"eq","rightOperand":"https://purpose.example/collaboration"}]}],"storage":"https://storage.example/","type":["AccessRequest"]}
}

func ExampleWebhookVerifier_Handler() {
	verifier := lws.NewWebhookVerifier(&lws.WebhookVerifierOptions{
		TrustedStorages: []string{"https://storage.example/"},
	})
	inbox := "https://receiver.example/hooks/lws"
	http.Handle("/hooks/lws", verifier.Handler(inbox, func(ctx context.Context, n *lws.VerifiedNotification) {
		for _, a := range n.Notification.Activities {
			fmt.Println(a.Types, a.Object.ID)
		}
	}))
}

func ExampleHTTPError() {
	client := lws.NewClient()
	err := client.Delete(context.Background(), "https://storage.example/root/notes/")
	var httpErr *lws.HTTPError
	switch {
	case errors.Is(err, lws.ErrConflict):
		fmt.Println("container is not empty; retry with lws.Recursive()")
	case errors.As(err, &httpErr):
		fmt.Println("status", httpErr.StatusCode)
	}
}
