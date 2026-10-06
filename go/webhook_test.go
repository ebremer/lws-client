// SPDX-License-Identifier: MIT

package lws

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// signDelivery signs a webhook delivery like an LWS server would (RFC 9421,
// covering the required components).
func signDelivery(t *testing.T, req *http.Request, body []byte, key crypto.Signer, keyid, alg string, created time.Time) {
	t.Helper()
	req.Header.Set("Content-Type", MediaLWSJSON)
	req.Header.Set("Content-Digest", ContentDigest(body))
	params := &SFInnerList{Params: SFParams{{"created", created.Unix()}, {"keyid", keyid}, {"alg", alg}}}
	for _, c := range RequiredSignatureComponents {
		params.Items = append(params.Items, SFItem{Value: c})
	}
	base, err := signatureBase(RequiredSignatureComponents, params, req.Method, req.URL, req.Header)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signRaw(key, []byte(base))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Signature-Input", "sig1="+params.String())
	req.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
}

func TestWebhookHandler(t *testing.T) {
	var keys struct {
		PrivateJWK JWK `json:"privateJwk"`
	}
	fixture(t, "keys/p256.json", &keys)
	key, err := keys.PrivateJWK.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	sd := loadWebhookDescription(t)
	verifier := NewWebhookVerifier(&WebhookVerifierOptions{
		FetchStorageDescription: func(context.Context, string) (*StorageDescription, error) { return sd, nil },
	})
	var mu sync.Mutex
	var received []*VerifiedNotification
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	inbox := srv.URL + "/inbox"
	mux.Handle("/inbox", verifier.Handler(inbox, func(_ context.Context, n *VerifiedNotification) {
		mu.Lock()
		received = append(received, n)
		mu.Unlock()
	}))

	body := []byte(`{"@context":["https://www.w3.org/ns/lws/v1"],"type":"Notification","storage":"https://storage.example/",` +
		`"activity":{"id":"urn:uuid:1","type":"Update","object":{"id":"https://storage.example/root/a","type":"DataResource"},"published":"2026-10-06T10:00:00Z"}}`)
	send := func(mutate func(*http.Request, []byte) []byte) int {
		req, _ := http.NewRequest(http.MethodPost, inbox, nil)
		signDelivery(t, req, body, key, "https://storage.example/#key-p256", "ecdsa-p256-sha256", time.Now())
		b := body
		if mutate != nil {
			b = mutate(req, b)
		}
		req.Body = io.NopCloser(bytes.NewReader(b))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := send(nil); code != http.StatusNoContent {
		t.Fatalf("valid delivery answered %d", code)
	}
	if len(received) != 1 || !received[0].Notification.Activities[0].IsUpdate() || received[0].Storage != "https://storage.example/" {
		t.Fatalf("received = %+v", received)
	}
	if code := send(func(_ *http.Request, b []byte) []byte { return bytes.Replace(b, []byte("root/a"), []byte("root/b"), 1) }); code != http.StatusUnauthorized {
		t.Errorf("tampered delivery answered %d", code)
	}
	if code := send(func(r *http.Request, b []byte) []byte { r.Header.Del("Signature"); return b }); code != http.StatusUnauthorized {
		t.Errorf("unsigned delivery answered %d", code)
	}
	resp, _ := http.Get(inbox)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET inbox answered %d", resp.StatusCode)
	}
	if len(received) != 1 {
		t.Errorf("callbacks = %d", len(received))
	}

	// VerifyRequest with an inbox URL reconstructed from the request.
	req := httptest.NewRequest(http.MethodPost, "http://receiver.test/hook", nil)
	signDelivery(t, req, body, key, "https://storage.example/#key-p256", "ecdsa-p256-sha256", time.Now())
	req.Body = io.NopCloser(bytes.NewReader(body))
	if _, err := verifier.VerifyRequest(req, ""); err != nil {
		t.Errorf("reconstructed inbox URL: %v", err)
	}
}

func TestWebhookKeyRotation(t *testing.T) {
	oldKey, _ := GenerateP256Key()
	newKey, _ := GenerateP256Key()
	describe := func(k crypto.Signer) *StorageDescription {
		jwk, _ := JWKFromPublicKey(k.Public())
		data := fmt.Sprintf(`{"id":"https://s.example/","type":"Storage","verificationMethod":[{"id":"#k","type":"JsonWebKey","controller":"https://s.example/","publicKeyJwk":{"kty":"EC","crv":"P-256","x":%q,"y":%q}}],"authentication":["#k"]}`, jwk.X, jwk.Y)
		sd, err := ParseStorageDescription([]byte(data), "")
		if err != nil {
			t.Fatal(err)
		}
		return sd
	}
	current := describe(oldKey)
	fetches := 0
	v := NewWebhookVerifier(&WebhookVerifierOptions{
		FetchStorageDescription: func(context.Context, string) (*StorageDescription, error) { fetches++; return current, nil },
	})
	body := []byte(`{"type":"Notification","storage":"https://s.example/","activity":[]}`)
	deliver := func(k crypto.Signer) error {
		u, _ := url.Parse("https://inbox.example/x")
		req := &http.Request{Method: http.MethodPost, URL: u, Header: http.Header{}}
		signDelivery(t, req, body, k, "https://s.example/#k", "ecdsa-p256-sha256", time.Now())
		_, err := v.Verify(context.Background(), http.MethodPost, u.String(), req.Header, body)
		return err
	}
	if err := deliver(oldKey); err != nil {
		t.Fatal(err)
	}
	current = describe(newKey) // the storage rotates its key
	if err := deliver(newKey); err != nil {
		t.Fatalf("rotated key rejected: %v", err)
	}
	if fetches != 2 {
		t.Errorf("fetches = %d, want 2 (one refetch after rotation)", fetches)
	}
	if err := deliver(oldKey); err == nil || !strings.Contains(err.Error(), "signature mismatch") {
		t.Errorf("old key after rotation: %v", err)
	}
}
