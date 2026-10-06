// SPDX-License-Identifier: MIT

package lws

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// WebhookVerifierOptions configures a WebhookVerifier.
type WebhookVerifierOptions struct {
	// Client retrieves storage descriptions (default: NewClient()).
	Client *Client
	// FetchStorageDescription overrides how storage descriptions are
	// retrieved (useful for tests); it takes precedence over Client.
	FetchStorageDescription func(ctx context.Context, storageID string) (*StorageDescription, error)
	// MaxAge is how old a signature's "created" time may be (default 300 s).
	MaxAge time.Duration
	// ClockSkew is how far in the future "created" may be (default 300 s).
	ClockSkew time.Duration
	// TrustedStorages, if set, restricts the storages whose notifications are
	// accepted (compared with the keyid's storage identifier).
	TrustedStorages []string
	// KeyCacheTTL controls how long storage descriptions are cached
	// (default 10 minutes).
	KeyCacheTTL time.Duration
	// Clock returns the current time (default time.Now).
	Clock func() time.Time
	// MaxBodyBytes limits the body read by VerifyRequest (default 1 MiB).
	MaxBodyBytes int64
}

// WebhookVerifier verifies signed webhook deliveries (lws10-notifications-
// webhook): RFC 9530 Content-Digest, then the RFC 9421 HTTP Message
// Signature using the key published in the storage description. It is safe
// for concurrent use.
type WebhookVerifier struct {
	opts  WebhookVerifierOptions
	mu    sync.Mutex
	cache map[string]cachedDescription
}

type cachedDescription struct {
	sd      *StorageDescription
	fetched time.Time
}

// VerifiedNotification is a successfully verified delivery.
type VerifiedNotification struct {
	Notification *Notification
	// KeyID is the verification method that signed the delivery.
	KeyID string
	// Storage is the storage identifier derived from KeyID.
	Storage string
}

// RequiredSignatureComponents are the components an LWS webhook signature
// must cover.
var RequiredSignatureComponents = []string{"@method", "@scheme", "@authority", "@path", "content-type", "content-digest"}

// NewWebhookVerifier returns a verifier. opts may be nil.
func NewWebhookVerifier(opts *WebhookVerifierOptions) *WebhookVerifier {
	v := &WebhookVerifier{cache: map[string]cachedDescription{}}
	if opts != nil {
		v.opts = *opts
	}
	if v.opts.MaxAge <= 0 {
		v.opts.MaxAge = 300 * time.Second
	}
	if v.opts.ClockSkew <= 0 {
		v.opts.ClockSkew = 300 * time.Second
	}
	if v.opts.KeyCacheTTL <= 0 {
		v.opts.KeyCacheTTL = 10 * time.Minute
	}
	if v.opts.Clock == nil {
		v.opts.Clock = time.Now
	}
	if v.opts.MaxBodyBytes <= 0 {
		v.opts.MaxBodyBytes = 1 << 20
	}
	if v.opts.FetchStorageDescription == nil {
		client := v.opts.Client
		if client == nil {
			client = NewClient()
		}
		v.opts.FetchStorageDescription = func(ctx context.Context, id string) (*StorageDescription, error) {
			return client.GetStorageDescription(ctx, id)
		}
	}
	return v
}

// VerifyRequest reads and verifies an incoming delivery. inboxURL is the
// inbox URL registered in the subscription; when empty it is reconstructed
// from the request (which is unreliable behind proxies). The request body is
// consumed.
func (v *WebhookVerifier) VerifyRequest(r *http.Request, inboxURL string) (*VerifiedNotification, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, v.opts.MaxBodyBytes+1))
	if err != nil {
		return nil, &SignatureVerificationError{Reason: "reading body", Err: err}
	}
	if int64(len(body)) > v.opts.MaxBodyBytes {
		return nil, sigErr("body exceeds %d bytes", v.opts.MaxBodyBytes)
	}
	if inboxURL == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		inboxURL = scheme + "://" + r.Host + r.URL.RequestURI()
	}
	return v.Verify(r.Context(), r.Method, inboxURL, r.Header, body)
}

// Handler returns an http.Handler for an inbox: it verifies each delivery
// and calls fn with the verified notification, answering 204 No Content.
// Unverifiable deliveries are answered with 401 and fn is not called.
func (v *WebhookVerifier) Handler(inboxURL string, fn func(ctx context.Context, n *VerifiedNotification)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		n, err := v.VerifyRequest(r, inboxURL)
		if err != nil {
			http.Error(w, "signature verification failed", http.StatusUnauthorized)
			return
		}
		fn(r.Context(), n)
		w.WriteHeader(http.StatusNoContent)
	})
}

// Verify verifies a delivery given its method, the registered inbox URL,
// headers and raw body.
func (v *WebhookVerifier) Verify(ctx context.Context, method, inboxURL string, header http.Header, body []byte) (*VerifiedNotification, error) {
	target, err := url.Parse(inboxURL)
	if err != nil {
		return nil, &SignatureVerificationError{Reason: "invalid inbox URL", Err: err}
	}
	// 1. Content-Digest.
	if err := verifyContentDigest(header, body); err != nil {
		return nil, err
	}
	// 2. Signature-Input / Signature.
	inputs, err := ParseSFDictionary(strings.Join(header.Values("Signature-Input"), ", "))
	if err != nil {
		return nil, &SignatureVerificationError{Reason: "malformed Signature-Input", Err: err}
	}
	sigs, err := ParseSFDictionary(strings.Join(header.Values("Signature"), ", "))
	if err != nil {
		return nil, &SignatureVerificationError{Reason: "malformed Signature", Err: err}
	}
	var params *SFInnerList
	var signature []byte
	for _, m := range inputs {
		if m.List == nil {
			continue
		}
		if _, ok := m.List.Params.Get("keyid"); !ok {
			continue
		}
		s, ok := sigs.Get(m.Name)
		if !ok || s.Item == nil {
			continue
		}
		b, ok := s.Item.Value.([]byte)
		if !ok {
			continue
		}
		params, signature = m.List, b
		break
	}
	if params == nil {
		return nil, sigErr("no signature with a keyid")
	}
	// 3. Covered components and parameters.
	components := make([]string, 0, len(params.Items))
	for _, it := range params.Items {
		name, ok := it.Value.(string)
		if !ok || len(it.Params) > 0 {
			return nil, sigErr("unsupported component identifier %s", it.String())
		}
		components = append(components, name)
	}
	for _, req := range RequiredSignatureComponents {
		if !contains(components, req) {
			return nil, sigErr("required component %q not covered", req)
		}
	}
	createdV, ok := params.Params.Get("created")
	created, isInt := createdV.(int64)
	if !ok || !isInt {
		return nil, sigErr("signature has no integer created parameter")
	}
	keyidV, _ := params.Params.Get("keyid")
	keyid, ok := keyidV.(string)
	if !ok || keyid == "" {
		return nil, sigErr("signature keyid must be a string")
	}
	now := v.opts.Clock()
	createdAt := time.Unix(created, 0)
	if createdAt.Before(now.Add(-v.opts.MaxAge)) {
		return nil, sigErr("signature too old")
	}
	if createdAt.After(now.Add(v.opts.ClockSkew)) {
		return nil, sigErr("signature created in the future")
	}
	if expV, ok := params.Params.Get("expires"); ok {
		if exp, isInt := expV.(int64); !isInt || time.Unix(exp, 0).Before(now) {
			return nil, sigErr("signature expired")
		}
	}
	// 4. keyid → storage identifier.
	hash := strings.IndexByte(keyid, '#')
	if hash < 0 || hash == len(keyid)-1 {
		return nil, sigErr("keyid %q has no fragment", keyid)
	}
	storageID := keyid[:hash]
	if len(v.opts.TrustedStorages) > 0 && !contains(v.opts.TrustedStorages, storageID) {
		return nil, sigErr("storage %s is not trusted", storageID)
	}
	// 7. Signature base.
	base, err := signatureBase(components, params, method, target, header)
	if err != nil {
		return nil, err
	}
	algV, hasAlg := params.Params.Get("alg")
	alg, _ := algV.(string)
	if hasAlg && alg == "" {
		return nil, sigErr("alg parameter must be a string")
	}
	// 5./6./8. Resolve the key and verify, refetching once on failure with a
	// cached description (key rotation).
	for attempt := 0; attempt < 2; attempt++ {
		sd, cached, err := v.description(ctx, storageID, attempt > 0)
		if err != nil {
			return nil, err
		}
		pub, err := webhookKey(sd, storageID, keyid, alg)
		if err == nil && verifyRaw(pub, []byte(base), signature) {
			n, err := ParseNotification(body)
			if err != nil {
				return nil, &SignatureVerificationError{Reason: "invalid notification", Err: err}
			}
			if n.Storage != storageID {
				return nil, sigErr("notification storage %q does not match keyid storage %q", n.Storage, storageID)
			}
			return &VerifiedNotification{Notification: n, KeyID: keyid, Storage: storageID}, nil
		}
		if !cached {
			if err != nil {
				return nil, err
			}
			return nil, sigErr("signature mismatch")
		}
	}
	return nil, sigErr("signature mismatch")
}

// description returns the storage description for id; fresh forces a
// refetch. cached reports whether the result came from the cache.
func (v *WebhookVerifier) description(ctx context.Context, id string, fresh bool) (*StorageDescription, bool, error) {
	now := v.opts.Clock()
	if !fresh {
		v.mu.Lock()
		c, ok := v.cache[id]
		v.mu.Unlock()
		if ok && now.Sub(c.fetched) < v.opts.KeyCacheTTL {
			return c.sd, true, nil
		}
	}
	sd, err := v.opts.FetchStorageDescription(ctx, id)
	if err != nil {
		return nil, false, &SignatureVerificationError{Reason: "fetching storage description", Err: err}
	}
	if sd.ID != id {
		return nil, false, sigErr("storage description id %q does not match %q", sd.ID, id)
	}
	v.mu.Lock()
	v.cache[id] = cachedDescription{sd: sd, fetched: now}
	v.mu.Unlock()
	return sd, false, nil
}

// webhookKey finds the authentication verification method for keyid and
// checks the alg parameter against its key type.
func webhookKey(sd *StorageDescription, storageID, keyid, alg string) (any, error) {
	vm, ok := sd.VerificationMethod(keyid)
	if !ok {
		vm, ok = sd.VerificationMethod(keyid[strings.IndexByte(keyid, '#'):])
	}
	if !ok {
		return nil, sigErr("verification method %s not found", keyid)
	}
	if !sd.IsAuthenticationMethod(vm.ID) {
		return nil, sigErr("key %s is not authorized for authentication", keyid)
	}
	if vm.PublicKeyJWK == nil {
		return nil, sigErr("verification method %s has no publicKeyJwk", keyid)
	}
	pub, err := vm.PublicKeyJWK.PublicKey()
	if err != nil {
		return nil, &SignatureVerificationError{Reason: "invalid public key", Err: err}
	}
	want := ""
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			want = "ecdsa-p256-sha256"
		} else {
			want = "ecdsa-p384-sha384"
		}
	case ed25519.PublicKey:
		want = "ed25519"
	}
	if alg != "" && alg != want {
		return nil, sigErr("alg %q does not match key (%s)", alg, want)
	}
	return pub, nil
}

// signatureBase builds the RFC 9421 signature base.
func signatureBase(components []string, params *SFInnerList, method string, target *url.URL, header http.Header) (string, error) {
	var b strings.Builder
	for _, c := range components {
		var value string
		switch c {
		case "@method":
			value = strings.ToUpper(method)
		case "@scheme":
			value = strings.ToLower(target.Scheme)
		case "@authority":
			value = authority(target)
		case "@path":
			value = target.EscapedPath()
			if value == "" {
				value = "/"
			}
		case "@query":
			value = "?" + target.RawQuery
		case "@target-uri":
			value = target.String()
		default:
			if strings.HasPrefix(c, "@") {
				return "", sigErr("unsupported derived component %q", c)
			}
			vals := header.Values(c)
			if len(vals) == 0 {
				return "", sigErr("covered header %q is missing", c)
			}
			for i := range vals {
				vals[i] = strings.TrimSpace(vals[i])
			}
			value = strings.Join(vals, ", ")
		}
		b.WriteString(quoteString(c))
		b.WriteString(": ")
		b.WriteString(value)
		b.WriteByte('\n')
	}
	b.WriteString(`"@signature-params": `)
	b.WriteString(params.String())
	return b.String(), nil
}

func authority(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	scheme := strings.ToLower(u.Scheme)
	if port == "" || (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return host
	}
	return host + ":" + port
}

// verifyContentDigest checks every recognised (sha-256, sha-512) digest.
func verifyContentDigest(header http.Header, body []byte) error {
	values := header.Values("Content-Digest")
	if len(values) == 0 {
		return sigErr("missing Content-Digest")
	}
	dict, err := ParseSFDictionary(strings.Join(values, ", "))
	if err != nil {
		return &SignatureVerificationError{Reason: "malformed Content-Digest", Err: err}
	}
	recognised := 0
	for _, m := range dict {
		var sum []byte
		switch m.Name {
		case "sha-256":
			h := sha256.Sum256(body)
			sum = h[:]
		case "sha-512":
			h := sha512.Sum512(body)
			sum = h[:]
		default:
			continue
		}
		recognised++
		if m.Item == nil {
			return sigErr("malformed Content-Digest")
		}
		got, ok := m.Item.Value.([]byte)
		if !ok || subtle.ConstantTimeCompare(got, sum) != 1 {
			return sigErr("content-digest mismatch")
		}
	}
	if recognised == 0 {
		return sigErr("no supported Content-Digest algorithm")
	}
	return nil
}

// ContentDigest computes a Content-Digest header value (sha-256) for body.
func ContentDigest(body []byte) string {
	h := sha256.Sum256(body)
	return SFDictionary{{Name: "sha-256", Item: &SFItem{Value: h[:]}}}.String()
}

// String serialises the dictionary canonically.
func (d SFDictionary) String() string {
	var b bytes.Buffer
	for i, m := range d {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(m.Name)
		switch {
		case m.List != nil:
			b.WriteByte('=')
			b.WriteString(m.List.String())
		case m.Item != nil:
			if v, ok := m.Item.Value.(bool); ok && v {
				b.WriteString(m.Item.Params.String())
			} else {
				b.WriteByte('=')
				b.WriteString(m.Item.String())
			}
		}
	}
	return b.String()
}
