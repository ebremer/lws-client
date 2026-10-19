// SPDX-License-Identifier: MIT

package lws

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Authenticator adds credentials to requests. Implementations must be safe
// for concurrent use.
type Authenticator interface {
	// Authorize is called before a request is sent and may add credentials
	// (typically an Authorization header). It is also called again for
	// redirected requests, after the Authorization header has been removed.
	Authorize(ctx context.Context, req *http.Request) error
	// HandleChallenge is called when a response has status 401. It may obtain
	// credentials and returns true if the request should be retried (once).
	HandleChallenge(ctx context.Context, req *http.Request, resp *http.Response) (retry bool, err error)
}

// credentialChecker is implemented by authenticators that can tell whether a
// request would be sent with credentials.
type credentialChecker interface {
	hasCredentials(u *url.URL) bool
}

// BearerTokenAuthenticator sends a known access token.
type BearerTokenAuthenticator struct {
	token  string
	source func(ctx context.Context) (string, error)
	realm  string
}

// NewBearerTokenAuthenticator returns an authenticator that sends token as
// "Authorization: Bearer <token>". If realm is not empty, the token is only
// sent to URLs inside that realm (see RealmContains).
func NewBearerTokenAuthenticator(token, realm string) *BearerTokenAuthenticator {
	return &BearerTokenAuthenticator{token: token, realm: realm}
}

// NewBearerTokenSource returns an authenticator that calls source for the
// token before every request (e.g. to refresh it).
func NewBearerTokenSource(source func(ctx context.Context) (string, error), realm string) *BearerTokenAuthenticator {
	return &BearerTokenAuthenticator{source: source, realm: realm}
}

// Authorize implements Authenticator.
func (a *BearerTokenAuthenticator) Authorize(ctx context.Context, req *http.Request) error {
	if a.realm != "" && !RealmContains(a.realm, req.URL.String()) {
		return nil
	}
	token := a.token
	if a.source != nil {
		t, err := a.source(ctx)
		if err != nil {
			return &AuthenticationError{Message: "token source failed", Err: err}
		}
		token = t
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return nil
}

// HandleChallenge implements Authenticator; a static token cannot be renewed.
func (a *BearerTokenAuthenticator) HandleChallenge(context.Context, *http.Request, *http.Response) (bool, error) {
	return false, nil
}

// RealmContains reports whether target is logically contained in realm: the
// same scheme, host and port, and a path equal to the realm path or below it
// (the realm path is treated as a directory).
func RealmContains(realm, target string) bool {
	r, err := url.Parse(realm)
	if err != nil {
		return false
	}
	t, err := url.Parse(target)
	if err != nil {
		return false
	}
	if !strings.EqualFold(r.Scheme, t.Scheme) || !sameHostPort(r, t) {
		return false
	}
	rp, tp := r.EscapedPath(), t.EscapedPath()
	if rp == "" {
		rp = "/"
	}
	if tp == "" {
		tp = "/"
	}
	if tp == rp {
		return true
	}
	if !strings.HasSuffix(rp, "/") {
		rp += "/"
	}
	return strings.HasPrefix(tp, rp)
}

// SameOrigin reports whether two absolute URLs have the same scheme and
// authority: scheme and host compared case-insensitively, the port after the
// scheme's default is applied. Before it asks for a token, a client checks
// this of the protected resource metadata URL and of the storage root against
// the URL that drew the 401 (lws10-core "Discovery Validation by a Client").
func SameOrigin(a, b string) bool {
	oa, _, _, ok := splitURL(a)
	ob, _, _, ok2 := splitURL(b)
	return ok && ok2 && oa == ob
}

// SameResource reports whether the resource of protected resource metadata
// is identical to the URL requested (RFC 9728 section 3.3): compared after
// lower-casing scheme and host and dropping a default port on both, and
// nothing else, so that a trailing slash, the case of the path or its
// percent-encoding tell two resources apart.
func SameResource(requested, resource string) bool {
	oa, ua, ra, ok := splitURL(requested)
	ob, ub, rb, ok2 := splitURL(resource)
	return ok && ok2 && oa == ob && ua == ub && ra == rb
}

// splitURL splits an absolute URL as written into its origin
// ("scheme://host:port", scheme and host lower-cased, the port explicit), its
// user information and the rest (path, query and fragment, as written). ok is
// false for a URL without a scheme or an authority.
func splitURL(s string) (origin, userinfo, rest string, ok bool) {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", "", "", false
	}
	// url.Parse found "scheme://": the authority runs from there to the path,
	// query or fragment.
	authority := s[len(u.Scheme)+len("://"):]
	if i := strings.IndexAny(authority, "/?#"); i >= 0 {
		authority, rest = authority[:i], authority[i:]
	}
	if i := strings.LastIndexByte(authority, '@'); i >= 0 {
		userinfo, authority = authority[:i+1], authority[i+1:]
	}
	host, port := authority, ""
	if i := strings.LastIndexByte(authority, ':'); i >= 0 && !strings.Contains(authority[i:], "]") {
		host, port = authority[:i], authority[i+1:]
	}
	if port == "" {
		port = defaultPort(u.Scheme)
	}
	return u.Scheme + "://" + strings.ToLower(host) + ":" + port, userinfo, rest, true
}

func sameHostPort(a, b *url.URL) bool {
	return strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return defaultPort(u.Scheme)
}

func defaultPort(scheme string) string {
	switch strings.ToLower(scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ProtectedResourceMetadata is the OAuth 2.0 protected resource metadata
// (RFC 9728) of a resource, named by the resource_metadata parameter of a
// 401's Bearer challenge.
type ProtectedResourceMetadata struct {
	// Resource identifies the resource the metadata describes: the requested
	// URL, not the storage that holds it.
	Resource string `json:"resource"`
	// AuthorizationServers lists the issuers of the authorization servers that
	// grant access to the resource, in order (at least one).
	AuthorizationServers []string `json:"authorization_servers"`
	// Raw is the original metadata document.
	Raw json.RawMessage `json:"-"`
}

// ParseProtectedResourceMetadata parses protected resource metadata. It fails
// with an *AuthenticationError unless the document is a JSON object with a
// string "resource" (RFC 9728) and a non-empty array of strings
// "authorization_servers" (which lws10-core makes required).
func ParseProtectedResourceMetadata(data []byte) (*ProtectedResourceMetadata, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil || doc == nil {
		return nil, &AuthenticationError{Message: "protected resource metadata is not a JSON object", Err: err}
	}
	md := &ProtectedResourceMetadata{Raw: append(json.RawMessage(nil), data...)}
	if json.Unmarshal(doc["resource"], &md.Resource) != nil || md.Resource == "" {
		return nil, authErr("protected resource metadata has no resource")
	}
	if json.Unmarshal(doc["authorization_servers"], &md.AuthorizationServers) != nil || len(md.AuthorizationServers) == 0 {
		return nil, authErr("protected resource metadata names no authorization server")
	}
	return md, nil
}

// FetchProtectedResourceMetadata retrieves and parses the protected resource
// metadata at metadataURL. hc should not follow redirects (the
// TokenExchangeAuthenticator's does not): anything but a 200 is an
// *AuthenticationError.
func FetchProtectedResourceMetadata(ctx context.Context, hc *http.Client, metadataURL string) (*ProtectedResourceMetadata, error) {
	body, err := fetchDocument(ctx, hc, metadataURL, MediaJSON, "protected resource metadata")
	if err != nil {
		return nil, err
	}
	return ParseProtectedResourceMetadata(body)
}

// AuthorizationServerMetadata is the RFC 8414 metadata published by an LWS
// authorization server at /.well-known/lws-configuration.
type AuthorizationServerMetadata struct {
	Issuer                          string   `json:"issuer"`
	TokenEndpoint                   string   `json:"token_endpoint"`
	JWKSURI                         string   `json:"jwks_uri,omitempty"`
	GrantTypesSupported             []string `json:"grant_types_supported,omitempty"`
	ClaimsSupported                 []string `json:"claims_supported,omitempty"`
	ResponseTypesSupported          []string `json:"response_types_supported,omitempty"`
	SubjectTokenTypesSupported      []string `json:"subject_token_types_supported,omitempty"`
	SubjectIdentifierTypesSupported []string `json:"subject_identifier_types_supported,omitempty"`
	// Raw is the original metadata document.
	Raw json.RawMessage `json:"-"`
}

// AuthorizationServerMetadataURL derives the metadata URL for an issuer
// (RFC 8414 section 3.1): the well-known path is inserted between the host
// and any issuer path.
func AuthorizationServerMetadataURL(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("lws: issuer %q is not an absolute URL", issuer)
	}
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	m := &url.URL{Scheme: u.Scheme, Host: u.Host}
	m, err = m.Parse(WellKnownLWSConfiguration + path)
	if err != nil {
		return "", err
	}
	return m.String(), nil
}

// AccessToken is an access token issued by an authorization server.
type AccessToken struct {
	Value     string
	Type      string
	ExpiresAt time.Time
	// Issuer is the authorization server that issued the token.
	Issuer string
	// Storage is the storage the token is for (its audience).
	Storage string
	// Scope lists the URLs the token is sent to ahead of a 401, each with
	// everything below it: the storage and its root (for the LWS challenge of
	// the drafts before 19 October 2026, the realm). Elsewhere it is only sent
	// in the retry of a request whose 401 passed the checks.
	Scope []string
}

// TokenExchangeOptions configures a TokenExchangeAuthenticator.
type TokenExchangeOptions struct {
	// HTTPClient is used for metadata, storage description and token requests
	// (default: a client with a 30 s timeout). The authenticator uses a copy
	// that never follows a redirect: a 307 or 308 from the authorization
	// server would carry the subject token, a credential, on to wherever it
	// points.
	HTTPClient *http.Client
	// AllowInsecureHTTP permits plain-http authorization servers on
	// non-loopback hosts. Loopback hosts are always allowed.
	AllowInsecureHTTP bool
	// AuthorizationServerFilter, if set, must approve every authorization
	// server (its issuer) before credentials are sent to it; storage is the
	// storage the token would be for.
	AuthorizationServerFilter func(issuer, storage string) bool
	// Clock returns the current time (default time.Now).
	Clock func() time.Time
}

// TokenExchangeAuthenticator implements the LWS authorization flow
// (lws10-core "Authorization"). On a 401 whose Bearer challenge names
// protected resource metadata (RFC 9728) it checks what the 401 told it
// against the URL that drew it, as lws10-core requires before any token
// request: the metadata is on the requested origin and describes that URL,
// and the root of the storage the 401 links to is on that origin too. It then
// fetches the metadata of the first acceptable authorization server, exchanges
// a subject token from its CredentialProvider for an access token for the
// storage (OAuth 2.0 Token Exchange) and retries. The challenge of the drafts
// before 19 October 2026 (as_uri and realm, without resource_metadata) is
// still followed, after its realm check.
//
// Access tokens are cached per (issuer, storage) and sent proactively to URLs
// inside the storage or its root (for the older challenge, the realm); the
// retry after a 401 also carries the token to a URL outside them, which has
// just passed the checks, but later requests there get none up front.
// Concurrent exchanges for the same storage are coalesced. Metadata, storage
// description and token requests never follow a redirect. A 401 that fails a
// check costs the client nothing: no token is requested for it, and a cached
// token the request carried stays cached.
type TokenExchangeAuthenticator struct {
	provider CredentialProvider
	opts     TokenExchangeOptions
	hc       *http.Client

	mu           sync.Mutex
	metadata     map[string]*AuthorizationServerMetadata
	descriptions map[string]*StorageDescription
	tokens       map[tokenKey]*AccessToken
	inflight     map[tokenKey]*flight
}

type tokenKey struct{ issuer, storage string }

type flight struct {
	done  chan struct{}
	token *AccessToken
	err   error
}

// discovery is what a 401 names once it passes its checks: the authorization
// server to ask, the storage the token is for and the token's scope.
type discovery struct {
	issuer, storage string
	scope           []string
}

// retryGrant carries the token HandleChallenge obtained, and the URL whose
// 401 it answered, to the Authorize calls of that request's retry: the retry
// sends the token to that URL even outside the token's scope, as the URL has
// just passed the checks. The Client puts one in the context of each request
// it sends.
type retryGrant struct {
	url   string
	token *AccessToken
}

type retryGrantKey struct{}

func withRetryGrant(ctx context.Context) context.Context {
	return context.WithValue(ctx, retryGrantKey{}, &retryGrant{})
}

// NewTokenExchangeAuthenticator returns an authenticator using provider for
// subject tokens. opts may be nil.
func NewTokenExchangeAuthenticator(provider CredentialProvider, opts *TokenExchangeOptions) *TokenExchangeAuthenticator {
	a := &TokenExchangeAuthenticator{
		provider:     provider,
		metadata:     map[string]*AuthorizationServerMetadata{},
		descriptions: map[string]*StorageDescription{},
		tokens:       map[tokenKey]*AccessToken{},
		inflight:     map[tokenKey]*flight{},
	}
	if opts != nil {
		a.opts = *opts
	}
	hc := a.opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	// A copy, so that the caller's client keeps its own redirect policy.
	noRedirects := *hc
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	a.hc = &noRedirects
	if a.opts.Clock == nil {
		a.opts.Clock = time.Now
	}
	return a
}

const tokenRefreshMargin = 30 * time.Second

func (a *TokenExchangeAuthenticator) valid(t *AccessToken) bool {
	return t != nil && a.opts.Clock().Add(tokenRefreshMargin).Before(t.ExpiresAt)
}

// tokenFor returns the cached token whose scope contains u (where several
// do, the longest scope path wins).
func (a *TokenExchangeAuthenticator) tokenFor(u *url.URL) *AccessToken {
	target := u.String()
	a.mu.Lock()
	defer a.mu.Unlock()
	var best *AccessToken
	longest := -1
	for _, t := range a.tokens {
		if !a.valid(t) {
			continue
		}
		for _, s := range t.Scope {
			su, err := url.Parse(s)
			if err == nil && len(su.EscapedPath()) > longest && RealmContains(s, target) {
				best, longest = t, len(su.EscapedPath())
			}
		}
	}
	return best
}

func (a *TokenExchangeAuthenticator) hasCredentials(u *url.URL) bool { return a.tokenFor(u) != nil }

// Authorize implements Authenticator: it sends a cached token to URLs inside
// its scope, and in the retry after a 401, the token obtained for it to the
// URL that drew the 401.
func (a *TokenExchangeAuthenticator) Authorize(ctx context.Context, req *http.Request) error {
	t := a.tokenFor(req.URL)
	if g, ok := ctx.Value(retryGrantKey{}).(*retryGrant); ok && g.token != nil && g.url == req.URL.String() {
		t = g.token
	}
	if t != nil {
		req.Header.Set("Authorization", "Bearer "+t.Value)
	}
	return nil
}

// HandleChallenge implements Authenticator. A 401 without a Bearer challenge
// that has resource_metadata, or as_uri and realm, is left to the caller.
func (a *TokenExchangeAuthenticator) HandleChallenge(ctx context.Context, req *http.Request, resp *http.Response) (bool, error) {
	// The URL that drew the 401 is that of the last redirect, if any.
	if resp.Request != nil && resp.Request.URL != nil {
		req = resp.Request
	}
	challenges := ParseChallenges(resp.Header.Values("WWW-Authenticate")...)
	var d *discovery
	var err error
	if ch, ok := bearerChallenge(challenges, "resource_metadata"); ok {
		d, err = a.discover(ctx, req.URL, ch.ResourceMetadata(), resp.Header)
	} else if ch, ok := bearerChallenge(challenges, "as_uri", "realm"); ok {
		d, err = a.discoverRealm(req.URL, ch.AsURI(), ch.Realm())
	} else {
		return false, nil
	}
	if err == nil {
		// The authorization server's metadata is the last check.
		var md *AuthorizationServerMetadata
		if md, err = a.Metadata(ctx, d.issuer); err == nil {
			err = a.checkTransport(md.TokenEndpoint, "token endpoint")
		}
	}
	// A challenge is acted on only once it checks out: one that points
	// elsewhere (a decoy) must not cost the client its token.
	if err != nil {
		return false, err
	}
	// The cached token of this issuer and storage was rejected: drop it.
	key := tokenKey{d.issuer, d.storage}
	if sent, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer "); ok && sent != "" {
		a.mu.Lock()
		if t := a.tokens[key]; t != nil && t.Value == sent {
			delete(a.tokens, key)
		}
		a.mu.Unlock()
	}
	t, err := a.token(ctx, d)
	if err != nil {
		return false, err
	}
	if g, ok := ctx.Value(retryGrantKey{}).(*retryGrant); ok {
		g.url, g.token = req.URL.String(), t
	}
	return true, nil
}

// bearerChallenge returns the first Bearer challenge that has every one of
// params.
func bearerChallenge(challenges []Challenge, params ...string) (Challenge, bool) {
	for _, c := range challenges {
		ok := c.IsBearer()
		for _, p := range params {
			ok = ok && c.Params[p] != ""
		}
		if ok {
			return c, true
		}
	}
	return Challenge{}, false
}

// discover runs the checks of a 401 that names protected resource metadata
// (lws10-core "Discovery Validation by a Client"), in order: the metadata is
// on the requested origin, the 401 links to a storage, the metadata describes
// the URL requested, and the storage's root is on the requested origin. The
// issuer is the first of the metadata's authorization servers that passes
// checkIssuer.
func (a *TokenExchangeAuthenticator) discover(ctx context.Context, requested *url.URL, resourceMetadata string, header http.Header) (*discovery, error) {
	target := requested.String()
	mdURL := resolveRef(requested, resourceMetadata)
	if !SameOrigin(mdURL, target) {
		return nil, authErr("protected resource metadata %s is not on the origin of %s", mdURL, target)
	}
	link, ok := findLink(ParseLinkHeader(target, header.Values("Link")...), RelStorage)
	if !ok {
		return nil, authErr("the 401 of %s has no %s link", target, RelStorage)
	}
	storage := link.Href
	prm, err := FetchProtectedResourceMetadata(ctx, a.hc, mdURL)
	if err != nil {
		return nil, err
	}
	if !SameResource(target, prm.Resource) {
		return nil, authErr("protected resource metadata %s describes %s, not %s", mdURL, prm.Resource, target)
	}
	sd, err := a.storageDescription(ctx, storage)
	if err != nil {
		return nil, err
	}
	root, err := sd.StorageRoot()
	if err != nil {
		return nil, &AuthenticationError{Message: "storage " + storage + " has no root", Err: err}
	}
	if !SameOrigin(root, target) {
		return nil, authErr("the root %s of storage %s is not on the origin of %s", root, storage, target)
	}
	var first error
	for _, issuer := range prm.AuthorizationServers {
		err := a.checkIssuer(issuer, storage)
		if err == nil {
			return &discovery{issuer: issuer, storage: storage, scope: []string{storage, root}}, nil
		}
		if first == nil {
			first = err
		}
	}
	return nil, first
}

// discoverRealm runs the check of the LWS challenge of the drafts before 19
// October 2026: the realm contains the URL requested. as_uri is the issuer,
// and the realm is both the storage and the token's scope.
func (a *TokenExchangeAuthenticator) discoverRealm(requested *url.URL, asURI, realm string) (*discovery, error) {
	if !RealmContains(realm, requested.String()) {
		return nil, authErr("request URL %s is not within realm %s", requested, realm)
	}
	if err := a.checkIssuer(asURI, realm); err != nil {
		return nil, err
	}
	return &discovery{issuer: asURI, storage: realm, scope: []string{realm}}, nil
}

// storageDescription returns the (cached) description of storage, read with
// no credentials and no redirect.
func (a *TokenExchangeAuthenticator) storageDescription(ctx context.Context, storage string) (*StorageDescription, error) {
	a.mu.Lock()
	sd := a.descriptions[storage]
	a.mu.Unlock()
	if sd != nil {
		return sd, nil
	}
	body, err := fetchDocument(ctx, a.hc, storage, storageDescriptionAccept, "storage description")
	if err != nil {
		return nil, err
	}
	sd, err = ParseStorageDescription(body, storage)
	if err != nil {
		return nil, &AuthenticationError{Message: "malformed storage description " + storage, Err: err}
	}
	a.mu.Lock()
	a.descriptions[storage] = sd
	a.mu.Unlock()
	return sd, nil
}

// Exchange obtains (or returns a cached) access token from the authorization
// server issuer for storage, the token's audience. The token is sent
// proactively to URLs inside storage and inside each URL of scope. The issuer
// must pass the transport check and the AuthorizationServerFilter; the
// discovery checks of a 401 are HandleChallenge's, so the caller vouches for
// issuer and storage.
func (a *TokenExchangeAuthenticator) Exchange(ctx context.Context, issuer, storage string, scope ...string) (*AccessToken, error) {
	if err := a.checkIssuer(issuer, storage); err != nil {
		return nil, err
	}
	return a.token(ctx, &discovery{issuer: issuer, storage: storage, scope: append([]string{storage}, scope...)})
}

// token returns the cached token of d's issuer and storage, or exchanges one;
// concurrent exchanges for the same issuer and storage are coalesced.
func (a *TokenExchangeAuthenticator) token(ctx context.Context, d *discovery) (*AccessToken, error) {
	key := tokenKey{d.issuer, d.storage}
	a.mu.Lock()
	if t := a.tokens[key]; a.valid(t) {
		a.mu.Unlock()
		return t, nil
	}
	if f, ok := a.inflight[key]; ok {
		a.mu.Unlock()
		select {
		case <-f.done:
			return f.token, f.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f := &flight{done: make(chan struct{})}
	a.inflight[key] = f
	a.mu.Unlock()

	f.token, f.err = a.exchange(ctx, d)

	a.mu.Lock()
	delete(a.inflight, key)
	if f.err == nil {
		a.tokens[key] = f.token
	}
	a.mu.Unlock()
	close(f.done)
	return f.token, f.err
}

// checkIssuer applies the checks an authorization server must pass before
// credentials are sent to it: it is https (or loopback, or allowed by
// AllowInsecureHTTP), and the policy filter accepts it.
func (a *TokenExchangeAuthenticator) checkIssuer(issuer, storage string) error {
	if err := a.checkTransport(issuer, "authorization server"); err != nil {
		return err
	}
	if f := a.opts.AuthorizationServerFilter; f != nil && !f(issuer, storage) {
		return authErr("authorization server %s rejected by policy", issuer)
	}
	return nil
}

// checkTransport requires an absolute https URL, or a loopback host, unless
// AllowInsecureHTTP is set.
func (a *TokenExchangeAuthenticator) checkTransport(rawURL, what string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return authErr("invalid %s URI %q", what, rawURL)
	}
	if !strings.EqualFold(u.Scheme, "https") && !a.opts.AllowInsecureHTTP && !isLoopbackHost(u.Hostname()) {
		return authErr("refusing insecure %s %s", what, rawURL)
	}
	return nil
}

// Metadata returns the (cached) authorization server metadata of issuer.
func (a *TokenExchangeAuthenticator) Metadata(ctx context.Context, issuer string) (*AuthorizationServerMetadata, error) {
	a.mu.Lock()
	md := a.metadata[issuer]
	a.mu.Unlock()
	if md != nil {
		return md, nil
	}
	md, err := FetchAuthorizationServerMetadata(ctx, a.hc, issuer)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.metadata[issuer] = md
	a.mu.Unlock()
	return md, nil
}

// ClearTokens forgets every cached access token and storage description.
func (a *TokenExchangeAuthenticator) ClearTokens() {
	a.mu.Lock()
	a.tokens = map[tokenKey]*AccessToken{}
	a.descriptions = map[string]*StorageDescription{}
	a.mu.Unlock()
}

func (a *TokenExchangeAuthenticator) exchange(ctx context.Context, d *discovery) (*AccessToken, error) {
	md, err := a.Metadata(ctx, d.issuer)
	if err != nil {
		return nil, err
	}
	if err := a.checkTransport(md.TokenEndpoint, "token endpoint"); err != nil {
		return nil, err
	}
	tokenType := a.provider.TokenType()
	if len(md.SubjectTokenTypesSupported) > 0 && !contains(md.SubjectTokenTypesSupported, tokenType) {
		return nil, authErr("authorization server %s does not accept subject tokens of type %s", d.issuer, tokenType)
	}
	subject, err := a.provider.SubjectToken(ctx, CredentialContext{Issuer: md.Issuer, Storage: d.storage, Metadata: md})
	if err != nil {
		return nil, &AuthenticationError{Message: "credential provider failed", Err: err}
	}
	tr, err := ExchangeToken(ctx, a.hc, md.TokenEndpoint, d.storage, subject, tokenType)
	if err != nil {
		return nil, err
	}
	expires := tokenExpiry(tr, a.opts.Clock())
	return &AccessToken{Value: tr.AccessToken, Type: tr.TokenType, ExpiresAt: expires, Issuer: d.issuer, Storage: d.storage, Scope: d.scope}, nil
}

// fetchDocument GETs a discovery document (metadata or a storage
// description) with hc. Anything but a 200 is an *AuthenticationError.
func fetchDocument(ctx context.Context, hc *http.Client, rawURL, accept, what string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, &AuthenticationError{Message: "invalid " + what + " URL", Err: err}
	}
	req.Header.Set("Accept", accept)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, &AuthenticationError{Message: "fetching " + what, Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, &AuthenticationError{Message: "reading " + what, Err: err}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &AuthenticationError{Message: what + " " + rawURL + " returned " + resp.Status, StatusCode: resp.StatusCode}
	}
	return body, nil
}

// FetchAuthorizationServerMetadata retrieves and validates the metadata of
// issuer. The document's issuer must equal issuer (ignoring a trailing "/").
func FetchAuthorizationServerMetadata(ctx context.Context, hc *http.Client, issuer string) (*AuthorizationServerMetadata, error) {
	mdURL, err := AuthorizationServerMetadataURL(issuer)
	if err != nil {
		return nil, &AuthenticationError{Message: "invalid issuer", Err: err}
	}
	body, err := fetchDocument(ctx, hc, mdURL, MediaJSON, "authorization server metadata")
	if err != nil {
		return nil, err
	}
	var md AuthorizationServerMetadata
	if err := json.Unmarshal(body, &md); err != nil {
		return nil, &AuthenticationError{Message: "malformed authorization server metadata", Err: err}
	}
	md.Raw = body
	if strings.TrimSuffix(md.Issuer, "/") != strings.TrimSuffix(issuer, "/") {
		return nil, authErr("authorization server metadata issuer %q does not match %q", md.Issuer, issuer)
	}
	if md.TokenEndpoint == "" {
		return nil, authErr("authorization server metadata has no token_endpoint")
	}
	return &md, nil
}

// TokenResponse is an OAuth 2.0 token endpoint response (RFC 6749 §5.1).
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	Scope           string `json:"scope,omitempty"`
}

// ExchangeToken performs an OAuth 2.0 Token Exchange (RFC 8693) request at
// tokenEndpoint for resource (the storage). Error responses are returned as
// *AuthenticationError carrying the OAuth error code.
func ExchangeToken(ctx context.Context, hc *http.Client, tokenEndpoint, resource, subjectToken, subjectTokenType string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":         {GrantTypeTokenExchange},
		"resource":           {resource},
		"subject_token":      {subjectToken},
		"subject_token_type": {subjectTokenType},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", MediaForm)
	req.Header.Set("Accept", MediaJSON)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, &AuthenticationError{Message: "token request failed", Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var oe struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &oe)
		return nil, &AuthenticationError{
			Message:     "token exchange rejected with " + resp.Status,
			Code:        oe.Error,
			Description: oe.ErrorDescription,
			StatusCode:  resp.StatusCode,
		}
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, &AuthenticationError{Message: "malformed token response", Err: err}
	}
	if tr.AccessToken == "" {
		return nil, authErr("token response has no access_token")
	}
	if !strings.EqualFold(tr.TokenType, "Bearer") {
		return nil, authErr("unsupported token_type %q", tr.TokenType)
	}
	return &tr, nil
}

// tokenExpiry derives the expiry: expires_in, else the JWT "exp" claim, else
// five minutes.
func tokenExpiry(tr *TokenResponse, now time.Time) time.Time {
	if tr.ExpiresIn > 0 {
		return now.Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	if _, claims, err := DecodeJWT(tr.AccessToken); err == nil {
		if exp, ok := claims["exp"].(float64); ok && exp > 0 {
			return time.Unix(int64(exp), 0)
		}
	}
	return now.Add(5 * time.Minute)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
