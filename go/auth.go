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

func sameHostPort(a, b *url.URL) bool {
	return strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
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
	// Realm is the protection scope (the token's audience).
	Realm string
}

// TokenExchangeOptions configures a TokenExchangeAuthenticator.
type TokenExchangeOptions struct {
	// HTTPClient is used for metadata and token requests (default: a client
	// with a 30 s timeout). The authenticator uses a copy that never follows a
	// redirect: a 307 or 308 from the authorization server would carry the
	// subject token, a credential, on to wherever it points.
	HTTPClient *http.Client
	// AllowInsecureHTTP permits plain-http authorization servers on
	// non-loopback hosts. Loopback hosts are always allowed.
	AllowInsecureHTTP bool
	// AuthorizationServerFilter, if set, must approve every authorization
	// server (as_uri) before credentials are sent to it.
	AuthorizationServerFilter func(asURI, realm string) bool
	// Clock returns the current time (default time.Now).
	Clock func() time.Time
}

// TokenExchangeAuthenticator implements the LWS authorization flow: on a 401
// with an LWS Bearer challenge it validates the realm, fetches the
// authorization server metadata, exchanges a subject token from its
// CredentialProvider for an access token (OAuth 2.0 Token Exchange) and
// retries. Access tokens are cached per (issuer, realm) and sent proactively
// to URLs inside a cached realm. Concurrent exchanges for the same realm are
// coalesced.
type TokenExchangeAuthenticator struct {
	provider CredentialProvider
	opts     TokenExchangeOptions
	hc       *http.Client

	mu       sync.Mutex
	metadata map[string]*AuthorizationServerMetadata
	tokens   map[tokenKey]*AccessToken
	inflight map[tokenKey]*flight
}

type tokenKey struct{ issuer, realm string }

type flight struct {
	done  chan struct{}
	token *AccessToken
	err   error
}

// NewTokenExchangeAuthenticator returns an authenticator using provider for
// subject tokens. opts may be nil.
func NewTokenExchangeAuthenticator(provider CredentialProvider, opts *TokenExchangeOptions) *TokenExchangeAuthenticator {
	a := &TokenExchangeAuthenticator{
		provider: provider,
		metadata: map[string]*AuthorizationServerMetadata{},
		tokens:   map[tokenKey]*AccessToken{},
		inflight: map[tokenKey]*flight{},
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

// tokenFor returns the cached token whose realm contains u (the most
// specific realm wins).
func (a *TokenExchangeAuthenticator) tokenFor(u *url.URL) *AccessToken {
	target := u.String()
	a.mu.Lock()
	defer a.mu.Unlock()
	var best *AccessToken
	for k, t := range a.tokens {
		if !a.valid(t) || !RealmContains(k.realm, target) {
			continue
		}
		if best == nil || len(k.realm) > len(best.Realm) {
			best = t
		}
	}
	return best
}

func (a *TokenExchangeAuthenticator) hasCredentials(u *url.URL) bool { return a.tokenFor(u) != nil }

// Authorize implements Authenticator: it sends a cached token to URLs inside
// its realm.
func (a *TokenExchangeAuthenticator) Authorize(_ context.Context, req *http.Request) error {
	if t := a.tokenFor(req.URL); t != nil {
		req.Header.Set("Authorization", "Bearer "+t.Value)
	}
	return nil
}

// HandleChallenge implements Authenticator.
func (a *TokenExchangeAuthenticator) HandleChallenge(ctx context.Context, req *http.Request, resp *http.Response) (bool, error) {
	var ch *Challenge
	for _, c := range ParseChallenges(resp.Header.Values("WWW-Authenticate")...) {
		if c.IsBearer() && c.AsURI() != "" && c.Realm() != "" {
			ch = &c
			break
		}
	}
	if ch == nil {
		return false, nil
	}
	// A challenge is acted on only once it checks out: one whose realm does not
	// contain the URL (a decoy) must not cost the client its token.
	if err := a.checkChallenge(ch.AsURI(), ch.Realm(), req.URL.String()); err != nil {
		return false, err
	}
	// A rejected token is dropped from the cache.
	if sent := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "); sent != "" && sent != req.Header.Get("Authorization") {
		a.mu.Lock()
		for k, t := range a.tokens {
			if t.Value == sent {
				delete(a.tokens, k)
			}
		}
		a.mu.Unlock()
	}
	if _, err := a.Exchange(ctx, ch.AsURI(), ch.Realm(), req.URL.String()); err != nil {
		return false, err
	}
	return true, nil
}

// Exchange obtains (or returns a cached) access token from the authorization
// server asURI for realm. target is the URL being accessed; it must be inside
// the realm (pass "" to skip that check).
func (a *TokenExchangeAuthenticator) Exchange(ctx context.Context, asURI, realm, target string) (*AccessToken, error) {
	if err := a.checkChallenge(asURI, realm, target); err != nil {
		return nil, err
	}
	key := tokenKey{asURI, realm}
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

	f.token, f.err = a.exchange(ctx, asURI, realm)

	a.mu.Lock()
	delete(a.inflight, key)
	if f.err == nil {
		a.tokens[key] = f.token
	}
	a.mu.Unlock()
	close(f.done)
	return f.token, f.err
}

// checkChallenge applies the checks a challenge must pass before the client
// acts on it: target (when given) is inside realm, the authorization server is
// https (or loopback, or allowed by AllowInsecureHTTP), and the policy filter
// accepts it.
func (a *TokenExchangeAuthenticator) checkChallenge(asURI, realm, target string) error {
	if target != "" && !RealmContains(realm, target) {
		return authErr("request URL %s is not within realm %s", target, realm)
	}
	as, err := url.Parse(asURI)
	if err != nil || as.Scheme == "" || as.Host == "" {
		return authErr("invalid authorization server URI %q", asURI)
	}
	if !strings.EqualFold(as.Scheme, "https") && !a.opts.AllowInsecureHTTP && !isLoopbackHost(as.Hostname()) {
		return authErr("refusing insecure authorization server %s", asURI)
	}
	if f := a.opts.AuthorizationServerFilter; f != nil && !f(asURI, realm) {
		return authErr("authorization server %s rejected by policy", asURI)
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

// ClearTokens forgets every cached access token.
func (a *TokenExchangeAuthenticator) ClearTokens() {
	a.mu.Lock()
	a.tokens = map[tokenKey]*AccessToken{}
	a.mu.Unlock()
}

func (a *TokenExchangeAuthenticator) exchange(ctx context.Context, asURI, realm string) (*AccessToken, error) {
	md, err := a.Metadata(ctx, asURI)
	if err != nil {
		return nil, err
	}
	te, err := url.Parse(md.TokenEndpoint)
	if err != nil || te.Scheme == "" || te.Host == "" {
		return nil, authErr("invalid token endpoint %q", md.TokenEndpoint)
	}
	if !strings.EqualFold(te.Scheme, "https") && !a.opts.AllowInsecureHTTP && !isLoopbackHost(te.Hostname()) {
		return nil, authErr("refusing insecure token endpoint %s", md.TokenEndpoint)
	}
	tokenType := a.provider.TokenType()
	if len(md.SubjectTokenTypesSupported) > 0 && !contains(md.SubjectTokenTypesSupported, tokenType) {
		return nil, authErr("authorization server %s does not accept subject tokens of type %s", asURI, tokenType)
	}
	subject, err := a.provider.SubjectToken(ctx, CredentialContext{Issuer: md.Issuer, Realm: realm, Metadata: md})
	if err != nil {
		return nil, &AuthenticationError{Message: "credential provider failed", Err: err}
	}
	tr, err := ExchangeToken(ctx, a.hc, md.TokenEndpoint, realm, subject, tokenType)
	if err != nil {
		return nil, err
	}
	expires := tokenExpiry(tr, a.opts.Clock())
	return &AccessToken{Value: tr.AccessToken, Type: tr.TokenType, ExpiresAt: expires, Issuer: asURI, Realm: realm}, nil
}

// FetchAuthorizationServerMetadata retrieves and validates the metadata of
// issuer. The document's issuer must equal issuer (ignoring a trailing "/").
func FetchAuthorizationServerMetadata(ctx context.Context, hc *http.Client, issuer string) (*AuthorizationServerMetadata, error) {
	mdURL, err := AuthorizationServerMetadataURL(issuer)
	if err != nil {
		return nil, &AuthenticationError{Message: "invalid issuer", Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mdURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", MediaJSON)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, &AuthenticationError{Message: "fetching authorization server metadata", Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &AuthenticationError{Message: "authorization server metadata " + mdURL + " returned " + resp.Status, StatusCode: resp.StatusCode}
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
// tokenEndpoint for resource (the realm). Error responses are returned as
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
