// SPDX-License-Identifier: MIT

package lws

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// CredentialContext tells a CredentialProvider which authorization server
// the subject token is for.
type CredentialContext struct {
	// Issuer is the authorization server identifier (the audience of a
	// self-signed credential).
	Issuer string
	// Realm is the protection scope being accessed.
	Realm    string
	Metadata *AuthorizationServerMetadata
}

// CredentialProvider supplies subject tokens (LWS authentication
// credentials) for the token exchange. Implementations must be safe for
// concurrent use.
type CredentialProvider interface {
	// TokenType is the subject_token_type URI of the authentication suite.
	TokenType() string
	// SubjectToken returns an authentication credential for cc.Issuer.
	SubjectToken(ctx context.Context, cc CredentialContext) (string, error)
}

// CredentialFunc returns a subject token for an authorization server.
type CredentialFunc func(ctx context.Context, cc CredentialContext) (string, error)

// OpenIDCredentials provides OpenID Connect ID tokens
// (lws10-authn-openid, token type urn:ietf:params:oauth:token-type:id_token).
// Obtaining the ID token (the interactive login) is up to the application's
// OpenID Connect library.
type OpenIDCredentials struct{ fn CredentialFunc }

// NewOpenIDCredentials wraps a fixed ID token.
func NewOpenIDCredentials(idToken string) *OpenIDCredentials {
	return &OpenIDCredentials{fn: func(context.Context, CredentialContext) (string, error) { return idToken, nil }}
}

// NewOpenIDCredentialsFunc wraps a function returning a fresh ID token.
func NewOpenIDCredentialsFunc(fn CredentialFunc) *OpenIDCredentials {
	return &OpenIDCredentials{fn: fn}
}

// TokenType implements CredentialProvider.
func (c *OpenIDCredentials) TokenType() string { return TokenTypeIDToken }

// SubjectToken implements CredentialProvider.
func (c *OpenIDCredentials) SubjectToken(ctx context.Context, cc CredentialContext) (string, error) {
	return c.fn(ctx, cc)
}

// SAMLCredentials provides SAML 2.0 assertions (lws10-authn-saml, token type
// urn:ietf:params:oauth:token-type:saml2). Tokens are base64url-encoded
// assertions; see EncodeSAMLAssertion.
type SAMLCredentials struct{ fn CredentialFunc }

// NewSAMLCredentials wraps a fixed, base64url-encoded assertion.
func NewSAMLCredentials(encodedAssertion string) *SAMLCredentials {
	return &SAMLCredentials{fn: func(context.Context, CredentialContext) (string, error) { return encodedAssertion, nil }}
}

// NewSAMLCredentialsFunc wraps a function returning a base64url-encoded
// assertion.
func NewSAMLCredentialsFunc(fn CredentialFunc) *SAMLCredentials { return &SAMLCredentials{fn: fn} }

// EncodeSAMLAssertion base64url-encodes a SAML assertion XML document for use
// as a subject token (RFC 8693 section 3).
func EncodeSAMLAssertion(xml []byte) string { return base64.RawURLEncoding.EncodeToString(xml) }

// TokenType implements CredentialProvider.
func (c *SAMLCredentials) TokenType() string { return TokenTypeSAML2 }

// SubjectToken implements CredentialProvider.
func (c *SAMLCredentials) SubjectToken(ctx context.Context, cc CredentialContext) (string, error) {
	return c.fn(ctx, cc)
}

// SelfSignedOptions configures SelfSignedCredentials.
type SelfSignedOptions struct {
	// Lifetime of each credential (default 5 minutes).
	Lifetime time.Duration
	// Clock returns the current time (default time.Now).
	Clock func() time.Time
}

// SelfSignedCredentials signs its own JWT credentials
// (lws10-authn-ssi-cid; token type urn:ietf:params:oauth:token-type:jwt).
// The claims sub, iss and client_id are the agent URI, aud is the
// authorization server. Supported keys: ECDSA P-256 (ES256) and Ed25519
// (EdDSA). Credentials are cached per audience until shortly before expiry.
type SelfSignedCredentials struct {
	agent    string
	kid      string
	key      crypto.Signer
	alg      string
	lifetime time.Duration
	clock    func() time.Time

	mu    sync.Mutex
	cache map[string]cachedJWT
}

type cachedJWT struct {
	token string
	exp   time.Time
}

// NewSelfSignedCredentials returns credentials for an agent (an HTTPS URI
// or DID) whose controlled identifier document lists key under kid. kid is
// placed in the JWT header (see NewControlledIdentifierDocument).
func NewSelfSignedCredentials(agent string, key crypto.Signer, kid string, opts *SelfSignedOptions) (*SelfSignedCredentials, error) {
	if agent == "" {
		return nil, errors.New("lws: agent URI required")
	}
	alg, err := JWSAlgorithm(key.Public())
	if err != nil {
		return nil, err
	}
	if alg == "ES384" {
		return nil, errors.New("lws: self-signed credentials support ES256 and EdDSA keys")
	}
	s := &SelfSignedCredentials{agent: agent, kid: kid, key: key, alg: alg, lifetime: 5 * time.Minute, clock: time.Now, cache: map[string]cachedJWT{}}
	if opts != nil {
		if opts.Lifetime > 0 {
			s.lifetime = opts.Lifetime
		}
		if opts.Clock != nil {
			s.clock = opts.Clock
		}
	}
	return s, nil
}

// NewDIDKeyCredentials returns self-signed credentials whose agent identifier
// is the did:key derived from key; the kid is the did:key verification
// method ("did:key:z…#z…").
func NewDIDKeyCredentials(key crypto.Signer, opts *SelfSignedOptions) (*SelfSignedCredentials, error) {
	did, err := DIDKeyFromPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	return NewSelfSignedCredentials(did, key, DIDKeyVerificationMethod(did), opts)
}

// Agent returns the agent URI used as sub, iss and client_id.
func (s *SelfSignedCredentials) Agent() string { return s.agent }

// KeyID returns the kid placed in the JWT header.
func (s *SelfSignedCredentials) KeyID() string { return s.kid }

// Algorithm returns the JWS algorithm ("ES256" or "EdDSA").
func (s *SelfSignedCredentials) Algorithm() string { return s.alg }

// TokenType implements CredentialProvider.
func (s *SelfSignedCredentials) TokenType() string { return TokenTypeJWT }

// SubjectToken implements CredentialProvider: a JWT for cc.Issuer.
func (s *SelfSignedCredentials) SubjectToken(_ context.Context, cc CredentialContext) (string, error) {
	return s.Token(cc.Issuer)
}

// Token returns a (cached) signed credential whose audience is audience.
func (s *SelfSignedCredentials) Token(audience string) (string, error) {
	now := s.clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	// Reuse a cached credential until 60 s before it expires (or half its
	// lifetime, for short lifetimes).
	margin := 60 * time.Second
	if s.lifetime < 2*margin {
		margin = s.lifetime / 2
	}
	if c, ok := s.cache[audience]; ok && now.Add(margin).Before(c.exp) {
		return c.token, nil
	}
	iat := now.Unix()
	exp := now.Add(s.lifetime)
	claims := map[string]any{
		"sub":       s.agent,
		"iss":       s.agent,
		"client_id": s.agent,
		"aud":       []string{audience},
		"iat":       iat,
		"exp":       exp.Unix(),
		"jti":       newUUID(),
	}
	header := map[string]any{"typ": "JWT"}
	if s.kid != "" {
		header["kid"] = s.kid
	}
	token, err := SignJWT(header, claims, s.key)
	if err != nil {
		return "", err
	}
	s.cache[audience] = cachedJWT{token: token, exp: time.Unix(exp.Unix(), 0)}
	return token, nil
}
