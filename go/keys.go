// SPDX-License-Identifier: MIT

package lws

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// JWK is a JSON Web Key (RFC 7517) for the key types used by LWS: EC P-256
// (ES256), EC P-384 and OKP Ed25519 (EdDSA). D is only set for private keys.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// ParseJWK decodes a JWK from JSON.
func ParseJWK(data []byte) (*JWK, error) {
	var j JWK
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

// Public returns a copy of the key without private material.
func (j JWK) Public() JWK {
	j.D = ""
	return j
}

// GenerateP256Key generates an ECDSA P-256 key (for ES256).
func GenerateP256Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenerateEd25519Key generates an Ed25519 key (for EdDSA).
func GenerateEd25519Key() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

var b64u = base64.RawURLEncoding

func padTo(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

func curveByteLen(c elliptic.Curve) int { return (c.Params().BitSize + 7) / 8 }

// JWKFromPublicKey converts an *ecdsa.PublicKey (P-256/P-384) or an
// ed25519.PublicKey to a JWK.
func JWKFromPublicKey(pub crypto.PublicKey) (*JWK, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		crv, err := curveName(k.Curve)
		if err != nil {
			return nil, err
		}
		n := curveByteLen(k.Curve)
		return &JWK{Kty: "EC", Crv: crv, X: b64u.EncodeToString(padTo(k.X.Bytes(), n)), Y: b64u.EncodeToString(padTo(k.Y.Bytes(), n))}, nil
	case ed25519.PublicKey:
		return &JWK{Kty: "OKP", Crv: "Ed25519", X: b64u.EncodeToString(k)}, nil
	}
	return nil, fmt.Errorf("lws: unsupported public key type %T", pub)
}

// JWKFromPrivateKey converts an *ecdsa.PrivateKey or ed25519.PrivateKey to a
// private JWK (including "d").
func JWKFromPrivateKey(priv crypto.Signer) (*JWK, error) {
	j, err := JWKFromPublicKey(priv.Public())
	if err != nil {
		return nil, err
	}
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		j.D = b64u.EncodeToString(padTo(k.D.Bytes(), curveByteLen(k.Curve)))
	case ed25519.PrivateKey:
		j.D = b64u.EncodeToString(k.Seed())
	default:
		return nil, fmt.Errorf("lws: unsupported private key type %T", priv)
	}
	return j, nil
}

func curveName(c elliptic.Curve) (string, error) {
	switch c {
	case elliptic.P256():
		return "P-256", nil
	case elliptic.P384():
		return "P-384", nil
	}
	return "", errors.New("lws: unsupported elliptic curve")
}

func decodeB64u(s string) ([]byte, error) {
	return b64u.DecodeString(strings.TrimRight(s, "="))
}

// PublicKey returns the public key described by the JWK.
func (j *JWK) PublicKey() (crypto.PublicKey, error) {
	switch {
	case j.Kty == "EC" && (j.Crv == "P-256" || j.Crv == "P-384"):
		curve, ecdhCurve := elliptic.P256(), ecdh.P256()
		if j.Crv == "P-384" {
			curve, ecdhCurve = elliptic.P384(), ecdh.P384()
		}
		n := curveByteLen(curve)
		x, err := decodeB64u(j.X)
		if err != nil {
			return nil, fmt.Errorf("lws: bad JWK x: %w", err)
		}
		y, err := decodeB64u(j.Y)
		if err != nil {
			return nil, fmt.Errorf("lws: bad JWK y: %w", err)
		}
		if len(x) != n || len(y) != n {
			return nil, errors.New("lws: bad EC coordinate length")
		}
		point := append(append([]byte{4}, x...), y...)
		if _, err := ecdhCurve.NewPublicKey(point); err != nil {
			return nil, fmt.Errorf("lws: invalid EC public key: %w", err)
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
	case j.Kty == "OKP" && j.Crv == "Ed25519":
		x, err := decodeB64u(j.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("lws: bad Ed25519 public key")
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, fmt.Errorf("lws: unsupported JWK kty=%q crv=%q", j.Kty, j.Crv)
}

// PrivateKey returns the private key described by the JWK (which must
// include "d").
func (j *JWK) PrivateKey() (crypto.Signer, error) {
	if j.D == "" {
		return nil, errors.New("lws: JWK has no private key material")
	}
	d, err := decodeB64u(j.D)
	if err != nil {
		return nil, fmt.Errorf("lws: bad JWK d: %w", err)
	}
	pub, err := j.PublicKey()
	if err != nil {
		return nil, err
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		ecdhCurve := ecdh.P256()
		if k.Curve == elliptic.P384() {
			ecdhCurve = ecdh.P384()
		}
		priv, err := ecdhCurve.NewPrivateKey(padTo(d, curveByteLen(k.Curve)))
		if err != nil {
			return nil, fmt.Errorf("lws: invalid EC private key: %w", err)
		}
		want := append(append([]byte{4}, padTo(k.X.Bytes(), curveByteLen(k.Curve))...), padTo(k.Y.Bytes(), curveByteLen(k.Curve))...)
		if !bytes.Equal(priv.PublicKey().Bytes(), want) {
			return nil, errors.New("lws: JWK private key does not match its public key")
		}
		return &ecdsa.PrivateKey{PublicKey: *k, D: new(big.Int).SetBytes(d)}, nil
	case ed25519.PublicKey:
		if len(d) != ed25519.SeedSize {
			return nil, errors.New("lws: bad Ed25519 private key")
		}
		priv := ed25519.NewKeyFromSeed(d)
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), k) {
			return nil, errors.New("lws: JWK private key does not match its public key")
		}
		return priv, nil
	}
	return nil, errors.New("lws: unsupported key")
}

// did:key multicodec prefixes (unsigned varints).
var (
	multicodecP256    = []byte{0x80, 0x24} // p256-pub (0x1200)
	multicodecEd25519 = []byte{0xed, 0x01} // ed25519-pub (0xed)
)

// DIDKeyFromPublicKey returns the did:key identifier of a P-256
// (*ecdsa.PublicKey) or Ed25519 public key.
func DIDKeyFromPublicKey(pub crypto.PublicKey) (string, error) {
	var data []byte
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return "", errors.New("lws: did:key supports P-256 and Ed25519 keys")
		}
		data = append(append([]byte{}, multicodecP256...), elliptic.MarshalCompressed(k.Curve, k.X, k.Y)...)
	case ed25519.PublicKey:
		data = append(append([]byte{}, multicodecEd25519...), k...)
	default:
		return "", fmt.Errorf("lws: unsupported public key type %T", pub)
	}
	return "did:key:z" + base58Encode(data), nil
}

// DIDKeyVerificationMethod returns the verification method id (the JWT kid)
// of a did:key identifier: "did:key:z…#z…".
func DIDKeyVerificationMethod(did string) string {
	return did + "#" + strings.TrimPrefix(did, "did:key:")
}

// PublicKeyFromDIDKey extracts the public key from a did:key identifier (or
// a did:key verification method id).
func PublicKeyFromDIDKey(did string) (crypto.PublicKey, error) {
	if i := strings.IndexByte(did, '#'); i >= 0 {
		did = did[:i]
	}
	mb, ok := strings.CutPrefix(did, "did:key:z")
	if !ok {
		return nil, errors.New("lws: not a base58btc did:key identifier")
	}
	data, err := base58Decode(mb)
	if err != nil {
		return nil, err
	}
	switch {
	case bytes.HasPrefix(data, multicodecP256):
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), data[2:])
		if x == nil {
			return nil, errors.New("lws: invalid P-256 did:key")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	case bytes.HasPrefix(data, multicodecEd25519) && len(data) == 2+ed25519.PublicKeySize:
		return ed25519.PublicKey(data[2:]), nil
	}
	return nil, errors.New("lws: unsupported did:key key type")
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(data []byte) string {
	zeros := 0
	for zeros < len(data) && data[zeros] == 0 {
		zeros++
	}
	// Repeated division of the big-endian number by 58.
	buf := make([]byte, 0, len(data)*138/100+1)
	n := append([]byte(nil), data[zeros:]...)
	for len(n) > 0 {
		rem := 0
		out := n[:0]
		for _, b := range n {
			acc := rem*256 + int(b)
			q := acc / 58
			rem = acc % 58
			if len(out) > 0 || q > 0 {
				out = append(out, byte(q))
			}
		}
		buf = append(buf, base58Alphabet[rem])
		n = out
	}
	for i := 0; i < zeros; i++ {
		buf = append(buf, '1')
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

func base58Decode(s string) ([]byte, error) {
	n := new(big.Int)
	radix := big.NewInt(58)
	for _, c := range []byte(s) {
		i := strings.IndexByte(base58Alphabet, c)
		if i < 0 {
			return nil, fmt.Errorf("lws: invalid base58 character %q", c)
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(i)))
	}
	out := n.Bytes()
	for i := 0; i < len(s) && s[i] == '1'; i++ {
		out = append([]byte{0}, out...)
	}
	return out, nil
}

// ControlledIdentifierDocument is the document an HTTPS agent publishes at
// its identifier so that verifiers can validate its self-signed credentials
// (lws10-authn-ssi-cid).
type ControlledIdentifierDocument struct {
	Context        []string                    `json:"@context"`
	ID             string                      `json:"id"`
	Authentication []CIDVerificationMethodJSON `json:"authentication"`
}

// CIDVerificationMethodJSON is an embedded JsonWebKey verification method.
type CIDVerificationMethodJSON struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Controller   string `json:"controller"`
	PublicKeyJWK JWK    `json:"publicKeyJwk"`
}

// NewControlledIdentifierDocument builds the CID document for agent with one
// authentication key. kid is the key identifier used in JWT headers: a
// fragment ("key-1") or a full verification method id ("https://…#key-1").
func NewControlledIdentifierDocument(agent string, publicKey JWK, kid string) *ControlledIdentifierDocument {
	id, frag := verificationMethodID(agent, kid)
	pk := publicKey.Public()
	if pk.Kid == "" {
		pk.Kid = frag
	}
	return &ControlledIdentifierDocument{
		Context: []string{CIDContext},
		ID:      agent,
		Authentication: []CIDVerificationMethodJSON{{
			ID:           id,
			Type:         "JsonWebKey",
			Controller:   agent,
			PublicKeyJWK: pk,
		}},
	}
}

func verificationMethodID(agent, kid string) (id, fragment string) {
	if i := strings.IndexByte(kid, '#'); i >= 0 {
		return kid, kid[i+1:]
	}
	return agent + "#" + kid, kid
}
