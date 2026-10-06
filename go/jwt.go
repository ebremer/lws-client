// SPDX-License-Identifier: MIT

package lws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// JWSAlgorithm returns the JWS algorithm for a signing key: "ES256" for
// P-256, "ES384" for P-384 and "EdDSA" for Ed25519.
func JWSAlgorithm(key crypto.PublicKey) (string, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return "ES256", nil
		case elliptic.P384():
			return "ES384", nil
		}
	case ed25519.PublicKey:
		return "EdDSA", nil
	}
	return "", fmt.Errorf("lws: unsupported key type %T", key)
}

// SignJWT creates a compact JWS over the given claims. The "alg" header is
// set from the key; other header members (typ, kid, …) are taken from header.
// ECDSA signatures use the JOSE raw r‖s encoding.
func SignJWT(header map[string]any, claims any, key crypto.Signer) (string, error) {
	alg, err := JWSAlgorithm(key.Public())
	if err != nil {
		return "", err
	}
	h := map[string]any{}
	for k, v := range header {
		h[k] = v
	}
	h["alg"] = alg
	hj, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	cj, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64u.EncodeToString(hj) + "." + b64u.EncodeToString(cj)
	sig, err := signRaw(key, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64u.EncodeToString(sig), nil
}

// signRaw signs msg: ECDSA (SHA-256/384, raw r‖s) or Ed25519.
func signRaw(key crypto.Signer, msg []byte) ([]byte, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		digest := hashFor(k.Curve, msg)
		r, s, err := ecdsa.Sign(rand.Reader, k, digest)
		if err != nil {
			return nil, err
		}
		n := curveByteLen(k.Curve)
		return append(padTo(r.Bytes(), n), padTo(s.Bytes(), n)...), nil
	case ed25519.PrivateKey:
		return ed25519.Sign(k, msg), nil
	}
	return nil, fmt.Errorf("lws: unsupported signing key %T", key)
}

func hashFor(c elliptic.Curve, msg []byte) []byte {
	if c == elliptic.P384() {
		h := sha512.Sum384(msg)
		return h[:]
	}
	h := sha256.Sum256(msg)
	return h[:]
}

// verifyRaw verifies a raw signature (ECDSA r‖s or Ed25519) over msg.
func verifyRaw(pub crypto.PublicKey, msg, sig []byte) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		n := curveByteLen(k.Curve)
		if len(sig) != 2*n {
			return false
		}
		r := new(big.Int).SetBytes(sig[:n])
		s := new(big.Int).SetBytes(sig[n:])
		return ecdsa.Verify(k, hashFor(k.Curve, msg), r, s)
	case ed25519.PublicKey:
		return len(sig) == ed25519.SignatureSize && ed25519.Verify(k, msg, sig)
	}
	return false
}

// DecodeJWT decodes a compact JWT's header and claims WITHOUT verifying the
// signature.
func DecodeJWT(token string) (header, claims map[string]any, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("lws: malformed JWT")
	}
	hb, err := decodeB64u(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("lws: malformed JWT header: %w", err)
	}
	cb, err := decodeB64u(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("lws: malformed JWT claims: %w", err)
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, nil, fmt.Errorf("lws: malformed JWT header: %w", err)
	}
	if err := json.Unmarshal(cb, &claims); err != nil {
		return nil, nil, fmt.Errorf("lws: malformed JWT claims: %w", err)
	}
	return header, claims, nil
}

// VerifyJWT verifies a compact JWS signature with pub and returns the
// decoded header and claims. The "alg" header must match the key ("none" is
// always rejected). Claims (exp, aud, …) are not validated.
func VerifyJWT(token string, pub crypto.PublicKey) (header, claims map[string]any, err error) {
	header, claims, err = DecodeJWT(token)
	if err != nil {
		return nil, nil, err
	}
	want, err := JWSAlgorithm(pub)
	if err != nil {
		return nil, nil, err
	}
	if alg, _ := header["alg"].(string); alg != want {
		return nil, nil, fmt.Errorf("lws: JWT alg %q does not match key (%s)", alg, want)
	}
	i := strings.LastIndexByte(token, '.')
	sig, err := decodeB64u(token[i+1:])
	if err != nil {
		return nil, nil, fmt.Errorf("lws: malformed JWT signature: %w", err)
	}
	if !verifyRaw(pub, []byte(token[:i]), sig) {
		return nil, nil, errors.New("lws: JWT signature verification failed")
	}
	return header, claims, nil
}

// newUUID returns a random (version 4) UUID.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
