// SPDX-License-Identifier: MIT

// Command selfsigned shows the self-signed authentication suite
// (lws10-authn-ssi-cid): it creates (or loads) a key, prints the did:key
// identity and the controlled identifier document an HTTPS agent would
// publish, then authenticates to a storage.
//
//	go run ./examples/selfsigned -url http://localhost:8787/root/ -key agent.jwk
package main

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"time"

	lws "github.com/ebremer/lws-client/go"
)

func main() {
	target := flag.String("url", "http://localhost:8787/root/", "protected resource to access")
	keyFile := flag.String("key", "", "private JWK file (created if missing; ephemeral key if empty)")
	agent := flag.String("agent", "", "HTTPS agent URI (default: use the did:key identifier)")
	flag.Parse()

	key, err := loadKey(*keyFile)
	if err != nil {
		log.Fatal(err)
	}

	var creds *lws.SelfSignedCredentials
	if *agent == "" {
		creds, err = lws.NewDIDKeyCredentials(key, nil)
	} else {
		creds, err = lws.NewSelfSignedCredentials(*agent, key, "key-1", nil)
		pub, _ := lws.JWKFromPublicKey(key.Public())
		doc, _ := json.MarshalIndent(lws.NewControlledIdentifierDocument(*agent, *pub, "key-1"), "", "  ")
		fmt.Printf("Publish this controlled identifier document at %s:\n%s\n\n", *agent, doc)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("agent:", creds.Agent())
	fmt.Println("kid:  ", creds.KeyID())

	auth := lws.NewTokenExchangeAuthenticator(creds, nil)
	client := lws.NewClient(lws.WithAuthenticator(auth))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	meta, err := client.Head(ctx, *target)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("HEAD %s -> %d (container: %v)\n", *target, meta.StatusCode, meta.IsContainer())
}

// loadKey reads a private JWK from path, creating it when the file does not
// exist. An empty path yields an ephemeral key.
func loadKey(path string) (crypto.Signer, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			jwk, err := lws.ParseJWK(data)
			if err != nil {
				return nil, err
			}
			k, err := jwk.PrivateKey()
			if err != nil {
				return nil, err
			}
			return k, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	k, err := lws.GenerateP256Key()
	if err != nil {
		return nil, err
	}
	if path != "" {
		jwk, _ := lws.JWKFromPrivateKey(k)
		data, _ := json.MarshalIndent(jwk, "", "  ")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return nil, err
		}
		fmt.Println("wrote new key to", path)
	}
	return k, nil
}
