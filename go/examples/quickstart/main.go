// SPDX-License-Identifier: MIT

// Command quickstart discovers a storage, creates, reads, updates, lists and
// deletes resources.
//
//	node testing/mock-server/server.mjs --port 8787
//	go run ./examples/quickstart -url http://localhost:8787/root/
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	lws "github.com/ebremer/lws-client/go"
)

func main() {
	start := flag.String("url", "http://localhost:8787/root/", "any resource URL inside the storage")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Self-signed did:key credentials; the client exchanges them for access
	// tokens automatically when the storage answers 401.
	key, err := lws.GenerateP256Key()
	if err != nil {
		log.Fatal(err)
	}
	creds, err := lws.NewDIDKeyCredentials(key, nil)
	if err != nil {
		log.Fatal(err)
	}
	client := lws.NewClient(lws.WithAuthenticator(lws.NewTokenExchangeAuthenticator(creds, nil)))
	fmt.Println("agent:", creds.Agent())

	storage, err := client.DiscoverStorage(ctx, *start)
	if err != nil {
		log.Fatal(err)
	}
	root, err := storage.StorageRoot()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("storage:", storage.ID, "root:", root)

	folder, err := client.CreateContainer(ctx, root, lws.Slug("quickstart"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("created container", folder.Location)

	note, err := client.Create(ctx, folder.Location, strings.NewReader("milk\neggs\nbread\n"), "text/plain", lws.Slug("shopping.txt"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("created", note.Location)

	res, err := client.Read(ctx, note.Location)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("read %d bytes, ETag %s, parent %s\n", len(res.Body), res.ETag, res.Parent)

	if _, err := client.Update(ctx, note.Location, strings.NewReader(res.Text()+"butter\n"), "text/plain", lws.IfMatch(res.ETag)); err != nil {
		log.Fatal(err)
	}
	// Re-using the old ETag now fails: someone (we) changed the resource.
	_, err = client.Update(ctx, note.Location, strings.NewReader("stale"), "text/plain", lws.IfMatch(res.ETag))
	fmt.Println("stale update rejected:", errors.Is(err, lws.ErrPreconditionFailed))

	profile, err := client.CreateJSON(ctx, folder.Location, map[string]any{"name": "Alice", "age": 30},
		lws.Slug("profile.json"), lws.Types("https://schema.org/Person"))
	if err != nil {
		log.Fatal(err)
	}
	if _, err := client.Patch(ctx, profile.Location, lws.JSONPatch{}.Replace("/age", 31)); err != nil {
		log.Fatal(err)
	}

	fmt.Println("members of", folder.Location)
	for item, err := range client.ListContainer(ctx, folder.Location) {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("  %-60s %-18s %d bytes\n", item.ID, item.Format, item.Size)
	}

	if err := client.Delete(ctx, folder.Location, lws.Recursive()); err != nil {
		log.Fatal(err)
	}
	fmt.Println("deleted", folder.Location)
}
