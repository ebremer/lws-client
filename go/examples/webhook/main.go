// SPDX-License-Identifier: MIT

// Command webhook runs a notification inbox: it subscribes to a container
// and prints every verified (RFC 9421 signed) notification it receives.
//
//	go run ./examples/webhook -url http://localhost:8787/root/ -listen 127.0.0.1:9000
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	lws "github.com/ebremer/lws-client/go"
)

func main() {
	topic := flag.String("url", "http://localhost:8787/root/", "container or resource to watch")
	listen := flag.String("listen", "127.0.0.1:9000", "address of the local inbox")
	public := flag.String("inbox", "", "public inbox URL (default http://<listen>/inbox)")
	flag.Parse()
	inbox := *public
	if inbox == "" {
		inbox = "http://" + *listen + "/inbox"
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	key, _ := lws.GenerateP256Key()
	creds, _ := lws.NewDIDKeyCredentials(key, nil)
	client := lws.NewClient(lws.WithAuthenticator(lws.NewTokenExchangeAuthenticator(creds, nil)))

	storage, err := client.DiscoverStorage(ctx, *topic)
	if err != nil {
		log.Fatal(err)
	}

	// Only accept notifications signed by this storage's published key.
	verifier := lws.NewWebhookVerifier(&lws.WebhookVerifierOptions{TrustedStorages: []string{storage.ID}})
	mux := http.NewServeMux()
	mux.Handle("/inbox", verifier.Handler(inbox, func(_ context.Context, n *lws.VerifiedNotification) {
		for _, a := range n.Notification.Activities {
			fmt.Printf("%s %v %s (signed by %s)\n", a.Published.Format(time.RFC3339), a.Types, a.Object.ID, n.KeyID)
		}
	}))
	srv := &http.Server{Addr: *listen, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	sub, err := client.SubscribeWebhook(ctx, storage, lws.WebhookSubscriptionRequest{
		Topics:  []string{*topic},
		Inbox:   inbox,
		Expires: time.Now().Add(time.Hour),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("subscribed:", sub.URL, "— waiting for notifications (Ctrl+C to stop)")

	<-ctx.Done()
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Unsubscribe(cleanup, sub.URL); err != nil {
		log.Println("unsubscribe:", err)
	}
	_ = srv.Shutdown(cleanup)
}
