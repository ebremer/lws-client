// SPDX-License-Identifier: MIT

// Package lws is a client for the W3C Linked Web Storage (LWS) protocol.
//
// It targets the LWS Working Group specifications as of 2026-10-19 (the
// Working Draft of 19 October 2026): the Linked Web Storage Protocol 1.0
// (core), the OpenID Connect, SAML 2.0 and self-signed Controlled Identifier
// authentication suites, the Webhook notification suite, and the Search and
// Type Index services.
//
// # Overview
//
// A [Client] performs every LWS operation over HTTP. It is safe for
// concurrent use and every network method takes a [context.Context] first:
//
//	client := lws.NewClient(lws.WithAuthenticator(auth))
//	storage, err := client.DiscoverStorage(ctx, "https://storage.example/root/")
//	root, _ := storage.StorageRoot()
//	res, err := client.Create(ctx, root, strings.NewReader("hello"), "text/plain",
//		lws.Slug("hello.txt"))
//
// Container listings are paginated by the server; [Client.ListContainer]
// follows the pagination links lazily and yields every member as an
// iter.Seq2:
//
//	for item, err := range client.ListContainer(ctx, root) {
//		if err != nil { return err }
//		fmt.Println(item.ID, item.Format)
//	}
//
// Per-call settings (conditional requests, slugs, links, recursion, …) are
// passed as variadic [CallOption] values such as [IfMatch], [Slug] or
// [Recursive]. Each method documents the options it honours.
//
// [Client.Move] moves a resource into another container by patching the up
// link of its linkset, where the storage's [StorageDescription.MoveCapability]
// allows it.
//
// # Authentication
//
// LWS authorization is OAuth 2.0 token exchange. Configure a
// [TokenExchangeAuthenticator] with a [CredentialProvider] for one of the
// authentication suites — [OpenIDCredentials], [SAMLCredentials] or
// [SelfSignedCredentials] — and the client transparently handles the
// 401 → protected resource metadata (RFC 9728) → storage description →
// authorization server metadata → token exchange → retry flow, with the
// discovery checks lws10-core requires before any token request, caching
// access tokens per authorization server and storage:
//
//	key, _ := lws.GenerateP256Key()
//	creds, _ := lws.NewDIDKeyCredentials(key, nil)
//	client := lws.NewClient(lws.WithAuthenticator(
//		lws.NewTokenExchangeAuthenticator(creds, nil)))
//
// # Errors
//
// Non-success HTTP statuses are returned as *[HTTPError], which matches the
// sentinel errors with [errors.Is] (for example [ErrNotFound],
// [ErrConflict] or [ErrPreconditionFailed]). Authentication, protocol and
// webhook signature failures are reported as *[AuthenticationError],
// *[ProtocolError] and *[SignatureVerificationError].
//
// # Notifications
//
// [Client.Subscribe] registers webhook subscriptions and [WebhookVerifier]
// verifies signed deliveries (RFC 9421 HTTP Message Signatures and RFC 9530
// Content-Digest) against the key published in the storage description.
package lws
