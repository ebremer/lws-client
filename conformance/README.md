# Conformance fixtures

Shared, language-neutral test data used by every client so that they parse, build and verify
exactly the same things. Each client's test suite loads these files directly from this directory
(relative path `../conformance/fixtures` from the language folder).

| File | What it tests |
|---|---|
| `fixtures/link-headers.json` | RFC 8288 `Link` parsing and URL resolution |
| `fixtures/www-authenticate.json` | `WWW-Authenticate` challenge parsing (LWS `resource_metadata`, and the `as_uri` / `realm` of earlier drafts) |
| `fixtures/discovery.json` | The authorization flow after a `401`: protected resource metadata (RFC 9728), the three discovery checks, the token request, and where the token is sent next |
| `fixtures/move.json` | Moving a resource: the JSON Patch a client sends to the linkset, and what it makes of the answer |
| `fixtures/structured-fields.json` | RFC 8941/9651 dictionaries (Signature-Input, Signature, Content-Digest) |
| `fixtures/json-patch.json` | JSON Pointer escaping and JSON Patch serialisation |
| `fixtures/json-patch-apply.json` | Applying JSON Patch documents: RFC 6902 Appendix A and edge cases (optional for clients; servers need it) |
| `fixtures/type-queries.json` | `application/lws-query+json` builder and validation |
| `fixtures/did-key.json` | did:key derivation (includes the did:key spec P-256 vector) |
| `fixtures/jwt.json` | self-signed JWT credentials (ES256, EdDSA) that must verify |
| `fixtures/keys/*.json` | **test-only** key pairs used by the generator |
| `fixtures/webhook/*.json` | RFC 9421 signed webhook deliveries — 3 valid, 10 invalid |
| `fixtures/responses/*.json` | HTTP response bodies/headers with the expected parsed model (`oauth.json` also holds protected resource metadata and the origin and resource comparisons of the discovery checks) |

`scenario.md` defines the end-to-end interop scenario run against the mock server.

## Discovery vectors

`discovery.json` is run through the client's own `TokenExchangeAuthenticator`, against an in-process
server or a mock transport that answers as its `description` says. `{A}` and `{B}` stand for two
origins; with a real loopback server, `http://127.0.0.1:<port>` and `http://localhost:<port>` are
two origins served by one listener (route on the `Host` header). Each case checks the outcome, the
one token request (or that none was made), that the URLs in `notFetched` were never requested, and,
where `then` is given, which later requests carry the token without a `401` first.

Regenerate the cryptographic fixtures (keys are reused; ECDSA signatures change) with:

```sh
node conformance/tools/generate-fixtures.mjs
```

## Webhook vectors

For each `webhook/<name>.json`: verify the request (`method`, `url` = registered inbox URL,
`headers`, `body` as UTF-8 bytes) using `webhook/storage-description.json` as the result of
dereferencing the storage identifier, `now` (unix seconds) as the current time and a 300 s
max-age / clock-skew window. `expected.valid` says whether verification must succeed;
`expected.reason` is a human hint (do not compare error messages). Valid vectors include the
exact `signatureBase` so implementations can debug their signature-base construction.
