# Conformance fixtures

Shared, language-neutral test data used by every client so that they parse, build and verify
exactly the same things. Each client's test suite loads these files directly from this directory
(relative path `../conformance/fixtures` from the language folder).

| File | What it tests |
|---|---|
| `fixtures/link-headers.json` | RFC 8288 `Link` parsing and URL resolution |
| `fixtures/www-authenticate.json` | `WWW-Authenticate` challenge parsing (LWS `as_uri` / `realm`) |
| `fixtures/structured-fields.json` | RFC 8941/9651 dictionaries (Signature-Input, Signature, Content-Digest) |
| `fixtures/json-patch.json` | JSON Pointer escaping and JSON Patch serialisation |
| `fixtures/json-patch-apply.json` | Applying JSON Patch documents: RFC 6902 Appendix A and edge cases (optional for clients; servers need it) |
| `fixtures/type-queries.json` | `application/lws-query+json` builder and validation |
| `fixtures/did-key.json` | did:key derivation (includes the did:key spec P-256 vector) |
| `fixtures/jwt.json` | self-signed JWT credentials (ES256, EdDSA) that must verify |
| `fixtures/keys/*.json` | **test-only** key pairs used by the generator |
| `fixtures/webhook/*.json` | RFC 9421 signed webhook deliveries — 3 valid, 10 invalid |
| `fixtures/responses/*.json` | HTTP response bodies/headers with the expected parsed model |

`scenario.md` defines the end-to-end interop scenario run against the mock server.

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
