// SPDX-License-Identifier: MIT
// Self-signed identities for bots and server-side agents (lws10-authn-ssi-cid):
//  * did:key: the identifier is derived from the public key, so there is nothing to publish;
//  * an HTTPS agent: publish the printed controlled identifier document at the agent URL.
//
//   swift run SelfSignedAuth
import Foundation
import LWS

// 1. did:key. Persist the private JWK to keep the same identity across runs.
let key = SigningKey.generateP256()
print("did:key agent : \(try DIDKey.did(for: key.publicKey))")
print("private JWK   : \(key.jwk)   (keep it secret)")
let didKey = try SelfSignedCredentials.didKey(key)
// Reload it later with: try SelfSignedCredentials.didKey(SigningKey(jwk: savedPrivateJWK))

// 2. An HTTPS agent identifier with an Ed25519 key.
let agent = URL(string: "https://bot.example/id")!
let edKey = SigningKey.generateEd25519()
let https = SelfSignedCredentials.forAgent(agent, key: edKey, keyID: "https://bot.example/id#key-1")
print("Publish at \(agent):")
print(JSONValue.object(ControlledIdentifierDocument.create(agent: agent, key: edKey.publicKey, kid: "key-1")).serialized(pretty: true))

// Either credential plugs into the LWS token exchange flow.
let authenticator = TokenExchangeAuthenticator(credentials: didKey, options: TokenExchangeOptions(
    // Optional: only send credentials to authorization servers you trust.
    authorizationServerFilter: { server, _ in server.scheme == "https" || server.host == "localhost" }))
let client = LWSClient(authenticator: authenticator)
print("Client ready: \(client.authenticator != nil); the did:key agent signs with \(didKey.algorithm), the HTTPS agent with \(https.algorithm)")

// The credential is a short-lived JWT; this is what the authorization server receives.
let jwt = try didKey.createToken(audience: "https://as.example")
print("Example credential claims: \(try JWT.decodeClaims(jwt))")
