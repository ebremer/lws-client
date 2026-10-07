// SPDX-License-Identifier: MIT
// Self-signed identities for bots and server-side agents (lws10-authn-ssi-cid):
//  * did:key: the identifier is derived from the public key, so there is nothing to publish;
//  * an HTTPS agent: publish the printed controlled identifier document at the agent URL.
//
//   dotnet run --project examples/SelfSignedAuth
using System.Text.Json;
using Ebremer.Lws;
using Ebremer.Lws.Auth;

var pretty = new JsonSerializerOptions { WriteIndented = true };

// 1. did:key. Persist the private JWK to keep the same identity across runs.
SigningKey key = SigningKey.GenerateP256();
Console.WriteLine($"did:key agent : {DidKey.FromPublicKey(key.PublicKey)}");
Console.WriteLine($"private JWK   : {key.ToJwk().ToJsonString()}   (keep it secret)");
SelfSignedCredentials didKey = SelfSignedCredentials.DidKey(key);
// Reload it later with: SelfSignedCredentials.DidKey(SigningKey.FromJwk(savedPrivateJwk))

// 2. An HTTPS agent identifier with an Ed25519 key.
var agent = new Uri("https://bot.example/id");
SigningKey edKey = SigningKey.GenerateEd25519();
SelfSignedCredentials https = SelfSignedCredentials.ForAgent(agent, edKey, "https://bot.example/id#key-1");
Console.WriteLine($"Publish at {agent}:");
Console.WriteLine(ControlledIdentifierDocument.Create(agent, edKey.PublicKey, "key-1").ToJsonString(pretty));

// Either credential plugs into the LWS token exchange flow.
using var authenticator = new TokenExchangeAuthenticator(didKey, new TokenExchangeOptions
{
    // Optional: only send credentials to authorization servers you trust.
    AuthorizationServerFilter = (authorizationServer, realm) => authorizationServer.Scheme == Uri.UriSchemeHttps || authorizationServer.IsLoopback,
});
using var client = new LwsClient(new LwsClientOptions { Authenticator = authenticator });
Console.WriteLine($"Client ready: {client.Authenticator is not null}; the did:key agent signs with {didKey.Algorithm}, the HTTPS agent with {https.Algorithm}");

// The credential is a short-lived JWT; this is what the authorization server receives.
string jwt = didKey.CreateToken("https://as.example");
Console.WriteLine($"Example credential claims: {Jwt.DecodeClaims(jwt)}");
