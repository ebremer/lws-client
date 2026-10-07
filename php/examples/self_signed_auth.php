<?php
// SPDX-License-Identifier: MIT
// Self-signed identities for bots and server-side agents (lws10-authn-ssi-cid):
//  * did:key: the identifier is derived from the public key, so there is nothing to publish;
//  * an HTTPS agent: publish the printed controlled identifier document at the agent URL.
//
//   php php/examples/self_signed_auth.php
declare(strict_types=1);

require __DIR__ . '/../../vendor/autoload.php';

use Ebremer\Lws\Auth\ControlledIdentifierDocument;
use Ebremer\Lws\Auth\DidKey;
use Ebremer\Lws\Auth\Jwt;
use Ebremer\Lws\Auth\SelfSignedCredentials;
use Ebremer\Lws\Auth\SigningKey;
use Ebremer\Lws\Auth\TokenExchangeAuthenticator;
use Ebremer\Lws\LwsClient;

// 1. did:key. Persist the private JWK to keep the same identity across runs.
$key = SigningKey::generateP256();
echo 'did:key agent : ', DidKey::did($key->publicKey), "\n";
echo 'private JWK   : ', json_encode($key->jwk()), "   (keep it secret)\n";
$didKey = SelfSignedCredentials::didKey($key);
// Reload it later with: SelfSignedCredentials::didKey(SigningKey::fromJwk($savedPrivateJwk))

// 2. An HTTPS agent identifier with an Ed25519 key.
$agent = 'https://bot.example/id';
$edKey = SigningKey::generateEd25519();
$https = SelfSignedCredentials::forAgent($agent, $edKey, 'https://bot.example/id#key-1');
echo "Publish at $agent:\n";
echo json_encode(ControlledIdentifierDocument::create($agent, $edKey->publicKey, 'key-1'), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";

// Either credential plugs into the LWS token exchange flow.
$authenticator = new TokenExchangeAuthenticator($didKey,
    // Optional: only send credentials to authorization servers you trust.
    authorizationServerFilter: static fn (string $server, string $realm): bool => str_starts_with($server, 'https://')
        || in_array(parse_url($server, PHP_URL_HOST), ['localhost', '127.0.0.1'], true));
$client = new LwsClient(authenticator: $authenticator);
echo 'Client ready: the did:key agent signs with ', $didKey->algorithm(), ', the HTTPS agent with ', $https->algorithm(), "\n";

// The credential is a short-lived JWT; this is what the authorization server receives.
$jwt = $didKey->createToken('https://as.example');
echo 'Example credential claims: ', json_encode(Jwt::decodeClaims($jwt), JSON_UNESCAPED_SLASHES), "\n";
