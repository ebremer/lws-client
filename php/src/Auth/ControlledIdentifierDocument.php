<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\Json\Json;
use Ebremer\Lws\Vocabulary;

/**
 * The controlled identifier document an agent with an HTTPS identifier publishes at that identifier, so that
 * authorization servers can verify its self-signed credentials (`lws10-authn-ssi-cid`).
 */
final class ControlledIdentifierDocument
{
    private function __construct()
    {
    }

    /**
     * The document: `@context` CID v1, `id`, and `authentication` with one `JsonWebKey` verification method
     * (`agent#kid`, or `kid` itself when it is a URI).
     *
     * @param VerificationKey|array<array-key, mixed>|\stdClass $publicKey the key or its public JWK
     * @return array<string, mixed>
     */
    public static function create(string $agent, VerificationKey|array|\stdClass $publicKey, string $kid): array
    {
        $jwk = $publicKey instanceof VerificationKey ? $publicKey->jwk() : (Json::members($publicKey) ?? []);
        unset($jwk['d']);
        $jwk['kid'] = $kid;
        if (!isset($jwk['alg'])) {
            $jwk['alg'] = ($jwk['kty'] ?? '') === 'OKP' ? 'EdDSA' : (($jwk['crv'] ?? '') === 'P-384' ? 'ES384' : 'ES256');
        }
        return [
            '@context' => [Vocabulary::CID_CONTEXT],
            'id' => $agent,
            'authentication' => [[
                'id' => str_contains($kid, ':') ? $kid : $agent . '#' . $kid,
                'type' => 'JsonWebKey',
                'controller' => $agent,
                'publicKeyJwk' => $jwk,
            ]],
        ];
    }
}
