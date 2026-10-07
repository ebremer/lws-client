<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\Vocabulary;

/** Authorization server metadata (RFC 8414), served at `/.well-known/lws-configuration`. */
final class AuthorizationServerMetadata
{
    /**
     * @param string $issuer the issuer identifier, as the server states it
     * @param list<string> $grantTypesSupported
     * @param list<string> $subjectTokenTypesSupported empty when not advertised
     * @param list<string> $subjectIdentifierTypesSupported `['https']` when not advertised
     * @param array<array-key, mixed> $raw
     */
    public function __construct(
        public readonly string $issuer,
        public readonly string $tokenEndpoint,
        public readonly ?string $jwksUri = null,
        public readonly array $grantTypesSupported = [],
        public readonly array $subjectTokenTypesSupported = [],
        public readonly array $subjectIdentifierTypesSupported = ['https'],
        public readonly array $raw = [],
    ) {
    }

    /**
     * Parses a metadata document retrieved from `base`.
     *
     * @throws ProtocolException without `issuer` or `token_endpoint`
     */
    public static function parse(mixed $json, ?string $base = null): self
    {
        $o = JsonAccess::object($json, 'The authorization server metadata');
        $issuer = JsonAccess::str($o, 'issuer') ?? throw new ProtocolException('The authorization server metadata has no issuer');
        $token = JsonAccess::url($o, 'token_endpoint', $base)
            ?? throw new ProtocolException('The authorization server metadata has no token_endpoint');
        $idTypes = JsonAccess::strings($o, 'subject_identifier_types_supported');
        return new self($issuer, $token, JsonAccess::url($o, 'jwks_uri', $base), JsonAccess::strings($o, 'grant_types_supported'),
            JsonAccess::strings($o, 'subject_token_types_supported'), $idTypes === [] ? ['https'] : $idTypes, $o);
    }

    /** Whether the server accepts subject tokens of a type (true when it advertises none). */
    public function supportsSubjectTokenType(string $tokenType): bool
    {
        return $this->subjectTokenTypesSupported === [] || in_array($tokenType, $this->subjectTokenTypesSupported, true);
    }

    /**
     * The metadata URL of an issuer (RFC 8414 section 3.1): `https://as.example` →
     * `https://as.example/.well-known/lws-configuration`; `https://as.example/t1` →
     * `https://as.example/.well-known/lws-configuration/t1`.
     */
    public static function metadataUrl(string $issuer): string
    {
        $c = Url::parse($issuer);
        $path = $c['path'];
        if (str_ends_with($path, '/')) {
            $path = substr($path, 0, -1);
        }
        return ($c['scheme'] ?? 'https') . '://' . ($c['authority'] ?? '') . Vocabulary::WELL_KNOWN_LWS_CONFIGURATION . $path;
    }
}
