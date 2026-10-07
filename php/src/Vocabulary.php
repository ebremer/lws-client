<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws;

/**
 * LWS namespaces and contexts, OAuth and access profile identifiers, and type matching.
 *
 * JSON documents use short terms (`Container`), compact IRIs (`lws:Container`) and full IRIs
 * (`https://www.w3.org/ns/lws#Container`) interchangeably; {@see typeMatches()} treats them as equal.
 */
final class Vocabulary
{
    public const LWS_NS = 'https://www.w3.org/ns/lws#';
    public const LWS_CONTEXT = 'https://www.w3.org/ns/lws/v1';
    public const CID_CONTEXT = 'https://www.w3.org/ns/cid/v1';
    public const ACTIVITYSTREAMS_CONTEXT = 'https://www.w3.org/ns/activitystreams';
    public const GRANT_TYPE_TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
    public const WELL_KNOWN_LWS_CONFIGURATION = '/.well-known/lws-configuration';
    public const OPENID_PROVIDER_SERVICE = 'https://www.w3.org/ns/lws#OpenIdProvider';
    public const ACCESS_PROFILE = 'https://www.w3.org/ns/lws#AccessProfile';
    public const PUBLIC_AGENT = 'http://xmlns.com/foaf/0.1/Agent';

    private function __construct()
    {
    }

    /** The full IRI of a type: `Container` and `lws:Container` become `https://www.w3.org/ns/lws#Container`. */
    public static function expandType(string $type): string
    {
        if (str_starts_with($type, 'lws:')) {
            return self::LWS_NS . substr($type, 4);
        }
        return str_contains($type, ':') ? $type : self::LWS_NS . $type;
    }

    /** Whether two type values name the same type (short term, `lws:` compact IRI or full IRI). */
    public static function typeMatches(string $a, string $b): bool
    {
        return $a === $b || self::expandType($a) === self::expandType($b);
    }

    /** @param iterable<string> $types */
    public static function hasType(iterable $types, string $type): bool
    {
        foreach ($types as $t) {
            if (self::typeMatches($t, $type)) {
                return true;
            }
        }
        return false;
    }
}
