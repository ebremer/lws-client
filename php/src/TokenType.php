<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws;

/** OAuth 2.0 token type URIs (RFC 8693) of the LWS authentication suites. */
final class TokenType
{
    public const ID_TOKEN = 'urn:ietf:params:oauth:token-type:id_token';
    public const SAML2 = 'urn:ietf:params:oauth:token-type:saml2';
    public const JWT = 'urn:ietf:params:oauth:token-type:jwt';
    public const ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token';

    private function __construct()
    {
    }
}
