<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

/** Where a subject token will be presented: the authorization server, the realm and the server's metadata. */
final class CredentialContext
{
    /**
     * @param string $issuer the authorization server (`as_uri`)
     * @param string $realm the protection realm the access token is requested for
     * @param AuthorizationServerMetadata $metadata whose `issuer` is the audience of self-signed tokens
     */
    public function __construct(public readonly string $issuer, public readonly string $realm, public readonly AuthorizationServerMetadata $metadata)
    {
    }
}
