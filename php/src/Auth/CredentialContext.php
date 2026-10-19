<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

/** Where a subject token will be presented: the authorization server, the storage and the server's metadata. */
final class CredentialContext
{
    /**
     * @param string $issuer the authorization server
     * @param string $storage the storage the access token is requested for (the token request's `resource`; with the
     *     challenge of the drafts before 19 October 2026, its realm)
     * @param AuthorizationServerMetadata $metadata whose `issuer` is the audience of self-signed tokens
     */
    public function __construct(public readonly string $issuer, public readonly string $storage, public readonly AuthorizationServerMetadata $metadata)
    {
    }
}
