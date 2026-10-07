<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

/**
 * Supplies the subject token (an LWS authentication credential) presented to an authorization server in the
 * OAuth 2.0 token exchange. One implementation per LWS authentication suite: {@see OpenIdCredentials},
 * {@see SamlCredentials}, {@see SelfSignedCredentials}.
 */
interface CredentialProvider
{
    /** The `subject_token_type` URI (see {@see \Ebremer\Lws\TokenType}). */
    public function tokenType(): string;

    /** A subject token for the given authorization server. */
    public function subjectToken(CredentialContext $context): string;
}
