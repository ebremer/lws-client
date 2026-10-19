<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Exception;

/**
 * The LWS authorization flow failed: a discovery check failed (the protected resource metadata is on another
 * origin, cannot be read or describes another URL; the storage root is on another origin), the request is outside
 * the realm of a challenge of the drafts before 19 October 2026, the authorization server is insecure or rejected,
 * its metadata is wrong, or the token exchange was refused (then `oauthError` and `oauthErrorDescription` carry the
 * RFC 6749 `error` and `error_description`, and `status` the HTTP status).
 */
class AuthenticationException extends LwsException
{
    public function __construct(
        string $message,
        public readonly ?string $oauthError = null,
        public readonly ?string $oauthErrorDescription = null,
        public readonly ?int $status = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
