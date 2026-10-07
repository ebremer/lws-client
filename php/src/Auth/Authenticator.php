<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Auth;

/**
 * Pluggable request authentication for {@see \Ebremer\Lws\LwsClient}.
 *
 * The client calls {@see authorize()} before every request attempt (every redirect hop included, each for its own
 * URL). When an attempt is answered `401 Unauthorized` it calls {@see handleChallenge()}; returning true makes it
 * send the request once more, authorizing it again first.
 *
 * Provided: {@see TokenExchangeAuthenticator} (the LWS OAuth 2.0 token exchange flow) and
 * {@see BearerTokenAuthenticator} (a known access token). Others (cookies, DPoP, mTLS, …) implement this interface.
 */
interface Authenticator
{
    /** Returns the request with credentials added, typically an `Authorization` header. */
    public function authorize(AuthRequest $request): AuthRequest;

    /** Reacts to a `401` response, e.g. by obtaining a token; returns whether to send the request again. */
    public function handleChallenge(AuthRequest $request, AuthResponse $response): bool;
}
