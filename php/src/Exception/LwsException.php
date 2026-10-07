<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Exception;

/**
 * The base of every error the client raises about a response or an exchange: {@see HttpException} and its
 * status-specific subclasses, {@see AuthenticationException}, {@see ProtocolException},
 * {@see SignatureVerificationException} and {@see TransportException}.
 *
 * Arguments the caller gets wrong (a relative URL, an invalid type query) raise PHP's own
 * `\InvalidArgumentException` instead, before any request is sent.
 */
class LwsException extends \RuntimeException
{
}
