<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Exception;

/** A webhook delivery that fails verification (RFC 9421 signature, RFC 9530 digest, key or storage checks). */
class SignatureVerificationException extends LwsException
{
}
