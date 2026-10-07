<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

/** A structured field byte sequence (`:base64:`); `$bytes` is the decoded binary string. */
final class SfBytes
{
    public function __construct(public readonly string $bytes)
    {
    }
}
