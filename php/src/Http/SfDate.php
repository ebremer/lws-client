<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

/** A structured field date (`@1659578233`, RFC 9651): seconds since the epoch. */
final class SfDate
{
    public function __construct(public readonly int $seconds)
    {
    }
}
