<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

/** A structured field display string (`%"f%c3%bc"`, RFC 9651); `$value` is UTF-8 text. */
final class SfDisplayString implements \Stringable
{
    public function __construct(public readonly string $value)
    {
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
