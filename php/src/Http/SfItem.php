<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

/**
 * A structured field item: a bare item with parameters.
 *
 * Bare items are `int` (integer), `float` (decimal), `string` (string), `bool` (boolean), {@see SfToken},
 * {@see SfBytes}, {@see SfDate} and {@see SfDisplayString}.
 */
final class SfItem
{
    /** @param array<string, int|float|string|bool|SfToken|SfBytes|SfDate|SfDisplayString> $params */
    public function __construct(
        public readonly int|float|string|bool|SfToken|SfBytes|SfDate|SfDisplayString $value,
        public readonly array $params = [],
    ) {
    }
}
