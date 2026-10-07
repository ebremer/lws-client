<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Internal;

use Ebremer\Lws\Http\Headers;

/**
 * The final response of a call, with the method and URL of the hop that produced it.
 *
 * @internal
 */
final class Answer
{
    public function __construct(
        public readonly string $method,
        public readonly string $url,
        public readonly int $status,
        public readonly Headers $headers,
        public readonly string $body,
    ) {
    }
}
