<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Json;

/**
 * A JSON Patch that cannot be applied to a document (RFC 6902 §5): a failed `test`, or an operation whose target
 * or `from` location does not exist. Nothing of the patch was applied.
 */
final class JsonPatchException extends \RuntimeException
{
    /**
     * @param int $operation the index of the operation that failed
     * @param ?string $path its `path`
     */
    public function __construct(string $message, public readonly int $operation = 0, public readonly ?string $path = null)
    {
        parent::__construct($message);
    }
}
