<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Exception;

/** No response arrived: the connection was refused or reset, TLS failed, or the time limit passed. */
class TransportException extends LwsException
{
    public function __construct(string $message, private readonly bool $timeout = false, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }

    /** Whether the request ran out of time. */
    public function isTimeout(): bool
    {
        return $this->timeout;
    }
}
