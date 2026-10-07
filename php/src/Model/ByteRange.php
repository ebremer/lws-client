<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

/** A byte range to read (`Range: bytes=…`): `ByteRange::of(0, 1023)`, `ByteRange::from(1024)`, `ByteRange::last(500)`. */
final class ByteRange implements \Stringable
{
    private function __construct(public readonly ?int $start, public readonly ?int $end, public readonly ?int $suffixLength)
    {
    }

    /**
     * The bytes from `start` to `end`, both included (`end` null: to the end).
     *
     * @throws \InvalidArgumentException for negative offsets or `end < start`
     */
    public static function of(int $start, ?int $end = null): self
    {
        if ($start < 0 || ($end !== null && $end < $start)) {
            throw new \InvalidArgumentException("Invalid byte range $start-" . ($end ?? ''));
        }
        return new self($start, $end, null);
    }

    /** The bytes from `start` to the end. */
    public static function from(int $start): self
    {
        return self::of($start);
    }

    /**
     * The last `length` bytes.
     *
     * @throws \InvalidArgumentException when `length` is not positive
     */
    public static function last(int $length): self
    {
        if ($length <= 0) {
            throw new \InvalidArgumentException("Invalid suffix length $length");
        }
        return new self(null, null, $length);
    }

    /** The `Range` header value. */
    public function headerValue(): string
    {
        return $this->suffixLength !== null ? "bytes=-{$this->suffixLength}" : "bytes={$this->start}-" . ($this->end ?? '');
    }

    public function __toString(): string
    {
        return $this->headerValue();
    }
}
