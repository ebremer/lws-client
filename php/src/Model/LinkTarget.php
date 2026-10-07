<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Json\Json;

/** A link target of a linkset: `href` and its target attributes (JSON values: `type`, `title`, `hreflang`, `title*`, …). */
final class LinkTarget implements \Stringable
{
    /** @var array<string, mixed> */
    public readonly array $attributes;

    /** @param array<array-key, mixed> $attributes */
    public function __construct(public readonly string $href, array $attributes = [])
    {
        unset($attributes['href']);
        $this->attributes = $attributes;
    }

    /** An attribute that is a string, or null. */
    public function attribute(string $name): ?string
    {
        return JsonAccess::str($this->attributes, $name);
    }

    /** @return array<array-key, mixed> the target object */
    public function toJson(): array
    {
        return ['href' => $this->href] + $this->attributes;
    }

    public function __toString(): string
    {
        return $this->href;
    }

    /** @internal */
    public static function fromJson(mixed $json): ?self
    {
        $o = Json::members($json);
        $href = $o === null ? null : JsonAccess::str($o, 'href');
        return $href === null ? null : new self($href, $o);
    }
}
