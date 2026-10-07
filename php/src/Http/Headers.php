<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

/**
 * An ordered, case-insensitive multimap of header fields (a name may repeat, e.g. `Link`). Immutable: the `with*`
 * methods return copies.
 *
 * Iterating yields each field as `name => value`, so a repeated name is yielded once per value.
 *
 * @implements \IteratorAggregate<string, string>
 */
final class Headers implements \IteratorAggregate, \Countable
{
    /** @var list<array{0: string, 1: string}> */
    private array $fields = [];

    /**
     * @param iterable<array-key, mixed> $fields a map of name to value or list of values (`['Accept' => 'text/plain',
     *     'Link' => ['<a>; rel="x"', '<b>; rel="y"']]`), or a list of `[name, value]` pairs
     * @throws \InvalidArgumentException for a name that is not a token or a value with a line break
     */
    public function __construct(iterable $fields = [])
    {
        foreach ($fields as $key => $value) {
            if (is_int($key) && is_array($value) && array_is_list($value) && count($value) === 2
                && is_string($value[0]) && is_string($value[1])) {
                $this->fields[] = self::field($value[0], $value[1]);
                continue;
            }
            $name = (string) $key;
            foreach (is_array($value) ? $value : [$value] as $v) {
                if (!is_scalar($v)) {
                    throw new \InvalidArgumentException("The value of header $name is not a string");
                }
                $this->fields[] = self::field($name, (string) $v);
            }
        }
    }

    /**
     * Headers from a map or list of pairs (see the constructor); a `Headers` is returned as is.
     *
     * @param Headers|iterable<array-key, mixed> $fields
     */
    public static function of(Headers|iterable $fields): self
    {
        return $fields instanceof self ? $fields : new self($fields);
    }

    /** @return array{0: string, 1: string} */
    private static function field(string $name, string $value): array
    {
        if (preg_match('/^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$/', $name) !== 1) {
            throw new \InvalidArgumentException("Invalid header name: $name");
        }
        if (preg_match('/[\r\n\0]/', $value) === 1) {
            throw new \InvalidArgumentException("The value of header $name contains a line break");
        }
        return [$name, trim($value, " \t")];
    }

    /** The first value of a field, or null. */
    public function first(string $name): ?string
    {
        foreach ($this->fields as [$n, $v]) {
            if (strcasecmp($n, $name) === 0) {
                return $v;
            }
        }
        return null;
    }

    /**
     * Every value of a field, in order.
     *
     * @return list<string>
     */
    public function all(string $name): array
    {
        $out = [];
        foreach ($this->fields as [$n, $v]) {
            if (strcasecmp($n, $name) === 0) {
                $out[] = $v;
            }
        }
        return $out;
    }

    /** Whether a field is present. */
    public function has(string $name): bool
    {
        return $this->first($name) !== null;
    }

    /**
     * The distinct field names, as first seen.
     *
     * @return list<string>
     */
    public function names(): array
    {
        $seen = [];
        foreach ($this->fields as [$n]) {
            $seen[strtolower($n)] ??= $n;
        }
        return array_values($seen);
    }

    /**
     * A copy with the field set to a value (or values), replacing any present; a null value removes it.
     *
     * @param string|list<string>|null $value
     */
    public function with(string $name, string|array|null $value): self
    {
        $h = $this->without($name);
        foreach ($value === null ? [] : (is_array($value) ? $value : [$value]) as $v) {
            $h->fields[] = self::field($name, $v);
        }
        return $h;
    }

    /** A copy with one more value of a field. */
    public function withAdded(string $name, string $value): self
    {
        $h = clone $this;
        $h->fields[] = self::field($name, $value);
        return $h;
    }

    /** A copy without a field. */
    public function without(string $name): self
    {
        $h = clone $this;
        $h->fields = array_values(array_filter($this->fields, static fn (array $f): bool => strcasecmp($f[0], $name) !== 0));
        return $h;
    }

    /** A copy in which every field of `$other` replaces the fields of that name. */
    public function merge(Headers $other): self
    {
        $h = $this;
        foreach ($other->names() as $name) {
            $h = $h->with($name, $other->all($name));
        }
        return $h;
    }

    /**
     * The fields as `[name, value]` pairs, in order.
     *
     * @return list<array{0: string, 1: string}>
     */
    public function toList(): array
    {
        return $this->fields;
    }

    /**
     * The fields as a map of lower-cased name to values.
     *
     * @return array<string, list<string>>
     */
    public function toArray(): array
    {
        $out = [];
        foreach ($this->fields as [$n, $v]) {
            $out[strtolower($n)][] = $v;
        }
        return $out;
    }

    public function count(): int
    {
        return count($this->fields);
    }

    /** @return \Generator<string, string> */
    public function getIterator(): \Generator
    {
        foreach ($this->fields as [$n, $v]) {
            yield $n => $v;
        }
    }
}
