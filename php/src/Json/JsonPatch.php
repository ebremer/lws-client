<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Json;

use Ebremer\Lws\MediaType;

/**
 * A JSON Patch (RFC 6902), the LWS baseline patch format (`application/json-patch+json`). A fluent builder:
 *
 * ```php
 * $patch = (new JsonPatch())->replace('/age', 31)->add('/city', 'Boston');
 * ```
 *
 * Values are anything `json_encode()` takes (see {@see Json}).
 *
 * @implements \IteratorAggregate<int, array<string, mixed>>
 */
final class JsonPatch implements \IteratorAggregate, \Countable, \JsonSerializable, \Stringable
{
    public const MEDIA_TYPE = MediaType::JSON_PATCH;

    /** @var list<array<string, mixed>> */
    private array $operations = [];

    /**
     * @param iterable<mixed> $operations operation objects to start from (`[['op' => 'remove', 'path' => '/a']]`)
     * @throws \InvalidArgumentException for an operation that is not valid RFC 6902
     */
    public function __construct(iterable $operations = [])
    {
        foreach ($operations as $op) {
            $this->operations[] = self::validate($op);
        }
    }

    /**
     * A patch from its JSON text or decoded array.
     *
     * @throws \InvalidArgumentException when it is not an array of valid operations
     */
    public static function fromJson(mixed $json): self
    {
        if (is_string($json)) {
            try {
                $json = Json::decode($json);
            } catch (\JsonException $e) {
                throw new \InvalidArgumentException('A JSON Patch is not valid JSON: ' . $e->getMessage(), 0, $e);
            }
        }
        if (!Json::isList($json)) {
            throw new \InvalidArgumentException('A JSON Patch must be an array of operations');
        }
        return new self($json);
    }

    public function add(string $path, mixed $value): static
    {
        $this->operations[] = ['op' => 'add', 'path' => $path, 'value' => $value];
        return $this;
    }

    public function remove(string $path): static
    {
        $this->operations[] = ['op' => 'remove', 'path' => $path];
        return $this;
    }

    public function replace(string $path, mixed $value): static
    {
        $this->operations[] = ['op' => 'replace', 'path' => $path, 'value' => $value];
        return $this;
    }

    public function move(string $from, string $path): static
    {
        $this->operations[] = ['op' => 'move', 'from' => $from, 'path' => $path];
        return $this;
    }

    public function copy(string $from, string $path): static
    {
        $this->operations[] = ['op' => 'copy', 'from' => $from, 'path' => $path];
        return $this;
    }

    public function test(string $path, mixed $value): static
    {
        $this->operations[] = ['op' => 'test', 'path' => $path, 'value' => $value];
        return $this;
    }

    /**
     * The operations, as JSON objects.
     *
     * @return list<array<string, mixed>>
     */
    public function operations(): array
    {
        return $this->operations;
    }

    /** @return list<array<string, mixed>> */
    public function toJson(): array
    {
        return $this->operations;
    }

    /** The serialized patch. */
    public function encode(): string
    {
        return Json::encode($this->operations);
    }

    /** @return list<array<string, mixed>> */
    public function jsonSerialize(): array
    {
        return $this->operations;
    }

    public function count(): int
    {
        return count($this->operations);
    }

    /** @return \ArrayIterator<int, array<string, mixed>> */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->operations);
    }

    public function __toString(): string
    {
        return $this->encode();
    }

    /** @return array<string, mixed> */
    private static function validate(mixed $op): array
    {
        $o = Json::members($op);
        $name = is_array($o) ? ($o['op'] ?? null) : null;
        if (!is_array($o) || !is_string($name) || !is_string($o['path'] ?? null)) {
            throw new \InvalidArgumentException('A JSON Patch operation needs string "op" and "path" members');
        }
        $pointer = static function (string $p): void {
            if ($p !== '' && !str_starts_with($p, '/')) {
                throw new \InvalidArgumentException("Not a JSON Pointer: $p");
            }
        };
        $pointer($o['path']);
        switch ($name) {
            case 'add':
            case 'replace':
            case 'test':
                if (!array_key_exists('value', $o)) {
                    throw new \InvalidArgumentException("A JSON Patch '$name' operation needs a value");
                }
                return ['op' => $name, 'path' => $o['path'], 'value' => $o['value']];
            case 'remove':
                return ['op' => $name, 'path' => $o['path']];
            case 'move':
            case 'copy':
                if (!is_string($o['from'] ?? null)) {
                    throw new \InvalidArgumentException("A JSON Patch '$name' operation needs a string 'from'");
                }
                $pointer($o['from']);
                return ['op' => $name, 'from' => $o['from'], 'path' => $o['path']];
            default:
                throw new \InvalidArgumentException("Unknown JSON Patch operation: $name");
        }
    }
}
