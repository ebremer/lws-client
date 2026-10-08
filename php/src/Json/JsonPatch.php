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
 * $document = $patch->apply(Json::decode('{"age": 30}'));   // {"age": 31, "city": "Boston"}
 * ```
 *
 * Values are anything `json_encode()` takes (see {@see Json}). Documents to {@see apply()} a patch to are decoded
 * JSON as {@see Json::decode()} returns it.
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

    /**
     * Applies the patch to a document (RFC 6902 §4), atomically: either every operation applies, or a
     * {@see JsonPatchException} is thrown and the document is unchanged. The document is never modified in place.
     *
     * Objects are non-list arrays or `\stdClass` (as {@see Json::decode()} returns them) and arrays are lists; the
     * result keeps the distinction, so it encodes back with {@see Json::encode()} as the patched JSON. `test`
     * compares as RFC 6902 §4.6 says: numbers by value, objects regardless of member order.
     *
     * @param mixed $document the decoded JSON document
     * @return mixed the patched document
     * @throws JsonPatchException when an operation fails: a failed `test`, or a location that does not exist
     */
    public function apply(mixed $document): mixed
    {
        foreach ($this->operations as $i => $op) {
            try {
                $document = self::applyOperation($document, $op);
            } catch (JsonPatchException $e) {
                throw new JsonPatchException("Operation $i ({$op['op']} {$op['path']}): {$e->getMessage()}", $i, $op['path']);
            }
        }
        return $document;
    }

    /**
     * @param array<string, mixed> $op a validated operation
     * @throws JsonPatchException
     */
    private static function applyOperation(mixed $document, array $op): mixed
    {
        $path = JsonPointer::segments($op['path']);
        switch ($op['op']) {
            case 'add':
                return self::addAt($document, $path, $op['value']);
            case 'remove':
                return self::removeAt($document, $path);
            case 'replace':
                self::valueAt($document, $path);
                return $path === [] ? $op['value'] : self::update($document, $path, static fn (mixed $parent, string $token): mixed
                    => self::withMember($parent, $token, $op['value'], false));
            case 'move':
                $from = JsonPointer::segments($op['from']);
                $value = self::valueAt($document, $from);
                if ($from === $path) {
                    return $document;
                }
                if (count($path) > count($from) && array_slice($path, 0, count($from)) === $from) {
                    throw new JsonPatchException('a value cannot be moved into one of its own children');
                }
                return self::addAt(self::removeAt($document, $from), $path, $value);
            case 'copy':
                return self::addAt($document, $path, self::valueAt($document, JsonPointer::segments($op['from'])));
            case 'test':
                if (!self::equal(self::valueAt($document, $path), $op['value'])) {
                    throw new JsonPatchException('the value is not the one tested for');
                }
                return $document;
        }
        throw new JsonPatchException("unknown operation {$op['op']}");
    }

    /**
     * @param list<string> $path
     * @throws JsonPatchException
     */
    private static function addAt(mixed $document, array $path, mixed $value): mixed
    {
        if ($path === []) {
            return $value;
        }
        return self::update($document, $path, static fn (mixed $parent, string $token): mixed
            => self::withMember($parent, $token, $value, true));
    }

    /**
     * @param list<string> $path
     * @throws JsonPatchException
     */
    private static function removeAt(mixed $document, array $path): mixed
    {
        if ($path === []) {
            throw new JsonPatchException('the whole document cannot be removed');
        }
        return self::update($document, $path, static function (mixed $parent, string $token): mixed {
            if (Json::isList($parent)) {
                $index = self::index($parent, $token, false);
                array_splice($parent, $index, 1);
                return $parent;
            }
            $members = self::members($parent);
            if (!array_key_exists($token, $members)) {
                throw new JsonPatchException('the member does not exist');
            }
            unset($members[$token]);
            return Json::object($members);
        });
    }

    /**
     * The value at a location.
     *
     * @param list<string> $path
     * @throws JsonPatchException when there is none
     */
    private static function valueAt(mixed $document, array $path): mixed
    {
        foreach ($path as $token) {
            $document = self::child($document, $token);
        }
        return $document;
    }

    /**
     * A copy of the document with the container that holds the last token of a path replaced by what `$change`
     * makes of it.
     *
     * @param list<string> $path a non-empty path
     * @param \Closure(mixed, string): mixed $change
     * @throws JsonPatchException
     */
    private static function update(mixed $document, array $path, \Closure $change): mixed
    {
        $token = $path[0];
        $rest = array_slice($path, 1);
        if ($rest === []) {
            return $change($document, $token);
        }
        return self::withMember($document, $token, self::update(self::child($document, $token), $rest, $change), false);
    }

    /**
     * The member or element a token names.
     *
     * @throws JsonPatchException when it does not exist
     */
    private static function child(mixed $container, string $token): mixed
    {
        if (Json::isList($container)) {
            return $container[self::index($container, $token, false)];
        }
        $members = self::members($container);
        if (!array_key_exists($token, $members)) {
            throw new JsonPatchException('the location does not exist');
        }
        return $members[$token];
    }

    /**
     * A copy of a container with a member set, or for an array an element set or inserted.
     *
     * @param bool $insert whether to add (insert into an array, or add or replace a member) rather than replace
     * @throws JsonPatchException
     */
    private static function withMember(mixed $container, string $token, mixed $value, bool $insert): mixed
    {
        if (Json::isList($container)) {
            if ($insert) {
                $index = $token === '-' ? count($container) : self::index($container, $token, true);
                array_splice($container, $index, 0, [$value]);
            } else {
                $container[self::index($container, $token, false)] = $value;
            }
            return $container;
        }
        $members = self::members($container);
        if (!$insert && !array_key_exists($token, $members)) {
            throw new JsonPatchException('the member does not exist');
        }
        $members[$token] = $value;
        return Json::object($members);
    }

    /**
     * The members of an object.
     *
     * @return array<array-key, mixed>
     * @throws JsonPatchException when the value is not an object
     */
    private static function members(mixed $value): array
    {
        if ($value instanceof \stdClass) {
            return get_object_vars($value);
        }
        if (is_array($value) && !array_is_list($value)) {
            return $value;
        }
        throw new JsonPatchException('the location is inside a value that is neither an object nor an array');
    }

    /**
     * The array index a token names (RFC 6901 §4: no leading zeros, and "-" names no element).
     *
     * @param list<mixed> $array
     * @param bool $end whether the index just past the last element is allowed, as for insertion
     * @throws JsonPatchException
     */
    private static function index(array $array, string $token, bool $end): int
    {
        if (preg_match('/^(0|[1-9][0-9]{0,17})$/', $token) !== 1) {
            throw new JsonPatchException("\"$token\" is not an array index");
        }
        $index = (int) $token;
        if ($index > count($array) || (!$end && $index === count($array))) {
            throw new JsonPatchException("index $index is out of bounds");
        }
        return $index;
    }

    /** JSON equality (RFC 6902 §4.6): numbers by value, arrays in order, objects regardless of member order. */
    private static function equal(mixed $a, mixed $b): bool
    {
        if ((is_int($a) || is_float($a)) && (is_int($b) || is_float($b))) {
            return $a == $b;
        }
        if (Json::isList($a) || Json::isList($b)) {
            if (!Json::isList($a) || !Json::isList($b) || count($a) !== count($b)) {
                return false;
            }
            foreach ($a as $i => $value) {
                if (!self::equal($value, $b[$i])) {
                    return false;
                }
            }
            return true;
        }
        $objectA = $a instanceof \stdClass || is_array($a);
        $objectB = $b instanceof \stdClass || is_array($b);
        if ($objectA || $objectB) {
            if (!$objectA || !$objectB) {
                return false;
            }
            $ma = $a instanceof \stdClass ? get_object_vars($a) : $a;
            $mb = $b instanceof \stdClass ? get_object_vars($b) : $b;
            if (count($ma) !== count($mb)) {
                return false;
            }
            foreach ($ma as $key => $value) {
                if (!array_key_exists($key, $mb) || !self::equal($value, $mb[$key])) {
                    return false;
                }
            }
            return true;
        }
        return $a === $b;
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
