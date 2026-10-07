<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

/**
 * Structured Field Values for HTTP (RFC 8941, with the dates and display strings of RFC 9651): parsing and
 * canonical serialization of dictionaries, lists and items, as `Signature-Input`, `Signature` and `Content-Digest`
 * need. Dictionaries keep member order.
 */
final class StructuredFields
{
    private const TCHAR = "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const KEY_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789_-.*';

    private string $s;
    private int $i = 0;

    private function __construct(string $input)
    {
        $this->s = $input;
    }

    /**
     * Parses a dictionary.
     *
     * @return array<string, SfItem|SfInnerList>
     * @throws StructuredFieldException
     */
    public static function parseDictionary(string $input): array
    {
        $p = new self($input);
        $p->skipSp();
        $out = [];
        while (!$p->atEnd()) {
            $key = $p->key();
            if ($p->peek() === '=') {
                $p->i++;
                $out[$key] = $p->itemOrInnerList();
            } else {
                $out[$key] = new SfItem(true, $p->parameters());
            }
            $p->skipOws();
            if ($p->atEnd()) {
                break;
            }
            $p->expect(',');
            $p->skipOws();
            if ($p->atEnd()) {
                throw new StructuredFieldException('Trailing comma in a dictionary');
            }
        }
        return $out;
    }

    /**
     * Parses a list.
     *
     * @return list<SfItem|SfInnerList>
     * @throws StructuredFieldException
     */
    public static function parseList(string $input): array
    {
        $p = new self($input);
        $p->skipSp();
        $out = [];
        while (!$p->atEnd()) {
            $out[] = $p->itemOrInnerList();
            $p->skipOws();
            if ($p->atEnd()) {
                break;
            }
            $p->expect(',');
            $p->skipOws();
            if ($p->atEnd()) {
                throw new StructuredFieldException('Trailing comma in a list');
            }
        }
        return $out;
    }

    /**
     * Parses an item.
     *
     * @throws StructuredFieldException
     */
    public static function parseItem(string $input): SfItem
    {
        $p = new self($input);
        $p->skipSp();
        $item = $p->item();
        $p->skipSp();
        if (!$p->atEnd()) {
            throw new StructuredFieldException('Unexpected characters after an item');
        }
        return $item;
    }

    // ------------------------------------------------------------------------------------------------
    // Parsing

    private function atEnd(): bool
    {
        // Trailing spaces are discarded at the top level.
        return strspn($this->s, ' ', $this->i) === strlen($this->s) - $this->i;
    }

    private function peek(): string
    {
        return $this->s[$this->i] ?? '';
    }

    private function expect(string $c): void
    {
        if ($this->peek() !== $c) {
            throw new StructuredFieldException("Expected '$c' at position {$this->i}");
        }
        $this->i++;
    }

    private function skipSp(): void
    {
        $this->i += strspn($this->s, ' ', $this->i);
    }

    private function skipOws(): void
    {
        $this->i += strspn($this->s, " \t", $this->i);
    }

    private function key(): string
    {
        $c = $this->peek();
        if (!($c === '*' || ($c >= 'a' && $c <= 'z'))) {
            throw new StructuredFieldException("A key must start with a lower-case letter or '*' at position {$this->i}");
        }
        $len = strspn($this->s, self::KEY_CHARS, $this->i);
        $key = substr($this->s, $this->i, $len);
        $this->i += $len;
        return $key;
    }

    private function itemOrInnerList(): SfItem|SfInnerList
    {
        return $this->peek() === '(' ? $this->innerList() : $this->item();
    }

    private function innerList(): SfInnerList
    {
        $this->expect('(');
        $items = [];
        while ($this->i < strlen($this->s)) {
            $this->skipSp();
            if ($this->peek() === ')') {
                $this->i++;
                return new SfInnerList($items, $this->parameters());
            }
            $items[] = $this->item();
            $c = $this->peek();
            if ($c !== ' ' && $c !== ')') {
                throw new StructuredFieldException("Expected ' ' or ')' in an inner list at position {$this->i}");
            }
        }
        throw new StructuredFieldException('Unterminated inner list');
    }

    private function item(): SfItem
    {
        $value = $this->bareItem();
        return new SfItem($value, $this->parameters());
    }

    /** @return array<string, int|float|string|bool|SfToken|SfBytes|SfDate|SfDisplayString> */
    private function parameters(): array
    {
        $params = [];
        while ($this->peek() === ';') {
            $this->i++;
            $this->skipSp();
            $key = $this->key();
            $value = true;
            if ($this->peek() === '=') {
                $this->i++;
                $value = $this->bareItem();
            }
            $params[$key] = $value;
        }
        return $params;
    }

    private function bareItem(): int|float|string|bool|SfToken|SfBytes|SfDate|SfDisplayString
    {
        $c = $this->peek();
        return match (true) {
            $c === '-' || ($c >= '0' && $c <= '9') => $this->number(),
            $c === '"' => $this->string(),
            $c === '*' || ($c >= 'a' && $c <= 'z') || ($c >= 'A' && $c <= 'Z') => $this->token(),
            $c === ':' => $this->bytes(),
            $c === '?' => $this->boolean(),
            $c === '@' => $this->date(),
            $c === '%' => $this->displayString(),
            default => throw new StructuredFieldException("Unexpected character '$c' at position {$this->i}"),
        };
    }

    private function number(): int|float
    {
        $start = $this->i;
        $negative = false;
        if ($this->peek() === '-') {
            $negative = true;
            $this->i++;
        }
        $c = $this->peek();
        if (!($c >= '0' && $c <= '9')) {
            throw new StructuredFieldException("Expected a digit at position {$this->i}");
        }
        $intLen = strspn($this->s, '0123456789', $this->i);
        $intPart = substr($this->s, $this->i, $intLen);
        $this->i += $intLen;
        if ($this->peek() !== '.') {
            if ($intLen > 15) {
                throw new StructuredFieldException("Integer too long at position $start");
            }
            $v = (int) $intPart;
            return $negative ? -$v : $v;
        }
        if ($intLen > 12) {
            throw new StructuredFieldException("Decimal too long at position $start");
        }
        $this->i++;
        $fracLen = strspn($this->s, '0123456789', $this->i);
        if ($fracLen < 1 || $fracLen > 3) {
            throw new StructuredFieldException("A decimal needs 1 to 3 fractional digits at position $start");
        }
        $frac = substr($this->s, $this->i, $fracLen);
        $this->i += $fracLen;
        $v = (float) ($intPart . '.' . $frac);
        return $negative ? -$v : $v;
    }

    private function string(): string
    {
        $this->expect('"');
        $out = '';
        $n = strlen($this->s);
        while ($this->i < $n) {
            $c = $this->s[$this->i++];
            if ($c === '\\') {
                $next = $this->s[$this->i] ?? '';
                if ($next !== '"' && $next !== '\\') {
                    throw new StructuredFieldException('Invalid escape in a string');
                }
                $out .= $next;
                $this->i++;
            } elseif ($c === '"') {
                return $out;
            } elseif (ord($c) < 0x20 || ord($c) > 0x7e) {
                throw new StructuredFieldException('Invalid character in a string');
            } else {
                $out .= $c;
            }
        }
        throw new StructuredFieldException('Unterminated string');
    }

    private function token(): SfToken
    {
        $start = $this->i;
        $this->i++;
        $this->i += strspn($this->s, self::TCHAR . ':/', $this->i);
        return new SfToken(substr($this->s, $start, $this->i - $start));
    }

    private function bytes(): SfBytes
    {
        $this->expect(':');
        $len = strspn($this->s, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=', $this->i);
        $b64 = substr($this->s, $this->i, $len);
        $this->i += $len;
        $this->expect(':');
        $decoded = base64_decode($b64, true);
        if ($decoded === false) {
            throw new StructuredFieldException('Invalid base64 in a byte sequence');
        }
        return new SfBytes($decoded);
    }

    private function boolean(): bool
    {
        $this->expect('?');
        $c = $this->peek();
        if ($c !== '0' && $c !== '1') {
            throw new StructuredFieldException("Expected ?0 or ?1 at position {$this->i}");
        }
        $this->i++;
        return $c === '1';
    }

    private function date(): SfDate
    {
        $this->expect('@');
        $v = $this->number();
        if (!is_int($v)) {
            throw new StructuredFieldException('A date must be an integer');
        }
        return new SfDate($v);
    }

    private function displayString(): SfDisplayString
    {
        $this->expect('%');
        $this->expect('"');
        $out = '';
        $n = strlen($this->s);
        while ($this->i < $n) {
            $c = $this->s[$this->i++];
            if ($c === '%') {
                $hex = substr($this->s, $this->i, 2);
                if (strlen($hex) !== 2 || strspn($hex, '0123456789abcdef') !== 2) {
                    throw new StructuredFieldException('Invalid percent-encoding in a display string');
                }
                $out .= chr((int) hexdec($hex));
                $this->i += 2;
            } elseif ($c === '"') {
                if (preg_match('//u', $out) !== 1) {
                    throw new StructuredFieldException('A display string is not valid UTF-8');
                }
                return new SfDisplayString($out);
            } elseif (ord($c) < 0x20 || ord($c) > 0x7e) {
                throw new StructuredFieldException('Invalid character in a display string');
            } else {
                $out .= $c;
            }
        }
        throw new StructuredFieldException('Unterminated display string');
    }

    // ------------------------------------------------------------------------------------------------
    // Serialization

    /**
     * Serializes a dictionary.
     *
     * @param array<string, SfItem|SfInnerList> $dictionary
     */
    public static function serializeDictionary(array $dictionary): string
    {
        $parts = [];
        foreach ($dictionary as $key => $member) {
            $k = self::serializeKey((string) $key);
            if ($member instanceof SfItem && $member->value === true) {
                $parts[] = $k . self::serializeParams($member->params);
            } else {
                $parts[] = $k . '=' . self::serializeMember($member);
            }
        }
        return implode(', ', $parts);
    }

    /**
     * Serializes a list.
     *
     * @param list<SfItem|SfInnerList> $list
     */
    public static function serializeList(array $list): string
    {
        return implode(', ', array_map(self::serializeMember(...), $list));
    }

    /** Serializes an item or inner list (a dictionary member's value). */
    public static function serializeMember(SfItem|SfInnerList $member): string
    {
        return $member instanceof SfInnerList ? self::serializeInnerList($member) : self::serializeItem($member);
    }

    /** Serializes an item with its parameters. */
    public static function serializeItem(SfItem $item): string
    {
        return self::serializeBareItem($item->value) . self::serializeParams($item->params);
    }

    /** Serializes an inner list canonically: `("a" "b");created=1;keyid="x"`. */
    public static function serializeInnerList(SfInnerList $list): string
    {
        return '(' . implode(' ', array_map(self::serializeItem(...), $list->items)) . ')' . self::serializeParams($list->params);
    }

    /** @param array<string, int|float|string|bool|SfToken|SfBytes|SfDate|SfDisplayString> $params */
    public static function serializeParams(array $params): string
    {
        $s = '';
        foreach ($params as $key => $value) {
            $s .= ';' . self::serializeKey((string) $key);
            if ($value !== true) {
                $s .= '=' . self::serializeBareItem($value);
            }
        }
        return $s;
    }

    /** Serializes a bare item. */
    public static function serializeBareItem(int|float|string|bool|SfToken|SfBytes|SfDate|SfDisplayString $value): string
    {
        if (is_bool($value)) {
            return $value ? '?1' : '?0';
        }
        if (is_int($value)) {
            if (abs($value) > 999_999_999_999_999) {
                throw new StructuredFieldException('Integer out of range');
            }
            return (string) $value;
        }
        if (is_float($value)) {
            return self::serializeDecimal($value);
        }
        if (is_string($value)) {
            if (preg_match('/[^\x20-\x7e]/', $value) === 1) {
                throw new StructuredFieldException('A string may hold printable ASCII only');
            }
            return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $value) . '"';
        }
        if ($value instanceof SfToken) {
            if (preg_match('~^[A-Za-z*][!#$%&\'*+\-.^_`|\~0-9A-Za-z:/]*$~', $value->value) !== 1) {
                throw new StructuredFieldException("Invalid token: {$value->value}");
            }
            return $value->value;
        }
        if ($value instanceof SfBytes) {
            return ':' . base64_encode($value->bytes) . ':';
        }
        if ($value instanceof SfDate) {
            return '@' . $value->seconds;
        }
        $out = '%"';
        $n = strlen($value->value);
        for ($i = 0; $i < $n; $i++) {
            $c = $value->value[$i];
            $o = ord($c);
            $out .= ($c === '%' || $c === '"' || $o < 0x20 || $o > 0x7e) ? sprintf('%%%02x', $o) : $c;
        }
        return $out . '"';
    }

    private static function serializeDecimal(float $value): string
    {
        $rounded = round($value, 3, PHP_ROUND_HALF_EVEN);
        if (abs($rounded) >= 1e12) {
            throw new StructuredFieldException('Decimal out of range');
        }
        $s = rtrim(sprintf('%.3F', $rounded), '0');
        if (str_ends_with($s, '.')) {
            $s .= '0';
        }
        return $s === '-0.0' ? '0.0' : $s;
    }

    private static function serializeKey(string $key): string
    {
        if (preg_match('/^[a-z*][a-z0-9_\-.*]*$/', $key) !== 1) {
            throw new StructuredFieldException("Invalid key: $key");
        }
        return $key;
    }
}
