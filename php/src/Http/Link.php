<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\LinkRelation;

/**
 * A web link (RFC 8288): an absolute target, one relation type and the target attributes (parameters other than
 * `rel`, with lower-cased names; a valueless parameter has the value `''`).
 */
final class Link implements \Stringable
{
    /** @var array<string, string> */
    public readonly array $params;

    /**
     * @param string $href the target, an absolute URI
     * @param string $rel one relation type (registered names are lower-cased, extension relations kept as they are)
     * @param array<string, string> $params target attributes; names are lower-cased, the first of a name wins
     */
    public function __construct(public readonly string $href, public readonly string $rel, array $params = [])
    {
        $p = [];
        foreach ($params as $k => $v) {
            $p[strtolower((string) $k)] ??= $v;
        }
        $this->params = $p;
    }

    /** A `rel="type"` link to a type IRI, as sent when creating a resource. */
    public static function typeLink(string $typeIri): self
    {
        return new self($typeIri, LinkRelation::TYPE);
    }

    /** The `type` attribute (the target's media type hint), or null. */
    public function type(): ?string
    {
        return $this->params['type'] ?? null;
    }

    /** The `anchor` attribute, or null. */
    public function anchor(): ?string
    {
        return $this->params['anchor'] ?? null;
    }

    /** The `title`, decoded from `title*` (RFC 8187) when that is present, or null. */
    public function title(): ?string
    {
        if (isset($this->params['title*'])) {
            $decoded = LinkHeader::decodeExtValue($this->params['title*']);
            if ($decoded !== null) {
                return $decoded;
            }
        }
        return $this->params['title'] ?? null;
    }

    /** An attribute by name (case-insensitive), or null. */
    public function param(string $name): ?string
    {
        return $this->params[strtolower($name)] ?? null;
    }

    /** A copy with one more attribute. */
    public function withParam(string $name, string $value): self
    {
        return new self($this->href, $this->rel, [...$this->params, strtolower($name) => $value]);
    }

    /** Whether the relation type matches (registered names case-insensitively, extension relations exactly). */
    public function hasRel(string $rel): bool
    {
        return $this->rel === LinkHeader::normalizeRel($rel);
    }

    /** Whether two links have the same target, relation and attributes. */
    public function equals(Link $other): bool
    {
        $a = $this->params;
        $b = $other->params;
        ksort($a);
        ksort($b);
        return $this->href === $other->href && $this->rel === $other->rel && $a === $b;
    }

    /** The link as a `Link` header value: `<href>; rel="rel"; name="value"`. */
    public function __toString(): string
    {
        return LinkHeader::format($this);
    }

    /**
     * The first link with a relation type, or null.
     *
     * @param iterable<Link> $links
     */
    public static function first(iterable $links, string $rel): ?self
    {
        $r = LinkHeader::normalizeRel($rel);
        foreach ($links as $l) {
            if ($l->rel === $r) {
                return $l;
            }
        }
        return null;
    }

    /**
     * The links with a relation type.
     *
     * @param iterable<Link> $links
     * @return list<Link>
     */
    public static function all(iterable $links, string $rel): array
    {
        $r = LinkHeader::normalizeRel($rel);
        $out = [];
        foreach ($links as $l) {
            if ($l->rel === $r) {
                $out[] = $l;
            }
        }
        return $out;
    }

    /** Whether the target is an absolute URI. */
    public function isAbsolute(): bool
    {
        return Url::hasScheme($this->href);
    }
}
