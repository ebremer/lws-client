<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Http\Link;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\Json\Json;

/**
 * A linkset (`application/linkset+json`, RFC 9264): `{"linkset": [{"anchor": "…", "<rel>": [{"href": "…", …}]}]}`.
 *
 * It round-trips: unknown members and target attributes are kept. {@see add()} and {@see remove()} change it in
 * place, for {@see \Ebremer\Lws\LwsClient::updateLinkset()}.
 *
 * @implements \IteratorAggregate<int, LinkContext>
 */
final class Linkset implements \IteratorAggregate, \Countable, \JsonSerializable
{
    /** @param list<LinkContext> $contexts */
    public function __construct(public array $contexts = [])
    {
    }

    /**
     * Parses a linkset document (JSON text or decoded).
     *
     * @throws ProtocolException when it has no `linkset` array of objects
     */
    public static function parse(mixed $json): self
    {
        if (is_string($json)) {
            $json = JsonAccess::parse($json, 'The linkset');
        }
        $o = JsonAccess::object($json, 'The linkset document');
        $list = $o['linkset'] ?? null;
        if (!Json::isList($list)) {
            throw new ProtocolException("The linkset document has no 'linkset' array");
        }
        $contexts = [];
        foreach ($list as $c) {
            $contexts[] = LinkContext::fromJson($c) ?? throw new ProtocolException('A linkset context is not an object');
        }
        return new self($contexts);
    }

    /**
     * Every link, flattened, with targets resolved against their anchors (the anchor as an `anchor` parameter,
     * string attributes as parameters).
     *
     * @return list<Link>
     */
    public function links(): array
    {
        $out = [];
        foreach ($this->contexts as $c) {
            $anchor = $c->anchor === null ? null : Url::resolve($c->anchor);
            foreach ($c->relations as $rel => $targets) {
                foreach ($targets as $t) {
                    $href = Url::resolve($t->href, $anchor);
                    if ($href === null) {
                        continue;
                    }
                    $params = $c->anchor === null ? [] : ['anchor' => $c->anchor];
                    foreach ($t->attributes as $k => $v) {
                        if (is_string($v)) {
                            $params[(string) $k] = $v;
                        }
                    }
                    $out[] = new Link($href, (string) $rel, $params);
                }
            }
        }
        return $out;
    }

    /**
     * The targets of a relation type, in every context.
     *
     * @return list<LinkTarget>
     */
    public function targets(string $rel): array
    {
        $out = [];
        foreach ($this->contexts as $c) {
            array_push($out, ...$c->targets($rel));
        }
        return $out;
    }

    /**
     * The targets of a relation type in the context of an anchor (null: the context without anchor).
     *
     * @return list<LinkTarget>
     */
    public function targetsOf(?string $anchor, string $rel): array
    {
        return $this->context($anchor)?->targets($rel) ?? [];
    }

    /**
     * The target URLs of a relation type, in every context or (with `$anchor`) in one.
     *
     * @return list<string>
     */
    public function hrefs(string $rel, ?string $anchor = null): array
    {
        $targets = func_num_args() > 1 ? $this->targetsOf($anchor, $rel) : $this->targets($rel);
        return array_map(static fn (LinkTarget $t): string => $t->href, $targets);
    }

    /** The context of an anchor (null: the context without anchor), or null. */
    public function context(?string $anchor): ?LinkContext
    {
        foreach ($this->contexts as $c) {
            if ($c->anchor === $anchor) {
                return $c;
            }
        }
        return null;
    }

    /**
     * Adds a link target, creating the context of the anchor when there is none.
     *
     * @param array<string, mixed> $attributes target attributes (`['type' => 'text/turtle']`)
     */
    public function add(?string $anchor, string $rel, string $href, array $attributes = []): static
    {
        $target = new LinkTarget($href, $attributes);
        $c = $this->context($anchor);
        if ($c === null) {
            $this->contexts[] = new LinkContext($anchor, [$rel => [$target]]);
        } else {
            $c->relations[$rel][] = $target;
        }
        return $this;
    }

    /**
     * Removes the targets of a relation type in the context of an anchor (only those with `href`, when given);
     * a relation left without targets is dropped. Returns how many targets were removed.
     */
    public function remove(?string $anchor, string $rel, ?string $href = null): int
    {
        $c = $this->context($anchor);
        if ($c === null || !isset($c->relations[$rel])) {
            return 0;
        }
        $before = count($c->relations[$rel]);
        $kept = $href === null ? [] : array_values(array_filter($c->relations[$rel], static fn (LinkTarget $t): bool => $t->href !== $href));
        if ($kept === []) {
            unset($c->relations[$rel]);
        } else {
            $c->relations[$rel] = $kept;
        }
        return $before - count($kept);
    }

    /** @return array{linkset: list<array<array-key, mixed>|\stdClass>} the document */
    public function toJson(): array
    {
        return ['linkset' => array_map(static fn (LinkContext $c): array|\stdClass => $c->toJson(), $this->contexts)];
    }

    /** @return array{linkset: list<array<array-key, mixed>|\stdClass>} */
    public function jsonSerialize(): array
    {
        return $this->toJson();
    }

    /** The serialized document. */
    public function encode(): string
    {
        return Json::encode($this->toJson());
    }

    /** The number of link targets. */
    public function count(): int
    {
        $n = 0;
        foreach ($this->contexts as $c) {
            foreach ($c->relations as $targets) {
                $n += count($targets);
            }
        }
        return $n;
    }

    /** @return \ArrayIterator<int, LinkContext> */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->contexts);
    }
}
