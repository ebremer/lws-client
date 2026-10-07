<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

use Ebremer\Lws\Json\Json;

/**
 * One link context of a linkset: an anchor and its relations (relation type → targets, in order). Members that are
 * neither the anchor nor arrays of targets are kept in `extra`, so that the context round-trips.
 */
final class LinkContext
{
    /**
     * @param array<string, list<LinkTarget>> $relations
     * @param array<array-key, mixed> $extra
     */
    public function __construct(public ?string $anchor = null, public array $relations = [], public array $extra = [])
    {
    }

    /** @internal */
    public static function fromJson(mixed $json): ?self
    {
        $o = Json::members($json);
        if ($o === null) {
            return $json instanceof \stdClass ? new self() : null;
        }
        $c = new self();
        foreach ($o as $key => $value) {
            $key = (string) $key;
            if ($key === 'anchor' && is_string($value)) {
                $c->anchor = $value;
                continue;
            }
            if (Json::isList($value)) {
                $targets = array_map(LinkTarget::fromJson(...), $value);
                if (!in_array(null, $targets, true)) {
                    /** @var list<LinkTarget> $targets */
                    $c->relations[$key] = $targets;
                    continue;
                }
            }
            $c->extra[$key] = $value;
        }
        return $c;
    }

    /**
     * The targets of a relation type.
     *
     * @return list<LinkTarget>
     */
    public function targets(string $rel): array
    {
        return $this->relations[$rel] ?? [];
    }

    /** @return array<array-key, mixed>|\stdClass the context object */
    public function toJson(): array|\stdClass
    {
        $o = [];
        if ($this->anchor !== null) {
            $o['anchor'] = $this->anchor;
        }
        foreach ($this->relations as $rel => $targets) {
            $o[$rel] = array_map(static fn (LinkTarget $t): array => $t->toJson(), $targets);
        }
        foreach ($this->extra as $k => $v) {
            $o[$k] = $v;
        }
        return Json::object($o);
    }
}
