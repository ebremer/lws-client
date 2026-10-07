<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Access;

use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\ResourceType;

/** An access policy: the actions an assignee may take on a target, under constraints. */
final class AccessPolicy
{
    /**
     * @param list<string> $actions `read`, `modify`, `create`, `delete` (see {@see \Ebremer\Lws\AccessAction})
     * @param string $assignee the agent (an absolute IRI)
     * @param list<Constraint> $constraints
     * @param list<string> $types
     * @throws \InvalidArgumentException without actions, or with an assignee that is not an absolute IRI
     */
    public function __construct(
        public readonly array $actions,
        public readonly string $assignee,
        public readonly ?AccessTarget $target = null,
        public readonly array $constraints = [],
        public readonly array $types = [ResourceType::ACCESS_POLICY],
    ) {
        if ($actions === []) {
            throw new \InvalidArgumentException('An access policy needs at least one action');
        }
        if (!Url::hasScheme($assignee)) {
            throw new \InvalidArgumentException("The assignee must be an absolute IRI: $assignee");
        }
    }

    /** @return array<string, mixed> */
    public function toJson(): array
    {
        $o = ['type' => $this->types, 'action' => $this->actions, 'assignee' => $this->assignee];
        if ($this->target !== null) {
            $o['target'] = $this->target->toJson();
        }
        if ($this->constraints !== []) {
            $o['constraint'] = array_map(static fn (Constraint $c): array => $c->toJson(), $this->constraints);
        }
        return $o;
    }

    /**
     * @throws ProtocolException when it is not a valid policy
     * @internal
     */
    public static function parse(mixed $json): self
    {
        $o = JsonAccess::object($json, 'The access policy');
        $assignee = JsonAccess::str($o, 'assignee') ?? throw new ProtocolException('The access policy has no assignee');
        $constraints = array_values(array_map(Constraint::parse(...), Json::isList($o['constraint'] ?? null) ? $o['constraint'] : []));
        $target = Json::members($o['target'] ?? null);
        try {
            return new self(JsonAccess::strings($o, 'action'), $assignee, $target === null ? null : AccessTarget::parse($target),
                $constraints, JsonAccess::types($o));
        } catch (\InvalidArgumentException $e) {
            throw new ProtocolException($e->getMessage(), 0, $e);
        }
    }
}
