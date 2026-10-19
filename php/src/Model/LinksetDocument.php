<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

use Ebremer\Lws\Exception\ProtocolException;
use Ebremer\Lws\Internal\Url;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\Json\JsonPatch;
use Ebremer\Lws\Json\JsonPointer;
use Ebremer\Lws\LinkRelation;

/** A linkset as read from its linkset resource: the resource URL, the linkset, its ETag and allowed methods. */
final class LinksetDocument
{
    public readonly ?string $etag;
    /** @var list<string> */
    public readonly array $allow;
    /** @var list<string> */
    public readonly array $acceptPatch;

    /** @param string $url the linkset resource */
    public function __construct(public readonly string $url, public readonly Linkset $linkset, public readonly ResourceMetadata $metadata)
    {
        $this->etag = $metadata->etag;
        $this->allow = $metadata->allow;
        $this->acceptPatch = $metadata->acceptPatch;
    }

    /** Whether the linkset resource allows `PUT` (else update it with `PATCH`). */
    public function supportsPut(): bool
    {
        foreach ($this->allow as $m) {
            if (strcasecmp($m, 'PUT') === 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * The JSON Patch that moves a resource into another container (lws10-core "Moving Resources"): `test` that the
     * resource's `up` link still holds the target as read, and `replace` it with the destination. The resource's
     * context is the first whose anchor resolves (against the linkset's URL) to `resourceUrl`, or the only context
     * when it has no anchor; its `up` link is its first `up` target with a string `href`.
     *
     * @param string $destinationUrl the container to move the resource into (absolute)
     * @throws ProtocolException when the linkset has no context of the resource, or that context no `up` link
     */
    public function movePatch(string $resourceUrl, string $destinationUrl): JsonPatch
    {
        $contexts = $this->linkset->contexts;
        $index = null;
        foreach ($contexts as $i => $c) {
            $anchor = $c->anchor === null ? null : Url::resolve($c->anchor, $this->url);
            if ($anchor !== null && Url::canonical($anchor) === Url::canonical($resourceUrl)) {
                $index = $i;
                break;
            }
        }
        if ($index === null && count($contexts) === 1 && $contexts[0]->anchor === null) {
            $index = 0;
        }
        if ($index === null) {
            throw new ProtocolException("The linkset {$this->url} does not describe $resourceUrl");
        }
        $context = $contexts[$index];
        // A relation whose targets are not all link target objects is kept in `extra`, as received.
        $targets = $context->relations[LinkRelation::UP] ?? $context->extra[LinkRelation::UP] ?? [];
        foreach (is_array($targets) ? $targets : [] as $j => $t) {
            $href = $t instanceof LinkTarget ? $t->href : (Json::members($t)['href'] ?? null);
            if (is_string($href)) {
                $pointer = JsonPointer::fromSegments('linkset', $index, LinkRelation::UP, $j, 'href');
                return (new JsonPatch())->test($pointer, $href)->replace($pointer, $destinationUrl);
            }
        }
        throw new ProtocolException("The linkset {$this->url} has no up link of $resourceUrl to replace");
    }
}
