<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

use Ebremer\Lws\Internal\HeaderLists;
use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Json\Json;
use Ebremer\Lws\MediaType;

/** RFC 9457 problem details from an error response, extension members preserved. */
final class ProblemDetails implements \Stringable
{
    private const STANDARD = ['type', 'title', 'status', 'detail', 'instance'];

    public readonly ?string $type;
    public readonly ?string $title;
    public readonly ?int $status;
    public readonly ?string $detail;
    public readonly ?string $instance;
    /** @var array<array-key, mixed> the members other than the five standard ones */
    public readonly array $extensions;

    /** @param array<array-key, mixed> $raw the problem object */
    public function __construct(public readonly array $raw)
    {
        $this->type = JsonAccess::str($raw, 'type');
        $this->title = JsonAccess::str($raw, 'title');
        $this->status = JsonAccess::int($raw, 'status');
        $this->detail = JsonAccess::str($raw, 'detail');
        $this->instance = JsonAccess::str($raw, 'instance');
        $this->extensions = array_diff_key($raw, array_flip(self::STANDARD));
    }

    /**
     * Parses an error response body: a JSON object with a problem media type, or a `+json` one with at least a
     * `type`, `title` or `detail`. Returns null otherwise.
     */
    public static function parse(?string $contentType, string $body): ?self
    {
        if (trim($body) === '' || !HeaderLists::isJson($contentType)) {
            return null;
        }
        try {
            $members = Json::members(Json::decode($body));
        } catch (\JsonException) {
            return null;
        }
        if ($members === null) {
            return null;
        }
        $problemType = HeaderLists::essence($contentType) === MediaType::PROBLEM_JSON;
        if (!$problemType && !isset($members['type']) && !isset($members['title']) && !isset($members['detail'])) {
            return null;
        }
        return new self($members);
    }

    public function __toString(): string
    {
        return Json::encode(Json::object($this->raw));
    }
}
