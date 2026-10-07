<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Model;

use Ebremer\Lws\Internal\JsonAccess;
use Ebremer\Lws\Json\Json;

/** A verification method of a controlled identifier document (`JsonWebKey` with `publicKeyJwk`). */
final class VerificationMethod
{
    public readonly ?string $id;
    public readonly ?string $type;
    public readonly ?string $controller;
    /** @var array<array-key, mixed>|null */
    public readonly ?array $publicKeyJwk;

    /** @param array<array-key, mixed> $raw */
    public function __construct(public readonly array $raw)
    {
        $this->id = JsonAccess::str($raw, 'id');
        $this->type = JsonAccess::str($raw, 'type');
        $this->controller = JsonAccess::str($raw, 'controller');
        $this->publicKeyJwk = Json::members($raw['publicKeyJwk'] ?? null);
    }
}
