<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Access;

use Ebremer\Lws\ResourceType;

/**
 * An access request: an agent asks a storage's controller for access.
 *
 * ```php
 * $request = AccessRequest::create('https://storage.example/', [
 *     new AccessPolicy(['read'], $me, AccessTarget::containers($folder), [Constraint::purpose('https://purpose.example/x')]),
 * ]);
 * ```
 */
final class AccessRequest extends AccessDocument
{
    protected static function documentType(): string
    {
        return ResourceType::ACCESS_REQUEST;
    }
}
