<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Access;

use Ebremer\Lws\ResourceType;

/** An access grant: a storage controller grants an agent access. */
final class AccessGrant extends AccessDocument
{
    protected static function documentType(): string
    {
        return ResourceType::ACCESS_GRANT;
    }
}
