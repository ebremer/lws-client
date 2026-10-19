<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws;

/** Capability types of a storage description (`capability[].type`). */
final class CapabilityType
{
    /** Resources can move between containers by a change of their `up` link (see {@see LwsClient::move()}). */
    public const MOVE_RESOURCE = 'MoveResource';

    private function __construct()
    {
    }
}
