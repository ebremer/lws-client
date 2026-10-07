<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws;

/** `Prefer` header values. */
final class Prefer
{
    public const SET_LINKSET = 'set-linkset';
    public const LINK_RELATIONS = 'https://www.w3.org/ns/lws#PreferLinkRelations';

    private function __construct()
    {
    }
}
