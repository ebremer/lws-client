<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws;

/** Link relation types. */
final class LinkRelation
{
    public const STORAGE = 'https://www.w3.org/ns/lws#storage';
    public const LINKSET = 'linkset';
    public const UP = 'up';
    public const TYPE = 'type';
    public const FIRST = 'first';
    public const NEXT = 'next';
    public const PREV = 'prev';
    public const LAST = 'last';

    private function __construct()
    {
    }
}
