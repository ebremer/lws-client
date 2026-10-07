<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws;

/** Access policy constraint operators. */
final class ConstraintOperator
{
    public const EQ = 'eq';
    public const IS_ANY_OF = 'isAnyOf';
    public const GTEQ = 'gteq';
    public const LTEQ = 'lteq';

    private function __construct()
    {
    }
}
