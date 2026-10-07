<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws;

/** Access policy constraint left operands. */
final class ConstraintOperand
{
    public const CLIENT = 'client';
    public const FORMAT = 'format';
    public const TYPE = 'type';
    public const PURPOSE = 'purpose';
    public const DATE_TIME = 'dateTime';

    private function __construct()
    {
    }
}
