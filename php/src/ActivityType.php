<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws;

/** Notification activity types. */
final class ActivityType
{
    public const CREATE = 'Create';
    public const UPDATE = 'Update';
    public const DELETE = 'Delete';

    private function __construct()
    {
    }
}
