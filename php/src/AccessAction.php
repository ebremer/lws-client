<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws;

/** Access profile actions. */
final class AccessAction
{
    public const READ = 'read';
    public const MODIFY = 'modify';
    public const CREATE = 'create';
    public const DELETE = 'delete';

    private function __construct()
    {
    }
}
