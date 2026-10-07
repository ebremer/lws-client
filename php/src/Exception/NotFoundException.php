<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Exception;

/** A `404 Not Found`: the target does not exist (or an expired search page link). */
class NotFoundException extends HttpException
{
}
