<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Exception;

/** A `409 Conflict`, such as deleting a non-empty container without `recursive`. */
class ConflictException extends HttpException
{
}
