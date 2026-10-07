<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Exception;

/** A `412 Precondition Failed`: an `If-Match` ETag that is no longer current. */
class PreconditionFailedException extends HttpException
{
}
