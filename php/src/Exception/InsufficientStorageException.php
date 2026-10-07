<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Exception;

/** A `507 Insufficient Storage`: a quota is exceeded. */
class InsufficientStorageException extends HttpException
{
}
