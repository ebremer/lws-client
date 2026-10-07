<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Exception;

/** A `422 Unprocessable Content`, such as a JSON Patch that cannot be applied. */
class UnprocessableContentException extends HttpException
{
}
