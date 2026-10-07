<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Exception;

/** A `410 Gone` (an expired search page link, among others). */
class GoneException extends HttpException
{
}
