<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

/** A structured field value that does not parse (or a value that cannot be serialized). */
final class StructuredFieldException extends \UnexpectedValueException
{
}
