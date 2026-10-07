<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Exception;

/** A server response that violates the specification: a missing `Location`, a wrong media type, invalid JSON. */
class ProtocolException extends LwsException
{
}
