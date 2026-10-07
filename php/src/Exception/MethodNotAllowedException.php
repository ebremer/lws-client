<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Exception;

use Ebremer\Lws\Internal\HeaderLists;

/** A `405 Method Not Allowed` (such as a PUT to a linkset that only allows PATCH). */
class MethodNotAllowedException extends HttpException
{
    /**
     * The methods the `Allow` header lists.
     *
     * @return list<string>
     */
    public function allow(): array
    {
        return HeaderLists::split($this->headers->all('allow'));
    }
}
