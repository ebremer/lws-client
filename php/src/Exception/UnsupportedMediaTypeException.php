<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Exception;

use Ebremer\Lws\Internal\HeaderLists;

/** A `415 Unsupported Media Type`, with the formats the server accepts instead. */
class UnsupportedMediaTypeException extends HttpException
{
    /**
     * The patch formats of `Accept-Patch`.
     *
     * @return list<string>
     */
    public function acceptPatch(): array
    {
        return array_map(HeaderLists::unquote(...), HeaderLists::split($this->headers->all('accept-patch')));
    }

    /**
     * The query formats of `Accept-Query`.
     *
     * @return list<string>
     */
    public function acceptQuery(): array
    {
        return array_map(HeaderLists::unquote(...), HeaderLists::split($this->headers->all('accept-query')));
    }
}
