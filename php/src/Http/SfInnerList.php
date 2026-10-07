<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Http;

/** A structured field inner list (`("@method" "@path");created=1;keyid="k"`): items with list parameters. */
final class SfInnerList
{
    /**
     * @param list<SfItem> $items
     * @param array<string, int|float|string|bool|SfToken|SfBytes|SfDate|SfDisplayString> $params
     */
    public function __construct(public readonly array $items, public readonly array $params = [])
    {
    }
}
