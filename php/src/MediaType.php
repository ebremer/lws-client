<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws;

/** Media types. */
final class MediaType
{
    public const LWS_JSON = 'application/lws+json';
    public const LWS_CID = 'application/lws+cid';
    public const LINKSET_JSON = 'application/linkset+json';
    public const JSON_PATCH = 'application/json-patch+json';
    public const LWS_QUERY_JSON = 'application/lws-query+json';
    public const LD_JSON = 'application/ld+json';
    public const JSON = 'application/json';
    public const PROBLEM_JSON = 'application/problem+json';
    public const FORM = 'application/x-www-form-urlencoded';

    private function __construct()
    {
    }
}
