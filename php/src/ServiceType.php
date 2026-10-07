<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws;

/** Service types of a storage description (`service[].type`). */
final class ServiceType
{
    public const STORAGE_ROOT = 'StorageRoot';
    public const NOTIFICATION = 'NotificationService';
    public const ACCESS_REQUEST = 'AccessRequestService';
    public const ACCESS_GRANT = 'AccessGrantService';
    public const TYPE_INDEX = 'TypeIndexService';
    public const TYPE_SEARCH = 'TypeSearchService';

    private function __construct()
    {
    }
}
