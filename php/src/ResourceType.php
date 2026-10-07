<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws;

/** Resource and document types. The three resource types are full IRIs (short terms are equivalent, see {@see Vocabulary::typeMatches()}). */
final class ResourceType
{
    public const CONTAINER = 'https://www.w3.org/ns/lws#Container';
    public const DATA_RESOURCE = 'https://www.w3.org/ns/lws#DataResource';
    public const STORAGE_RESOURCE = 'https://www.w3.org/ns/lws#StorageResource';
    public const STORAGE = 'Storage';
    public const NOTIFICATION = 'Notification';
    public const CONTAINER_PAGE = 'ContainerPage';
    public const TYPE_INDEX = 'TypeIndex';
    public const ACCESS_REQUEST = 'AccessRequest';
    public const ACCESS_GRANT = 'AccessGrant';
    public const ACCESS_POLICY = 'AccessPolicy';

    private function __construct()
    {
    }
}
