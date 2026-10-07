<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Ebremer\Lws\Notification;

/** A webhook delivery that passed verification: the notification and the key and storage that signed it. */
final class VerifiedNotification
{
    /**
     * @param string $keyId the `keyid` of the signature (a verification method of the storage)
     * @param string $storage the storage identifier
     * @param string $label the signature label used (`sig1`)
     * @param string $algorithm the signature algorithm (`ecdsa-p256-sha256`, `ed25519`, `ecdsa-p384-sha384`)
     */
    public function __construct(
        public readonly Notification $notification,
        public readonly string $keyId,
        public readonly string $storage,
        public readonly string $label = '',
        public readonly string $algorithm = '',
    ) {
    }
}
