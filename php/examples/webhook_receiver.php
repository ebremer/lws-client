<?php
// SPDX-License-Identifier: MIT
// Receives and verifies webhook notifications (RFC 9421 signatures) for changes in a storage root.
//
//   php php/examples/webhook_receiver.php http://localhost:8787/root/ 9090
//
// The inbox is an ordinary PHP script: any web server that runs PHP can host it, and WebhookVerifier::verifyGlobals()
// reads the delivery from the request. This example serves itself as the inbox with PHP's built-in server, subscribes
// to the storage root, makes a change and prints the verified notification that arrives.
declare(strict_types=1);

require __DIR__ . '/../../vendor/autoload.php';

use Ebremer\Lws\Auth\SelfSignedCredentials;
use Ebremer\Lws\Auth\SigningKey;
use Ebremer\Lws\Auth\TokenExchangeAuthenticator;
use Ebremer\Lws\Exception\LwsException;
use Ebremer\Lws\LwsClient;
use Ebremer\Lws\Notification\WebhookSubscriptionRequest;
use Ebremer\Lws\Notification\WebhookVerifier;

if (PHP_SAPI === 'cli-server') {
    // The inbox. A delivery that does not verify is answered 4xx, so the storage knows it was refused.
    try {
        $verifier = new WebhookVerifier(trustedStorages: [(string) getenv('LWS_STORAGE')]);
        $verified = $verifier->verifyGlobals((string) getenv('LWS_INBOX'));
        foreach ($verified->notification->activities as $a) {
            file_put_contents((string) getenv('LWS_LOG'), implode(',', $a->types) . " {$a->object->id} (signed by {$verified->keyId})\n", FILE_APPEND);
        }
        http_response_code(204);
    } catch (LwsException|\InvalidArgumentException $e) {
        file_put_contents((string) getenv('LWS_LOG'), "Refused: {$e->getMessage()}\n", FILE_APPEND);
        http_response_code(401);
    }
    return;
}

$start = $argv[1] ?? 'http://localhost:8787/root/';
$port = (int) ($argv[2] ?? 9090);

$client = new LwsClient(authenticator: new TokenExchangeAuthenticator(SelfSignedCredentials::didKey(SigningKey::generateP256())));
$storage = $client->discoverStorage($start);
$notifications = $storage->notificationService() ?? exit("The storage has no notification service\n");
$root = $storage->storageRoot();

// Serve this script as the inbox.
$inbox = "http://127.0.0.1:$port/inbox";
$log = tempnam(sys_get_temp_dir(), 'lws-inbox-');
$server = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", __FILE__], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes,
    null, ['LWS_STORAGE' => $storage->id, 'LWS_INBOX' => $inbox, 'LWS_LOG' => $log] + getenv());
for ($i = 0; $i < 50 && @fsockopen('127.0.0.1', $port) === false; $i++) {
    usleep(100_000);
}

$subscription = $client->subscribe($notifications, new WebhookSubscriptionRequest([$root], $inbox));
echo "Subscribed {$subscription->url}; inbox $inbox\n";

$note = $client->createText($root, 'Hello, webhooks!', slug: 'webhook-demo.txt')->location;
$client->update($note, 'Changed', 'text/plain');
for ($i = 0; $i < 50 && trim((string) file_get_contents($log)) === ''; $i++) {
    usleep(100_000);
}
echo "Received:\n", file_get_contents($log) ?: "  nothing within 5 seconds\n";

$client->unsubscribe($subscription->url);
$client->delete($note);
if (is_resource($server)) {
    proc_terminate($server);
    proc_close($server);
}
unlink($log);
