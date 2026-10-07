<?php
// SPDX-License-Identifier: MIT
// Discover a storage, then create, read, update, patch, list and delete resources.
//
//   php php/examples/quickstart.php http://localhost:8787/root/
declare(strict_types=1);

require __DIR__ . '/../../vendor/autoload.php';

use Ebremer\Lws\Auth\SelfSignedCredentials;
use Ebremer\Lws\Auth\SigningKey;
use Ebremer\Lws\Auth\TokenExchangeAuthenticator;
use Ebremer\Lws\Exception\PreconditionFailedException;
use Ebremer\Lws\Json\JsonPatch;
use Ebremer\Lws\LwsClient;

$start = $argv[1] ?? 'http://localhost:8787/root/';

// A did:key agent signs its own credential; the client exchanges it for access tokens on demand.
$me = SelfSignedCredentials::didKey(SigningKey::generateP256());
$client = new LwsClient(authenticator: new TokenExchangeAuthenticator($me));
echo "Agent: {$me->agent}\n";

$storage = $client->discoverStorage($start);
$root = $storage->storageRoot();
echo "Storage {$storage->id}, root $root\n";

$folder = $client->createContainer($root, slug: 'quickstart')->location;
$note = $client->createText($folder, 'Hello, LWS!', slug: 'hello.txt')->location;
echo "Created $note\n";

$r = $client->read($note);
echo "Read: {$r->text()} (ETag {$r->etag})\n";

// Optimistic concurrency: only replace it if nobody changed it since we read it.
$client->update($note, 'Hello again', 'text/plain', ifMatch: $r->etag);
try {
    $client->update($note, 'lost update', 'text/plain', ifMatch: $r->etag);
} catch (PreconditionFailedException $e) {
    echo "Stale update rejected with HTTP {$e->status}\n";
}

$profile = $client->createJson($folder, ['name' => 'Alice', 'age' => 30], slug: 'profile.json')->location;
$client->patch($profile, (new JsonPatch())->replace('/age', 31)->add('/city', 'Boston'));
echo 'Patched: ', $client->read($profile)->text(), "\n";

echo "Members of $folder:\n";
foreach ($client->listContainer($folder) as $item) {   // follows rel="next" pages lazily
    echo "  {$item->id} {$item->format}\n";
}

$client->delete($folder, recursive: true);   // Depth: infinity
echo "Deleted $folder\n";
