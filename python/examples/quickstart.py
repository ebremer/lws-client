# SPDX-License-Identifier: MIT
"""Quick start: discover a storage, create / read / update / delete resources, list a container.

    python examples/quickstart.py http://localhost:8787/root/

Authenticates with a freshly generated self-signed did:key identity (works with the mock
server in testing/mock-server; real deployments use their identity provider).
"""

from __future__ import annotations

import sys

from lws_client import (
    JsonPatch,
    LwsClient,
    NotFoundError,
    SelfSignedCredentials,
    SigningKey,
    TokenExchangeAuthenticator,
)


def main(resource_url: str) -> None:
    credentials = SelfSignedCredentials.did_key(SigningKey.generate())
    print("agent:", credentials.agent)

    with LwsClient(authenticator=TokenExchangeAuthenticator(credentials)) as client:
        storage = client.discover_storage(resource_url)
        root = storage.storage_root()
        print("storage:", storage.id, "root:", root)

        folder = client.create_container(root, slug="quickstart")
        print("created container", folder.location)

        note = client.create_text(folder.location, "milk\neggs\nbread\n", slug="shopping.txt")
        resource = client.read(note.location)
        print(f"read {resource.url} ({resource.content_type}, etag {resource.etag}):")
        print(resource.text)

        client.update(note.location, "milk\neggs\nbread\nbutter\n", "text/plain",
                      if_match=resource.etag)

        profile = client.create_json(folder.location, {"name": "Alice", "age": 30},
                                     slug="profile.json", types=["https://schema.org/Person"])
        client.patch(profile.location, JsonPatch().replace("/age", 31))
        print("profile:", client.read_json(profile.location))

        print("members:")
        for item in client.list_container(folder.location):
            kind = "container" if item.is_container else item.format
            print(f"  {item.id}  [{kind}]  {item.size} bytes")

        client.delete(folder.location, recursive=True)
        try:
            client.read(note.location)
        except NotFoundError:
            print("deleted", folder.location)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8787/root/")
