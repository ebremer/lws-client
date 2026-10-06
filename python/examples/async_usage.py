# SPDX-License-Identifier: MIT
"""Async usage: concurrent uploads, async iteration over listings and type search.

    python examples/async_usage.py http://localhost:8787/root/
"""

from __future__ import annotations

import asyncio
import sys

from lws_client import (
    AsyncLwsClient,
    SelfSignedCredentials,
    SigningKey,
    TokenExchangeAuthenticator,
    TypeQuery,
)

PERSON = "https://schema.org/Person"


async def main(resource_url: str) -> None:
    credentials = SelfSignedCredentials.did_key(SigningKey.generate("EdDSA"))
    async with AsyncLwsClient(authenticator=TokenExchangeAuthenticator(credentials)) as client:
        storage = await client.discover_storage(resource_url)
        folder = await client.create_container(storage.storage_root(), slug="async-demo")

        # Concurrent creates share a single token exchange.
        await asyncio.gather(*(
            client.create_json(folder.location, {"name": f"person {i}"}, slug=f"p{i}.json",
                               types=[PERSON])
            for i in range(10)
        ))

        async for item in client.list_container(folder.location):
            print(item.id, item.types)

        search = storage.type_search_service()
        if search:
            matches = [m.id async for m in client.search_all(search, TypeQuery.of_types(PERSON))]
            print(f"{len(matches)} resources typed {PERSON}")

        await client.delete(folder.location, recursive=True)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8787/root/"))
