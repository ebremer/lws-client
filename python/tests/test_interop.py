# SPDX-License-Identifier: MIT
"""Interop scenario (conformance/scenario.md) against the LWS mock server.

Skipped unless ``LWS_TEST_SERVER`` is set, e.g.::

    node testing/mock-server/server.mjs --port 8787
    LWS_TEST_SERVER=http://localhost:8787 pytest tests/test_interop.py
"""

from __future__ import annotations

import os
import queue
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from lws_client import (
    AccessGrant,
    AccessPolicy,
    AccessRequest,
    AccessTarget,
    AsyncLwsClient,
    ConflictError,
    Constraint,
    JsonPatch,
    LwsClient,
    NotFoundError,
    PreconditionFailedError,
    SelfSignedCredentials,
    SigningKey,
    TokenExchangeAuthenticator,
    TypeQuery,
    WebhookVerifier,
)

BASE = os.environ.get("LWS_TEST_SERVER", "").rstrip("/")
pytestmark = pytest.mark.skipif(not BASE, reason="set LWS_TEST_SERVER to run the interop scenario")
PERSON = "https://schema.org/Person"

Delivery = tuple[str, str, list[tuple[str, str]], bytes]


@pytest.fixture
def inbox() -> Iterator[tuple[str, queue.Queue[Delivery]]]:
    received: queue.Queue[Delivery] = queue.Queue()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            received.put(("POST", self.path, list(self.headers.items()), body))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/inbox", received
    finally:
        server.shutdown()
        server.server_close()


def test_interop_scenario(inbox: tuple[str, queue.Queue[Delivery]]) -> None:
    inbox_url, received = inbox
    creds = SelfSignedCredentials.did_key(SigningKey.generate("ES256"))
    with LwsClient(authenticator=TokenExchangeAuthenticator(creds)) as client:
        # 1. authenticate + discover
        sd = client.discover_storage(f"{BASE}/root/")
        assert sd.id == f"{BASE}/"
        assert sd.storage_root() == f"{BASE}/root/"
        for service in (sd.notification_service(), sd.access_request_service(),
                        sd.access_grant_service(), sd.type_index_service(),
                        sd.type_search_service()):
            assert service
        # 2. container
        c = client.create_container(sd.storage_root(), slug=f"interop-python-{int(time.time() * 1000)}")
        container = c.location
        # 3-4. create + read text
        h = client.create(container, "Hello, LWS!", "text/plain", slug="hello.txt").location
        res = client.read(h)
        assert res.text == "Hello, LWS!"
        assert res.etag and res.is_data_resource
        assert res.parent == container and res.linkset and res.storage == f"{BASE}/"
        # 5. conditional read
        assert client.read(h, if_none_match=res.etag).not_modified
        # 6. update + stale update
        client.update(h, "Hello again", "text/plain", if_match=res.etag)
        with pytest.raises(PreconditionFailedError):
            client.update(h, "stale", "text/plain", if_match=res.etag)
        # 7. JSON + JSON Patch
        p = client.create_json(container, {"name": "Alice", "age": 30}, slug="profile.json",
                               types=[PERSON]).location
        client.patch(p, JsonPatch().replace("/age", 31).add("/city", "Boston"))
        assert client.read_json(p) == {"name": "Alice", "age": 31, "city": "Boston"}
        # 8. linkset
        doc = client.read_linkset(p)
        client.patch_linkset(doc.url, JsonPatch().add("/linkset/0/describedby",
                                                      [{"href": "https://example.org/shapes/person"}]),
                             if_match=doc.etag)
        assert "https://example.org/shapes/person" in client.read_linkset(p).linkset.targets(
            "describedby"
        )
        # 9. pagination
        for i in range(6):
            client.create_text(container, f"item {i}", slug=f"item-{i}.txt")
        first = client.read_container(container)
        assert first.total_items == 8 and first.next
        ids = [item.id for item in client.list_container(container)]
        assert len(ids) == 8 and h in ids and p in ids
        # 10. type index / search
        assert PERSON in list(client.list_types(sd.type_index_service() or ""))
        search = sd.type_search_service() or ""
        assert p in [i.id for i in client.search_all(search, TypeQuery.of_types(PERSON))]
        assert "application/lws-query+json" in client.accepted_query_formats(search)
        # 11. notifications
        notifications = sd.service("NotificationService")
        assert notifications is not None
        sub = client.subscribe(notifications, [container], inbox_url)
        assert sub.subscription in [i.id for i in client.list_subscriptions(notifications)]
        client.update(h, "Hello, notifications", "text/plain")
        verifier = WebhookVerifier(client=client, trusted_storages=[sd.id])
        deadline = time.time() + 5
        verified = None
        while verified is None and time.time() < deadline:
            try:
                method, _path, headers, body = received.get(timeout=max(0.0, deadline - time.time()))
            except queue.Empty:
                break
            result = verifier.verify(method, inbox_url, headers, body)
            if any(a.is_update and a.object.id == h for a in result.notification.activities):
                verified = result
        assert verified is not None, "no verified Update notification received"
        assert verified.storage == sd.id
        client.unsubscribe(sub)
        # 12. access requests / grants
        policy = AccessPolicy(actions=["read"], assignee=creds.agent,
                              target=AccessTarget("StorageResource", [container]),
                              constraints=[Constraint.purpose("https://purpose.example/interop")])
        request_url = client.request_access(sd.access_request_service() or "",
                                            AccessRequest(storage=sd.id, access=[policy]))
        assert client.get_access_request(request_url).access[0].assignee == creds.agent
        assert request_url in [i.id for i in client.list_access_requests(
            sd.access_request_service() or "")]
        grant_url = client.grant_access(sd.access_grant_service() or "",
                                        AccessGrant(storage=sd.id, access=[policy]))
        assert client.get_access_grant(grant_url).storage == sd.id
        client.revoke_access_grant(grant_url)
        client.cancel_access_request(request_url)
        # 13. delete
        with pytest.raises(ConflictError):
            client.delete(container)
        client.delete(container, recursive=True)
        with pytest.raises(NotFoundError):
            client.read(h)


@pytest.mark.anyio
async def test_interop_async_ed25519() -> None:
    creds = SelfSignedCredentials.did_key(SigningKey.generate("EdDSA"))
    async with AsyncLwsClient(authenticator=TokenExchangeAuthenticator(creds)) as client:
        sd = await client.discover_storage(f"{BASE}/root/")
        c = await client.create_container(sd.storage_root(), slug="interop-python-async")
        await client.create_text(c.location, "async")
        assert len([i async for i in client.list_container(c.location)]) == 1
        await client.delete(c.location, recursive=True)
