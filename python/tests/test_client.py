# SPDX-License-Identifier: MIT
"""End-to-end operation tests against an in-memory LWS server (httpx.MockTransport)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator

import httpx
import pytest
from fakeserver import FakeLws

from lws_client import (
    AccessGrant,
    AccessPolicy,
    AccessRequest,
    AccessTarget,
    AsyncLwsClient,
    ConflictError,
    Constraint,
    JsonPatch,
    JsonPointer,
    Link,
    LwsClient,
    NotFoundError,
    PreconditionFailedError,
    ProtocolError,
    SelfSignedCredentials,
    SigningKey,
    TokenExchangeAuthenticator,
    TypeQuery,
    UnsupportedError,
    UnsupportedMediaTypeError,
)

PERSON = "https://schema.org/Person"


def sync_client(fake: FakeLws, key: SigningKey | None = None) -> LwsClient:
    auth = TokenExchangeAuthenticator(SelfSignedCredentials.did_key(key or SigningKey.generate()))
    return LwsClient(authenticator=auth, http_client=httpx.Client(transport=httpx.MockTransport(fake)))


def async_client(fake: FakeLws, key: SigningKey | None = None) -> AsyncLwsClient:
    auth = TokenExchangeAuthenticator(SelfSignedCredentials.did_key(key or SigningKey.generate()))
    return AsyncLwsClient(
        authenticator=auth, http_client=httpx.AsyncClient(transport=httpx.MockTransport(fake))
    )


@pytest.fixture
def fake() -> FakeLws:
    return FakeLws(auth=True, page_size=2)


@pytest.fixture
def client(fake: FakeLws) -> Iterator[LwsClient]:
    with sync_client(fake) as c:
        yield c


def test_full_scenario_sync(fake: FakeLws, client: LwsClient) -> None:
    sd = client.discover_storage(fake.root)
    assert sd.id == fake.storage_id
    assert sd.storage_root() == fake.root  # resolved from "/root/"
    assert sd.notification_service() == fake.notifications
    assert fake.metadata_requests == 1 and len(fake.token_requests) == 1

    c = client.create_container(fake.root, slug="notes")
    assert c.location == fake.root + "notes/"
    assert c.is_container and c.parent == fake.root

    h = client.create(c.location, "Hello, LWS!", "text/plain", slug="hello.txt")
    assert h.location == c.location + "hello.txt"
    res = client.read(h.location)
    assert res.text == "Hello, LWS!"
    assert res.etag and res.is_data_resource and res.parent == c.location
    assert res.storage == fake.storage_id and res.linkset == h.location + ".meta"

    assert client.read(h.location, if_none_match=res.etag).not_modified
    part = client.read(h.location, range=(0, 4))
    assert part.status == 206 and part.content == b"Hello" and part.content_range

    upd = client.update(h.location, "Hello again", "text/plain", if_match=res.etag)
    assert upd.status == 204 and upd.etag
    with pytest.raises(PreconditionFailedError):
        client.update(h.location, "stale", "text/plain", if_match=res.etag)

    p = client.create_json(c.location, {"name": "Alice", "age": 30}, slug="profile.json",
                           types=[PERSON])
    client.patch(p.location, JsonPatch().replace("/age", 31).add("/city", "Boston"))
    assert client.read_json(p.location) == {"name": "Alice", "age": 31, "city": "Boston"}
    with pytest.raises(ConflictError):
        client.patch(p.location, JsonPatch().test("/age", 99))
    with pytest.raises(UnsupportedMediaTypeError) as excinfo:
        client.patch(p.location, "x", content_type="application/sparql-update")
    assert excinfo.value.accept_patch == ["application/json-patch+json"]

    doc = client.read_linkset(p.location)
    assert doc.url == p.location + ".meta" and doc.etag and "PATCH" in doc.allow
    client.patch_linkset(
        doc.url,
        JsonPatch().add(JsonPointer.from_segments("linkset", 0, "describedby"),
                        [{"href": "https://example.org/shapes/person"}]),
        if_match=doc.etag,
    )
    again = client.read_linkset(p.location)
    assert again.linkset.targets("describedby") == ["https://example.org/shapes/person"]
    again.linkset.add(p.location, "license", "https://creativecommons.org/licenses/by/4.0/")
    client.update_linkset(again.url, again.linkset, if_match=again.etag)
    assert client.read_linkset_at(again.url).linkset.targets("license")

    for i in range(4):
        client.create_text(c.location, f"item {i}", slug=f"item-{i}.txt")
    first = client.read_container(c.location)
    assert first.total_items == 6 and first.next and len(first.items) == 2
    pages = list(client.container_pages(c.location))
    assert len(pages) == 3
    ids = [i.id for i in client.list_container(c.location)]
    assert len(ids) == 6 and h.location in ids and p.location in ids

    assert PERSON in list(client.list_types(sd.type_index_service() or ""))
    hits = [i.id for i in client.search_all(sd.type_search_service() or "", TypeQuery.of_types(PERSON))]
    assert hits == [p.location]
    assert client.accepted_query_formats(sd.type_search_service() or "") == [
        "application/lws-query+json"
    ]
    assert any(r.method == "QUERY" for r in fake.requests)

    service = sd.service("NotificationService")
    assert service is not None
    sub = client.subscribe(service, [c.location], "https://receiver.example/inbox",
                           expires="2026-12-01T00:00:00Z")
    assert sub.subscription.startswith(fake.notifications)
    assert sub.expires_raw == "2026-12-01T00:00:00Z"
    assert [i.id for i in client.list_subscriptions(service)] == [sub.subscription]
    assert client.get_subscription(sub.subscription).subscription == sub.subscription
    client.unsubscribe(sub)
    assert list(client.list_subscriptions(service)) == []

    agent = client.authenticator.credentials.agent  # type: ignore[union-attr]
    policy = AccessPolicy(actions=["read"], assignee=agent,
                          target=AccessTarget("StorageResource", [c.location]),
                          constraints=[Constraint.purpose("https://purpose.example/x")])
    req_url = client.request_access(sd.access_request_service() or "",
                                    AccessRequest(storage=sd.id, access=[policy]))
    assert client.get_access_request(req_url).access[0].assignee == agent
    assert req_url in [i.id for i in client.list_access_requests(sd.access_request_service() or "")]
    grant_url = client.grant_access(sd.access_grant_service() or "",
                                    AccessGrant(storage=sd.id, access=[policy]))
    assert client.get_access_grant(grant_url).storage == sd.id
    client.revoke_access_grant(grant_url)
    client.cancel_access_request(req_url)
    with pytest.raises(NotFoundError):
        client.get_access_request(req_url)

    with pytest.raises(ConflictError):
        client.delete(c.location)
    client.delete(c.location, recursive=True)
    with pytest.raises(NotFoundError):
        client.read(h.location)
    # one token exchange for the whole session (proactive reuse)
    assert len(fake.token_requests) == 1
    anonymous = [r for r in fake.requests
                 if r.url.host == "storage.example" and "authorization" not in r.headers]
    assert len(anonymous) == 1  # only the very first request went out without a token


@pytest.mark.anyio
async def test_full_scenario_async(fake: FakeLws) -> None:
    async with async_client(fake) as client:
        sd = await client.discover_storage(fake.root)
        root = sd.storage_root()
        c = await client.create_container(root, slug="async")
        h = await client.create_text(c.location, "Hello, LWS!", slug="hello.txt")
        res = await client.read(h.location)
        assert res.text == "Hello, LWS!"
        assert (await client.read(h.location, if_none_match=res.etag)).not_modified
        await client.update(h.location, "Hello again", "text/plain", if_match=res.etag)
        with pytest.raises(PreconditionFailedError):
            await client.update(h.location, "x", "text/plain", if_match=res.etag)
        p = await client.create_json(c.location, {"age": 30}, types=[PERSON], slug="p.json")
        await client.patch(p.location, [{"op": "replace", "path": "/age", "value": 31}])
        assert await client.read_json(p.location) == {"age": 31}
        doc = await client.read_linkset(p.location)
        await client.patch_linkset(doc.url, JsonPatch().add("/linkset/0/describedby",
                                                            [{"href": "https://example.org/s"}]),
                                   if_match=doc.etag)
        assert (await client.read_linkset(p.location)).linkset.targets("describedby")
        for i in range(3):
            await client.create_text(c.location, str(i))
        items = [i.id async for i in client.list_container(c.location)]
        assert len(items) == 5
        assert PERSON in [t async for t in client.list_types(sd.type_index_service() or "")]
        hits = [i.id async for i in client.search_all(sd.type_search_service() or "",
                                                      TypeQuery().all_of(PERSON))]
        assert hits == [p.location]
        sub = await client.subscribe(sd.notification_service() or "", c.location,
                                     "https://receiver.example/inbox")
        assert [i.id async for i in client.list_subscriptions(sd.notification_service() or "")]
        await client.unsubscribe(sub.subscription)
        with pytest.raises(ConflictError):
            await client.delete(c.location)
        await client.delete(c.location, recursive=True)
        with pytest.raises(NotFoundError):
            await client.head(h.location)
        async with client.stream(fake.root) as stream:
            assert stream.metadata.is_container
            assert json.loads(await stream.aread())["type"] == "Container"
    assert len(fake.token_requests) == 1


@pytest.mark.anyio
async def test_concurrent_requests_share_one_exchange(fake: FakeLws) -> None:
    async with async_client(fake) as client:
        await asyncio.gather(*(client.head(fake.root) for _ in range(8)))
    assert len(fake.token_requests) == 1
    assert fake.metadata_requests == 1


def test_streaming_read_and_upload(fake: FakeLws, client: LwsClient) -> None:
    def chunks() -> Iterator[bytes]:
        yield b"part one, "
        yield b"part two"

    # A non-replayable body: the client authenticates with a pre-flight HEAD first.
    created = client.create(fake.root, chunks(), "text/plain", slug="stream.txt")
    storage_requests = [r.method for r in fake.requests if r.url.host == "storage.example"]
    assert storage_requests == ["HEAD", "HEAD", "POST"]
    with client.stream(created.location) as stream:
        assert stream.metadata.content_type == "text/plain"
        assert b"".join(stream.iter_bytes()) == b"part one, part two"


def test_types_and_links_on_create(fake: FakeLws, client: LwsClient) -> None:
    client.create(fake.root, b"{}", "application/json", slug="naïve doc",
                  types=[PERSON], links=[Link("https://example.org/s", "describedby")])
    post = next(r for r in fake.requests if r.method == "POST")
    assert post.headers["slug"] == "na%C3%AFve doc"
    assert post.headers.get_list("link") == [
        '<https://example.org/s>; rel="describedby"', f'<{PERSON}>; rel="type"'
    ]
    created = fake.resources[fake.root + "na%C3%AFve%20doc"]
    assert created.types == [PERSON]
    assert created.links == {"describedby": [{"href": "https://example.org/s"}]}


def test_create_container_and_set_linkset_headers(fake: FakeLws, client: LwsClient) -> None:
    c = client.create_container(fake.root, slug="box")
    post = [r for r in fake.requests if r.method == "POST"][-1]
    assert post.headers["link"] == '<https://www.w3.org/ns/lws#Container>; rel="type"'
    assert post.content == b""
    h = client.create_text(c.location, "x")
    client.update(h.location, "y", "text/plain", links=[Link("https://l.example", "license")],
                  set_linkset=True)
    put = [r for r in fake.requests if r.method == "PUT"][-1]
    assert put.headers["prefer"] == "set-linkset"
    assert put.headers["link"] == '<https://l.example>; rel="license"'


def test_delete_headers(fake: FakeLws, client: LwsClient) -> None:
    c = client.create_container(fake.root, slug="d")
    client.delete(c.location, recursive=True, if_match=None)
    delete = [r for r in fake.requests if r.method == "DELETE"][-1]
    assert delete.headers["depth"] == "infinity"


def test_subscribe_rejects_unsupported_type(fake: FakeLws, client: LwsClient) -> None:
    from lws_client import Service

    service = Service(("NotificationService",), fake.notifications,
                      raw={"subscriptionType": ["WebSocketSubscription"]})
    with pytest.raises(UnsupportedError):
        client.subscribe(service, [fake.root], "https://receiver.example/inbox")


def test_read_container_on_data_resource_is_protocol_error(fake: FakeLws, client: LwsClient) -> None:
    h = client.create_text(fake.root, "x", slug="x.txt")
    with pytest.raises(ProtocolError):
        client.read_container(h.location)


def test_expired_search_page(fake: FakeLws, client: LwsClient) -> None:
    for i in range(3):
        client.create_json(fake.root, {}, types=[PERSON], slug=f"p{i}")
    page = client.search_types(fake.type_search, TypeQuery.of_types(PERSON))
    assert page.total_items == 3 and page.next
    pages = client.search_pages(fake.type_search, {"type": [PERSON]})
    assert len(next(pages).items) == 2
    fake.search_cursors.clear()  # the server forgets the cursor: restart required
    with pytest.raises(NotFoundError):
        next(pages)
