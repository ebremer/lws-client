# SPDX-License-Identifier: MIT
"""Shared-fixture tests for response models."""

from __future__ import annotations

import time

import pytest
from conftest import load, make_response

from lws_client import (
    AccessGrant,
    AccessPolicy,
    AccessRequest,
    AccessTarget,
    ConflictError,
    Constraint,
    ContainerPage,
    Linkset,
    Notification,
    ProblemDetails,
    ProtocolError,
    ResourceMetadata,
    SearchPage,
    StorageDescription,
    Subscription,
    TypeIndexPage,
    WebhookSubscriptionRequest,
    metadata_url,
    parse_notification,
    parse_token_response_expiry,
    realm_contains,
)
from lws_client.errors import error_for_response
from lws_client.linkset import LinksetDocument


def test_storage_description_fixture() -> None:
    fx = load("responses/storage-description.json")
    sd = StorageDescription.from_json(fx["body"], fx["url"])
    exp = fx["expected"]
    assert sd.id == exp["id"]
    assert list(sd.types) == exp["types"]
    assert sd.storage_root() == exp["storageRoot"]
    assert sd.notification_service() == exp["notificationService"]
    note = sd.service("NotificationService")
    assert note is not None and list(note.subscription_types) == exp["notificationSubscriptionTypes"]
    assert sd.type_index_service() == exp["typeIndexService"]
    assert sd.type_search_service() == exp["typeSearchService"]
    assert sd.access_request_service() == exp["accessRequestService"]
    assert sd.access_grant_service() == exp["accessGrantService"]
    assert len(sd.services) == exp["serviceCount"]
    assert [c.types[0] for c in sd.capabilities] == exp["capabilityTypes"]
    custom = sd.service(exp["customService"]["type"])
    assert custom is not None
    assert custom.id == exp["customService"]["id"]
    assert custom.service_endpoint == exp["customService"]["serviceEndpoint"]
    assert sd.capability("https://feature.example/PatchSupport") is not None
    assert sd.has_type("https://www.w3.org/ns/lws#Storage")


def test_storage_description_invalid() -> None:
    invalid = load("responses/storage-description.json")["invalid"]
    with pytest.raises(ProtocolError):
        StorageDescription.from_json(invalid["notStorage"])
    sd = StorageDescription.from_json(invalid["noRoot"])
    with pytest.raises(ProtocolError):
        sd.storage_root()


def test_container_page_fixture() -> None:
    fx = load("responses/container-page.json")
    response = make_response(fx["url"], fx["status"], fx["headers"], fx["body"])
    page = ContainerPage.parse(ResourceMetadata.from_response(response), response.content)
    exp = fx["expected"]
    assert page.id == exp["id"]
    assert page.metadata.is_container is exp["isContainer"]
    assert page.total_items == exp["totalItems"]
    assert page.etag == exp["etag"]
    assert page.metadata.linkset == exp["linkset"]
    assert page.metadata.parent == exp["parent"]
    assert page.metadata.storage == exp["storage"]
    assert (page.first, page.next, page.prev, page.last) == (
        exp["first"], exp["next"], exp["prev"], exp["last"]
    )
    assert len(page.items) == len(exp["items"])
    for item, e in zip(page.items, exp["items"], strict=True):
        assert item.id == e["id"]
        assert item.is_container is e["isContainer"]
        assert item.is_data_resource is e["isDataResource"]
        assert item.format == e["format"]
        assert item.size == e["size"]
        assert list(item.types) == e["types"]
        if "modified" in e and e["modified"] is not None:
            assert item.modified is not None
            assert item.modified.isoformat().replace("+00:00", "Z") == e["modified"]
        elif e.get("modified", "absent") is None:
            assert item.modified is None
        if "modifiedRaw" in e:
            assert item.modified_raw == e["modifiedRaw"]
        if "hasType" in e:
            assert item.has_type(e["hasType"])


def test_container_page_rejects_wrong_media_type_and_non_container() -> None:
    fx = load("responses/container-page.json")
    bad = make_response(fx["url"], 200, {"content-type": "text/turtle"}, fx["body"])
    with pytest.raises(ProtocolError):
        ContainerPage.parse(ResourceMetadata.from_response(bad), bad.content)
    data = make_response(
        fx["url"], 200,
        {"content-type": "application/json",
         "link": "<https://www.w3.org/ns/lws#DataResource>; rel=\"type\""},
        {"id": "/x", "type": "DataResource"},
    )
    with pytest.raises(ProtocolError):
        ContainerPage.parse(ResourceMetadata.from_response(data), data.content)


def test_linkset_fixture() -> None:
    fx = load("responses/linkset.json")
    response = make_response(fx["url"], fx["status"], fx["headers"], fx["body"])
    doc = LinksetDocument(fx["url"], Linkset.from_json(response.json()),
                          ResourceMetadata.from_response(response))
    exp = fx["expected"]
    assert doc.url == exp["url"]
    assert doc.etag == exp["etag"]
    assert doc.allow == exp["allow"]
    assert doc.accept_patch == exp["acceptPatch"]
    assert len(doc.linkset.contexts) == exp["contexts"]
    assert doc.linkset.contexts[0].anchor == exp["anchor"]
    assert len(doc.linkset) == exp["linkCount"]
    assert len(doc.linkset.links()) == exp["linkCount"]
    for rel, targets in exp["targets"].items():
        assert doc.linkset.targets(rel) == targets
    assert doc.linkset.to_json() == fx["body"]  # lossless round trip
    op = exp["afterAdd"]["operation"]
    doc.linkset.add(op["anchor"], op["rel"], op["href"])
    assert doc.linkset.targets("license", op["anchor"]) == exp["afterAdd"]["licenseTargets"]
    assert doc.linkset.remove(op["anchor"], "license", op["href"]) == 1
    assert doc.linkset.to_json() == fx["body"]


def test_notification_fixture() -> None:
    fx = load("responses/notification.json")
    for key in ("single", "batch"):
        n = parse_notification(fx[key])
        exp = fx[f"{key}Expected"]
        assert n.storage == exp["storage"]
        assert len(n.activities) == len(exp["activities"])
        for act, e in zip(n.activities, exp["activities"], strict=True):
            assert act.id == e["id"]
            assert list(act.types) == e["types"]
            assert act.object.id == e["objectId"]
            for flag in ("isCreate", "isUpdate", "isDelete"):
                if flag in e:
                    attr = "is_" + flag[2:].lower()
                    assert getattr(act, attr) is e[flag]
            if "objectTypes" in e:
                assert list(act.object.types) == e["objectTypes"]
            for name in ("origin", "target", "actor"):
                if name in e:
                    assert getattr(act, name) == e[name]
            if "published" in e:
                assert act.published_raw == e["published"]
                assert act.published is not None
    with pytest.raises(ProtocolError):
        parse_notification(fx["invalid"])
    assert isinstance(parse_notification(b'{"type":"Notification","storage":"s","activity":[]}'),
                      Notification)


def test_access_fixture() -> None:
    fx = load("responses/access.json")
    req = AccessRequest.from_json(fx["request"])
    assert req.storage == "https://storage.example/"
    assert req.access[0].actions == ("read", "create")
    assert req.to_json() == fx["request"]
    grant = AccessGrant.from_json(fx["grant"])
    assert grant.to_json() == fx["grant"]
    assert grant.access[0].constraints[0].right_operand == ["image/jpeg", "image/png"]
    built = AccessRequest(
        storage="https://storage.example/",
        inbox="https://id.example/agent/inbox/",
        access=[
            AccessPolicy(
                actions=["read", "create"],
                assignee="https://id.example/agent",
                target=AccessTarget("StorageResource", ["https://storage.example/root/projects/"]),
                constraints=[
                    Constraint.purpose("https://purpose.example/collaboration"),
                    Constraint.not_after("2026-06-09T10:00:00Z"),
                ],
            )
        ],
    )
    assert built.to_json() == fx["request"]
    with pytest.raises(ProtocolError):
        AccessGrant.from_json(fx["request"])
    with pytest.raises(ValueError):
        AccessPolicy(actions=[], assignee="https://id.example/agent")
    with pytest.raises(ValueError):
        AccessRequest(storage="https://storage.example/", access=[])


def test_constraint_factories() -> None:
    from datetime import datetime, timezone

    assert Constraint.not_before(datetime(2026, 3, 9, 12, tzinfo=timezone.utc)).to_json() == {
        "leftOperand": "dateTime", "operator": "gteq", "rightOperand": "2026-03-09T12:00:00Z"
    }
    assert Constraint.format_any_of("image/png").to_json()["rightOperand"] == ["image/png"]
    assert Constraint.resource_type("https://type.example/Song").left_operand == "type"
    assert Constraint.client("https://app.example/id").operator == "eq"


def test_type_index_and_search_fixture() -> None:
    fx = load("responses/type-index.json")
    ti = fx["typeIndex"]
    resp = make_response(ti["url"], 200, ti["headers"], ti["body"])
    page = TypeIndexPage.parse(ResourceMetadata.from_response(resp), resp.content)
    assert page.total_items == ti["expected"]["totalItems"]
    assert list(page.types) == ti["expected"]["types"]
    assert page.next == ti["expected"]["next"]
    se = fx["search"]
    resp = make_response(se["url"], 200, se["headers"], se["body"])
    sp = SearchPage.parse(ResourceMetadata.from_response(resp), resp.content)
    assert sp.total_items == se["expected"]["totalItems"]
    assert [i.id for i in sp.items] == se["expected"]["ids"]
    assert sp.next == se["expected"]["next"]
    assert sp.items[2].is_container


def test_oauth_fixture() -> None:
    fx = load("responses/oauth.json")
    for case in fx["metadataUrls"]:
        assert metadata_url(case["issuer"]) == case["url"]
    for case in fx["realmChecks"]:
        assert realm_contains(case["realm"], case["url"]) is case["contained"], case
    now = time.time()
    assert parse_token_response_expiry(fx["tokenResponse"]["body"], now) == pytest.approx(
        now + fx["tokenResponse"]["expectedExpiresIn"]
    )
    assert parse_token_response_expiry(fx["tokenResponseNoExpiry"]["body"], now) == fx[
        "tokenResponseNoExpiry"
    ]["expectedExp"]


def test_problem_details_fixture() -> None:
    fx = load("responses/problem-details.json")
    resp = make_response("https://storage.example/alice/notes/", fx["status"], fx["headers"],
                         fx["body"], method="DELETE")
    err = error_for_response(resp)
    assert isinstance(err, ConflictError)
    assert err.status == 409
    exp = fx["expected"]
    assert isinstance(err.problem, ProblemDetails)
    assert (err.problem.type, err.problem.title, err.problem.detail, err.problem.instance) == (
        exp["type"], exp["title"], exp["detail"], exp["instance"]
    )
    assert dict(err.problem.extensions) == exp["extension"]
    assert "container is not empty" in str(err)


def test_subscription_fixture() -> None:
    fx = load("responses/subscription.json")
    req = WebhookSubscriptionRequest(fx["input"]["topics"], fx["input"]["inbox"],
                                     fx["input"]["expires"])
    assert req.to_json() == fx["expectedRequestBody"]
    sub = Subscription.from_json(fx["response"]["body"])
    assert (sub.type, sub.subscription, sub.expires_raw) == (
        fx["expected"]["type"], fx["expected"]["subscription"], fx["expected"]["expires"]
    )
    assert sub.expires is not None
