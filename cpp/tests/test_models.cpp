// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Model parsing tests driven by conformance/fixtures/responses.

#include <gtest/gtest.h>

#include "test_support.hpp"

using namespace lws;
using lws::test::fixture;
using lws::test::response_from_fixture;

namespace {
std::optional<std::string> opt(const nlohmann::json& j) {
    if (j.is_null()) return std::nullopt;
    return j.get<std::string>();
}
}  // namespace

TEST(StorageDescriptionModel, ParsesDiscoveryExample) {
    const auto f = fixture("responses/storage-description.json");
    const auto d = StorageDescription::from_json(f["body"], f["url"].get<std::string>());
    const auto& e = f["expected"];
    EXPECT_EQ(d.id, e["id"].get<std::string>());
    EXPECT_EQ(d.types, e["types"].get<std::vector<std::string>>());
    EXPECT_EQ(d.storage_root(), e["storageRoot"].get<std::string>());
    ASSERT_NE(d.notification_service(), nullptr);
    EXPECT_EQ(d.notification_service()->service_endpoint, e["notificationService"].get<std::string>());
    EXPECT_EQ(d.notification_service()->strings("subscriptionType"),
              e["notificationSubscriptionTypes"].get<std::vector<std::string>>());
    EXPECT_EQ(d.type_index_service()->service_endpoint, e["typeIndexService"].get<std::string>());
    EXPECT_EQ(d.type_search_service()->service_endpoint, e["typeSearchService"].get<std::string>());
    EXPECT_EQ(d.access_request_service()->service_endpoint, e["accessRequestService"].get<std::string>());
    EXPECT_EQ(d.access_grant_service()->service_endpoint, e["accessGrantService"].get<std::string>());
    EXPECT_EQ(d.services.size(), e["serviceCount"].get<std::size_t>());
    std::vector<std::string> cap_types;
    for (const auto& c : d.capabilities) cap_types.push_back(c.types.at(0));
    EXPECT_EQ(cap_types, e["capabilityTypes"].get<std::vector<std::string>>());
    const auto* custom = d.service(e["customService"]["type"].get<std::string>());
    ASSERT_NE(custom, nullptr);
    EXPECT_EQ(custom->id, e["customService"]["id"].get<std::string>());
    EXPECT_EQ(custom->service_endpoint, e["customService"]["serviceEndpoint"].get<std::string>());
    EXPECT_NE(d.capability("https://feature.example/PatchSupport"), nullptr);
    EXPECT_EQ(d.capability("https://feature.example/Nope"), nullptr);
    EXPECT_TRUE(d.service("https://www.w3.org/ns/lws#StorageRoot"));
}

TEST(StorageDescriptionModel, RejectsInvalidDocuments) {
    const auto f = fixture("responses/storage-description.json");
    EXPECT_THROW(StorageDescription::from_json(f["invalid"]["notStorage"], "https://storage.example/"), ProtocolError);
    const auto no_root = StorageDescription::from_json(f["invalid"]["noRoot"], "https://storage.example/");
    EXPECT_THROW(no_root.storage_root(), ProtocolError);
}

TEST(ContainerPageModel, ParsesPaginatedContainer) {
    const auto f = fixture("responses/container-page.json");
    const auto page = ContainerPage::from_response(response_from_fixture(f));
    const auto& e = f["expected"];
    EXPECT_EQ(page.id, e["id"].get<std::string>());
    EXPECT_EQ(page.is_container(), e["isContainer"].get<bool>());
    EXPECT_EQ(page.total_items, e["totalItems"].get<std::int64_t>());
    EXPECT_EQ(page.metadata.etag, e["etag"].get<std::string>());
    EXPECT_EQ(page.metadata.linkset, opt(e["linkset"]));
    EXPECT_EQ(page.metadata.parent, opt(e["parent"]));
    EXPECT_EQ(page.metadata.storage, opt(e["storage"]));
    EXPECT_TRUE(page.metadata.is_container());
    EXPECT_EQ(page.first, opt(e["first"]));
    EXPECT_EQ(page.next, opt(e["next"]));
    EXPECT_EQ(page.prev, opt(e["prev"]));
    EXPECT_EQ(page.last, opt(e["last"]));
    ASSERT_EQ(page.items.size(), e["items"].size());
    for (std::size_t i = 0; i < page.items.size(); ++i) {
        const auto& item = page.items[i];
        const auto& x = e["items"][i];
        SCOPED_TRACE(item.id);
        EXPECT_EQ(item.id, x["id"].get<std::string>());
        EXPECT_EQ(item.is_container(), x["isContainer"].get<bool>());
        EXPECT_EQ(item.is_data_resource(), x["isDataResource"].get<bool>());
        EXPECT_EQ(item.format, opt(x["format"]));
        if (x["size"].is_null())
            EXPECT_FALSE(item.size);
        else
            EXPECT_EQ(item.size, x["size"].get<std::int64_t>());
        if (x.contains("modified")) {
            if (x["modified"].is_null()) {
                EXPECT_FALSE(item.modified);
            } else {
                ASSERT_TRUE(item.modified);
                EXPECT_EQ(format_rfc3339(*item.modified), x["modified"].get<std::string>());
            }
        }
        if (x.contains("modifiedRaw")) {
            EXPECT_EQ(item.modified_raw, x["modifiedRaw"].get<std::string>());
        }
        EXPECT_EQ(item.types, x["types"].get<std::vector<std::string>>());
        if (x.contains("hasType")) {
            EXPECT_TRUE(item.has_type(x["hasType"].get<std::string>()));
        }
    }
}

TEST(ContainerPageModel, RejectsNonContainers) {
    auto r = test::make_response(200, {{"Content-Type", "application/lws+json"},
                                       {"Link", "<https://www.w3.org/ns/lws#DataResource>; rel=\"type\""}},
                                 R"({"id":"/x","type":"Container","items":[]})");
    r.url = "https://s.example/x";
    EXPECT_THROW(ContainerPage::from_response(r), ProtocolError);
    auto wrong_media = test::make_response(200, {{"Content-Type", "text/turtle"}}, "<> a <x> .");
    wrong_media.url = "https://s.example/x/";
    EXPECT_THROW(ContainerPage::from_response(wrong_media), ProtocolError);
    auto body_type = test::make_response(200, {{"Content-Type", "application/json; charset=utf-8"}},
                                         R"({"id":"/x","type":"DataResource"})");
    body_type.url = "https://s.example/x";
    EXPECT_THROW(ContainerPage::from_response(body_type), ProtocolError);
    auto ld = test::make_response(200, {{"Content-Type", "application/ld+json"}}, R"({"type":"Container","items":[]})");
    ld.url = "https://s.example/y/";
    const auto page = ContainerPage::from_response(ld);
    EXPECT_EQ(page.id, "https://s.example/y/");
    EXPECT_TRUE(page.items.empty());
}

TEST(LinksetModel, ParsesAndRoundTrips) {
    const auto f = fixture("responses/linkset.json");
    const auto& e = f["expected"];
    auto ls = Linkset::from_json(f["body"]);
    EXPECT_EQ(ls.contexts.size(), e["contexts"].get<std::size_t>());
    EXPECT_EQ(ls.contexts[0].anchor, e["anchor"].get<std::string>());
    EXPECT_EQ(ls.links().size(), e["linkCount"].get<std::size_t>());
    for (auto it = e["targets"].begin(); it != e["targets"].end(); ++it)
        EXPECT_EQ(ls.targets(it.key()), it.value().get<std::vector<std::string>>()) << it.key();
    EXPECT_EQ(ls.to_json(), f["body"]);
    const auto& op = e["afterAdd"]["operation"];
    ls.add(op["anchor"].get<std::string>(), op["rel"].get<std::string>(), op["href"].get<std::string>());
    EXPECT_EQ(ls.targets(op["anchor"].get<std::string>(), "license"),
              e["afterAdd"]["licenseTargets"].get<std::vector<std::string>>());
    ls.remove(op["anchor"].get<std::string>(), "license", std::string_view("https://example.org/license-2"));
    EXPECT_EQ(ls.to_json(), f["body"]);
    ls.remove(op["anchor"].get<std::string>(), "license");
    EXPECT_TRUE(ls.targets("license").empty());
    const auto links = ls.links();
    const auto bob = std::find_if(links.begin(), links.end(), [](const Link& l) { return l.href == "https://id.example/bob"; });
    ASSERT_NE(bob, links.end());
    EXPECT_EQ(bob->params.at("title"), "Bob");
    EXPECT_EQ(bob->params.at("anchor"), "https://storage.example/alice/personalinfo.json");
}

TEST(LinksetModel, MetadataFromResponse) {
    const auto f = fixture("responses/linkset.json");
    const auto meta = ResourceMetadata::from_response(response_from_fixture(f));
    EXPECT_EQ(meta.etag, f["expected"]["etag"].get<std::string>());
    EXPECT_EQ(meta.allow, f["expected"]["allow"].get<std::vector<std::string>>());
    EXPECT_EQ(meta.accept_patch, f["expected"]["acceptPatch"].get<std::vector<std::string>>());
    EXPECT_EQ(meta.media_type(), "application/linkset+json");
}

TEST(NotificationModel, SingleBatchAndInvalid) {
    const auto f = fixture("responses/notification.json");
    for (const char* kind : {"single", "batch"}) {
        SCOPED_TRACE(kind);
        const auto n = parse_notification(f[kind].dump());
        const auto& e = f[std::string(kind) + "Expected"];
        EXPECT_EQ(n.storage, e["storage"].get<std::string>());
        ASSERT_EQ(n.activities.size(), e["activities"].size());
        for (std::size_t i = 0; i < n.activities.size(); ++i) {
            const auto& a = n.activities[i];
            const auto& x = e["activities"][i];
            EXPECT_EQ(a.id, x["id"].get<std::string>());
            EXPECT_EQ(a.types, x["types"].get<std::vector<std::string>>());
            EXPECT_EQ(a.object.id, x["objectId"].get<std::string>());
            if (x.contains("objectTypes")) {
                EXPECT_EQ(a.object.types, x["objectTypes"].get<std::vector<std::string>>());
            }
            if (x.contains("isCreate")) {
                EXPECT_TRUE(a.is_create());
            }
            if (x.contains("isUpdate")) {
                EXPECT_TRUE(a.is_update());
            }
            if (x.contains("isDelete")) {
                EXPECT_TRUE(a.is_delete());
            }
            if (x.contains("target")) {
                EXPECT_EQ(a.target, x["target"].get<std::string>());
            }
            if (x.contains("origin")) {
                EXPECT_EQ(a.origin, x["origin"].get<std::string>());
            }
            if (x.contains("actor")) {
                EXPECT_EQ(a.actor, x["actor"].get<std::string>());
            }
            if (x.contains("published")) {
                EXPECT_EQ(a.published_raw, x["published"].get<std::string>());
            }
            EXPECT_TRUE(a.published.has_value());
        }
    }
    EXPECT_THROW(Notification::from_json(f["invalid"]), ProtocolError);
    EXPECT_THROW(parse_notification("{not json"), ParseError);
}

TEST(AccessModel, ParseAndBuild) {
    const auto f = fixture("responses/access.json");
    const auto request = AccessRequest::from_json(f["request"]);
    EXPECT_TRUE(request.has_type("AccessRequest"));
    EXPECT_EQ(request.storage, "https://storage.example/");
    EXPECT_EQ(request.inbox, "https://id.example/agent/inbox/");
    ASSERT_EQ(request.access.size(), 1u);
    EXPECT_EQ(request.access[0].actions, (std::vector<std::string>{"read", "create"}));
    EXPECT_EQ(request.access[0].constraints.size(), 2u);
    EXPECT_EQ(request.to_json(), f["request"]);

    const auto grant = AccessGrant::from_json(f["grant"]);
    EXPECT_EQ(grant.access[0].constraints[0].right_operand, nlohmann::json::array({"image/jpeg", "image/png"}));
    EXPECT_EQ(grant.to_json(), f["grant"]);
    EXPECT_THROW(AccessGrant::from_json(f["request"]), ProtocolError);
    // A malformed document from the server is a protocol error.
    auto no_storage = f["request"];
    no_storage.erase("storage");
    EXPECT_THROW(AccessRequest::from_json(no_storage), ProtocolError);
    auto no_access = f["grant"];
    no_access["access"] = nlohmann::json::array();
    EXPECT_THROW(AccessGrant::from_json(no_access), ProtocolError);
    auto no_action = f["grant"];
    no_action["access"][0]["action"] = nlohmann::json::array();
    EXPECT_THROW(AccessGrant::from_json(no_action), ProtocolError);

    // Builder expectation (designated initializers).
    AccessRequest built{
        .storage = "https://storage.example/",
        .inbox = "https://id.example/agent/inbox/",
        .access = {AccessPolicy{
            .actions = {"read", "create"},
            .assignee = "https://id.example/agent",
            .target = AccessTarget{.type = "StorageResource", .values = {"https://storage.example/root/projects/"}},
            .constraints = {Constraint::purpose("https://purpose.example/collaboration"),
                            Constraint::not_after("2026-06-09T10:00:00Z")},
        }},
    };
    EXPECT_EQ(built.to_json(), f["request"]);

    AccessGrant invalid{.storage = "https://storage.example/"};
    EXPECT_THROW(invalid.to_json(), std::invalid_argument);
    AccessGrant no_assignee{.storage = "s", .access = {AccessPolicy{.actions = {"read"}}}};
    EXPECT_THROW(no_assignee.to_json(), std::invalid_argument);
    EXPECT_EQ(Constraint::format_any_of({"a/b"}).to_json()["operator"], "isAnyOf");
    EXPECT_EQ(Constraint::not_before("x").to_json()["operator"], "gteq");
}

TEST(TypeIndexModel, IndexAndSearchPages) {
    const auto f = fixture("responses/type-index.json");
    const auto index = TypeIndexPage::from_response(response_from_fixture(f["typeIndex"]));
    EXPECT_EQ(index.total_items, f["typeIndex"]["expected"]["totalItems"].get<std::int64_t>());
    EXPECT_EQ(index.types, f["typeIndex"]["expected"]["types"].get<std::vector<std::string>>());
    EXPECT_EQ(index.next, f["typeIndex"]["expected"]["next"].get<std::string>());

    const auto search = ContainerPage::from_response(response_from_fixture(f["search"]), false);
    EXPECT_EQ(search.total_items, f["search"]["expected"]["totalItems"].get<std::int64_t>());
    std::vector<std::string> ids;
    for (const auto& i : search.items) ids.push_back(i.id);
    EXPECT_EQ(ids, f["search"]["expected"]["ids"].get<std::vector<std::string>>());
    EXPECT_EQ(search.id, f["search"]["url"].get<std::string>());  // the body names no id: the page URL stands in
    EXPECT_EQ(search.next, f["search"]["expected"]["next"].get<std::string>());
    EXPECT_TRUE(search.has_type("ContainerPage"));
}

TEST(ProblemDetailsModel, MapsToConflictError) {
    const auto f = fixture("responses/problem-details.json");
    auto resp = response_from_fixture(f);
    resp.url = "https://storage.example/alice/notes/";
    HttpRequest req{.method = "DELETE", .url = resp.url};
    try {
        throw_http_error(req, resp);
        FAIL() << "expected ConflictError";
    } catch (const ConflictError& e) {
        const auto& x = f["expected"];
        EXPECT_EQ(e.status(), 409);
        ASSERT_TRUE(e.problem());
        EXPECT_EQ(e.problem()->type, x["type"].get<std::string>());
        EXPECT_EQ(e.problem()->title, x["title"].get<std::string>());
        EXPECT_EQ(e.problem()->detail, x["detail"].get<std::string>());
        EXPECT_EQ(e.problem()->instance, x["instance"].get<std::string>());
        EXPECT_EQ(e.problem()->status, 409);
        EXPECT_EQ(e.problem()->extensions, x["extension"]);
        EXPECT_NE(std::string(e.what()).find("Container not empty"), std::string::npos);
    }
}

TEST(SubscriptionModel, RequestAndResponse) {
    const auto f = fixture("responses/subscription.json");
    WebhookSubscriptionRequest req{
        .topics = f["input"]["topics"].get<std::vector<std::string>>(),
        .inbox = f["input"]["inbox"].get<std::string>(),
        .expires = f["input"]["expires"].get<std::string>(),
    };
    EXPECT_EQ(req.to_json(), f["expectedRequestBody"]);
    const auto resp = response_from_fixture(f["response"]);
    const auto sub = Subscription::from_json(f["response"]["body"], "https://notification.example/subscriptions",
                                             resp.headers.get("location"));
    EXPECT_EQ(sub.type, f["expected"]["type"].get<std::string>());
    EXPECT_EQ(sub.subscription, f["expected"]["subscription"].get<std::string>());
    EXPECT_EQ(sub.expires, f["expected"]["expires"].get<std::string>());
    EXPECT_THROW((WebhookSubscriptionRequest{.inbox = "x"}.to_json()), std::invalid_argument);
}

TEST(KeysModel, DidKeyVectors) {
    const auto f = fixture("did-key.json");
    for (const auto& v : f["vectors"]) {
        SCOPED_TRACE(v["name"].get<std::string>());
        const auto id = did_key_from_public_jwk(v["publicJwk"]);
        EXPECT_EQ(id.did, v["did"].get<std::string>());
        EXPECT_EQ(id.kid, v["kid"].get<std::string>());
    }
    EXPECT_THROW(did_key_from_public_jwk({{"kty", "RSA"}}), std::invalid_argument);
}

TEST(KeysModel, ControlledIdentifierDocument) {
    const nlohmann::json jwk = {{"kty", "EC"}, {"crv", "P-256"}, {"x", "X"}, {"y", "Y"}, {"d", "secret"}};
    const auto doc = controlled_identifier_document("https://id.example/agent", jwk, "c1f52577");
    EXPECT_EQ(doc["@context"], nlohmann::json::array({"https://www.w3.org/ns/cid/v1"}));
    EXPECT_EQ(doc["id"], "https://id.example/agent");
    const auto& vm = doc["authentication"][0];
    EXPECT_EQ(vm["id"], "https://id.example/agent#c1f52577");
    EXPECT_EQ(vm["type"], "JsonWebKey");
    EXPECT_EQ(vm["controller"], "https://id.example/agent");
    EXPECT_FALSE(vm["publicKeyJwk"].contains("d"));
    EXPECT_EQ(vm["publicKeyJwk"]["kid"], "c1f52577");
    EXPECT_EQ(controlled_identifier_document("did:example:1", jwk, "#k1")["authentication"][0]["id"], "did:example:1#k1");
}
