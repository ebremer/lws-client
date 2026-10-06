// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// End-to-end interop scenario (conformance/scenario.md) against the mock server in
// testing/mock-server. Skipped unless LWS_TEST_SERVER is set, e.g.
//   node testing/mock-server/server.mjs --port 8787
//   LWS_TEST_SERVER=http://localhost:8787 ctest

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>

#include "test_support.hpp"

using namespace lws;

namespace {
[[maybe_unused]] std::string test_server() {
    const char* env = std::getenv("LWS_TEST_SERVER");
    std::string base = env ? env : "";
    while (!base.empty() && base.back() == '/') base.pop_back();
    return base;
}
[[maybe_unused]] bool contains(const std::vector<std::string>& v, const std::string& x) { return std::find(v.begin(), v.end(), x) != v.end(); }
}  // namespace

#if LWS_WITH_CURL && LWS_WITH_OPENSSL

TEST(Interop, Scenario) {
    const std::string base = test_server();
    if (base.empty()) GTEST_SKIP() << "set LWS_TEST_SERVER to run the interop scenario";

    // 1. Authenticate + discover
    auto creds = SelfSignedCredentials::did_key(PrivateKey::generate(KeyAlgorithm::ES256));
    ClientOptions options;
    options.authenticator = std::make_shared<TokenExchangeAuthenticator>(creds);
    Client client(options);
    const auto sd = client.discover_storage(base + "/root/");
    EXPECT_EQ(sd.id, base + "/");
    EXPECT_EQ(sd.storage_root(), base + "/root/");
    ASSERT_NE(sd.notification_service(), nullptr);
    ASSERT_NE(sd.access_request_service(), nullptr);
    ASSERT_NE(sd.access_grant_service(), nullptr);
    ASSERT_NE(sd.type_index_service(), nullptr);
    ASSERT_NE(sd.type_search_service(), nullptr);

    // 2. Container
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
    const std::string name = "interop-cpp-" + std::to_string(millis);
    const auto C = client.create_container(sd.storage_root(), {.slug = name}).location;
    EXPECT_TRUE(C.starts_with(base + "/root/"));

    // 3. Text resource
    const auto H = client.create(C, "Hello, LWS!", "text/plain", {.slug = "hello.txt"}).location;

    // 4. Read
    const auto h = client.read(H);
    EXPECT_EQ(h.text(), "Hello, LWS!");
    ASSERT_TRUE(h.etag);
    EXPECT_TRUE(h.is_data_resource());
    EXPECT_EQ(h.parent, C);
    EXPECT_TRUE(h.linkset);
    EXPECT_EQ(h.storage, base + "/");

    // 5. Conditional read
    EXPECT_TRUE(client.read(H, {.if_none_match = h.etag}).not_modified);

    // 6. Update + stale ETag
    client.update(H, "Hello again", "text/plain", {.if_match = h.etag});
    EXPECT_EQ(client.read(H).text(), "Hello again");
    EXPECT_THROW(client.update(H, "nope", "text/plain", {.if_match = h.etag}), PreconditionFailedError);

    // 7. JSON + JSON Patch
    CreateOptions profile_opts;
    profile_opts.slug = "profile.json";
    profile_opts.types = {"https://schema.org/Person"};
    const auto P = client.create_json(C, {{"name", "Alice"}, {"age", 30}}, profile_opts).location;
    client.patch(P, JsonPatch{}.replace("/age", 31).add("/city", "Boston"));
    EXPECT_EQ(client.read(P).json(), (nlohmann::json{{"name", "Alice"}, {"age", 31}, {"city", "Boston"}}));

    // 8. Linkset
    const auto ls = client.read_linkset(P);
    ASSERT_FALSE(ls.linkset.contexts.empty());
    const nlohmann::json shape = {{"href", "https://example.org/shapes/person"}};
    JsonPatch add_link;
    if (ls.linkset.contexts[0].relation("describedby"))
        add_link.add("/linkset/0/describedby/-", shape);
    else
        add_link.add("/linkset/0/describedby", nlohmann::json::array({shape}));
    client.patch_linkset(ls.url, add_link, {.if_match = ls.etag});
    EXPECT_TRUE(contains(client.read_linkset(P).linkset.targets("describedby"), "https://example.org/shapes/person"));

    // 9. Pagination
    for (int i = 0; i < 6; ++i)
        client.create(C, "item " + std::to_string(i), "text/plain", {.slug = "item-" + std::to_string(i) + ".txt"});
    const auto first = client.read_container(C);
    EXPECT_EQ(first.total_items, 8);
    EXPECT_TRUE(first.next);
    std::vector<std::string> ids;
    for (const auto& item : client.list_container(C)) ids.push_back(item.id);
    EXPECT_EQ(ids.size(), 8u);
    EXPECT_TRUE(contains(ids, H));
    EXPECT_TRUE(contains(ids, P));

    // 10. Type index / search
    const auto index = sd.type_index_service()->service_endpoint;
    const auto search = sd.type_search_service()->service_endpoint;
    EXPECT_TRUE(contains(client.list_types(index).to_vector(), "https://schema.org/Person"));
    std::vector<std::string> found;
    for (const auto& r : client.search_all(search, TypeQuery::of_types({"https://schema.org/Person"}))) found.push_back(r.id);
    EXPECT_TRUE(contains(found, P));
    EXPECT_TRUE(contains(client.accepted_query_formats(search), "application/lws-query+json"));

    // 11. Notifications (no local listener in the C++ test: subscribe / list / get / unsubscribe)
    const auto sub = client.subscribe(sd, {.topics = {C}, .inbox = "http://127.0.0.1:9/inbox"});
    EXPECT_EQ(sub.type, "WebhookSubscription");
    std::vector<std::string> subs;
    for (const auto& s : client.list_subscriptions(sd.notification_service()->service_endpoint)) subs.push_back(s.id);
    EXPECT_TRUE(contains(subs, sub.subscription));
    EXPECT_FALSE(client.get_subscription(sub.subscription).subscription.empty());
    client.unsubscribe(sub.subscription);

    // 12. Access requests / grants
    const AccessPolicy policy{
        .actions = {"read"},
        .assignee = creds->agent_id(),
        .target = AccessTarget{.type = "StorageResource", .values = {C}},
        .constraints = {Constraint::purpose("https://purpose.example/collaboration")},
    };
    const auto request_url =
        client.request_access(sd.access_request_service()->service_endpoint, {.storage = sd.id, .access = {policy}});
    const auto request = client.get_access_request(request_url);
    EXPECT_EQ(request.storage, sd.id);
    ASSERT_EQ(request.access.size(), 1u);
    EXPECT_EQ(request.access[0].assignee, creds->agent_id());
    std::vector<std::string> requests;
    for (const auto& r : client.list_access_requests(sd.access_request_service()->service_endpoint)) requests.push_back(r.id);
    EXPECT_TRUE(contains(requests, request_url));
    const auto grant_url = client.grant_access(sd.access_grant_service()->service_endpoint, {.storage = sd.id, .access = {policy}});
    EXPECT_EQ(client.get_access_grant(grant_url).access.at(0).actions, std::vector<std::string>{"read"});
    client.revoke_access_grant(grant_url);
    client.cancel_access_request(request_url);

    // 13. Delete
    EXPECT_THROW(client.remove(C), ConflictError);
    client.remove(C, {.recursive = true});
    EXPECT_THROW(client.read(H), NotFoundError);
}

TEST(Interop, Ed25519Credentials) {
    const std::string base = test_server();
    if (base.empty()) GTEST_SKIP() << "set LWS_TEST_SERVER to run the interop scenario";
    ClientOptions options;
    options.authenticator = std::make_shared<TokenExchangeAuthenticator>(
        SelfSignedCredentials::did_key(PrivateKey::generate(KeyAlgorithm::EdDSA)));
    Client client(options);
    const auto page = client.read_container(base + "/root/");
    EXPECT_TRUE(page.is_container());
}

#else
TEST(Interop, Scenario) { GTEST_SKIP() << "requires LWS_WITH_CURL and LWS_WITH_OPENSSL"; }
#endif
