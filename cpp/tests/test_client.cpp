// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Client operations against an in-process mock transport.

#include <gtest/gtest.h>

#include <atomic>

#include "test_support.hpp"

using namespace lws;
using lws::test::fixture;
using lws::test::json_response;
using lws::test::make_response;
using lws::test::mock_client;

namespace {
const std::string kBase = "https://storage.example";

HttpHeaders resource_links(const std::string& linkset, const std::string& up, std::string_view type) {
    HttpHeaders h;
    h.add("Link", "<" + linkset + ">; rel=\"linkset\"; type=\"application/linkset+json\"");
    h.add("Link", "<" + up + ">; rel=\"up\"");
    h.add("Link", "<" + std::string(type) + ">; rel=\"type\"");
    h.add("Link", "<https://storage.example/>; rel=\"https://www.w3.org/ns/lws#storage\"");
    return h;
}
}  // namespace

TEST(ClientDiscovery, DiscoverStorageViaHead) {
    const auto description = fixture("responses/storage-description.json")["body"];
    auto [client, transport] = mock_client([&](const HttpRequest& r) {
        if (r.method == "HEAD" && r.url == kBase + "/root/")
            return make_response(200, resource_links("/root/.meta", "/", types::container));
        if (r.method == "GET" && r.url == kBase + "/") {
            EXPECT_EQ(r.headers.get("accept"), "application/lws+cid, application/ld+json;q=0.9, application/json;q=0.8");
            return json_response(200, description, "application/lws+cid");
        }
        return make_response(404);
    });
    const auto sd = client.discover_storage(kBase + "/root/");
    EXPECT_EQ(sd.id, "https://storage.example/");
    EXPECT_EQ(sd.storage_root(), "https://storage.example/root/");
    EXPECT_EQ(transport->requests().front().headers.get("user-agent"), "lws-client-cpp/0.1.0");
}

TEST(ClientDiscovery, FallsBackToGetAndUsesLinkOn401) {
    const auto description = fixture("responses/storage-description.json")["body"];
    auto [client, transport] = mock_client([&](const HttpRequest& r) {
        if (r.url == kBase + "/root/a") {
            if (r.method == "HEAD") return make_response(405, {{"Allow", "GET"}});
            return make_response(401, {{"Link", "<https://storage.example/>; rel=\"https://www.w3.org/ns/lws#storage\""},
                                       {"WWW-Authenticate", "Bearer realm=\"x\""}});
        }
        if (r.url == kBase + "/") return json_response(200, description, "application/lws+cid");
        return make_response(404);
    });
    EXPECT_EQ(client.discover_storage(kBase + "/root/a").id, "https://storage.example/");
    EXPECT_EQ(transport->count("GET", kBase + "/root/a"), 1u);
}

TEST(ClientDiscovery, MissingStorageLinkIsProtocolError) {
    auto [client, transport] = mock_client([](const HttpRequest&) { return make_response(200); });
    EXPECT_THROW(client.discover_storage(kBase + "/x"), ProtocolError);
    auto [client2, t2] = mock_client([](const HttpRequest&) { return make_response(404); });
    EXPECT_THROW(client2.discover_storage(kBase + "/x"), NotFoundError);
}

TEST(ClientRead, ReadsDataResourceWithMetadata) {
    auto [client, transport] = mock_client([](const HttpRequest& r) {
        auto h = resource_links("/notes/a.txt.meta", "/notes/", types::data_resource);
        h.add("ETag", "\"abc\"").add("Content-Type", "text/plain; charset=UTF-8").add("Content-Length", "5");
        if (r.headers.get("if-none-match") == "\"abc\"") return make_response(304, h);
        if (auto range = r.headers.get("range")) {
            h.add("Content-Range", "bytes 0-1/5");
            return make_response(206, h, "he");
        }
        return make_response(200, h, "hello");
    });
    const auto res = client.read(kBase + "/notes/a.txt");
    EXPECT_EQ(res.text(), "hello");
    EXPECT_EQ(res.etag, "\"abc\"");
    EXPECT_EQ(res.content_length, 5u);
    EXPECT_EQ(res.media_type(), "text/plain");
    EXPECT_TRUE(res.is_data_resource());
    EXPECT_FALSE(res.is_container());
    EXPECT_EQ(res.parent, kBase + "/notes/");
    EXPECT_EQ(res.linkset, kBase + "/notes/a.txt.meta");
    EXPECT_EQ(res.storage, "https://storage.example/");
    EXPECT_FALSE(res.not_modified);

    const auto cached = client.read(kBase + "/notes/a.txt", {.if_none_match = res.etag});
    EXPECT_TRUE(cached.not_modified);
    EXPECT_TRUE(cached.body.empty());

    const auto partial = client.read(kBase + "/notes/a.txt", {.range = byte_range(0, 1)});
    EXPECT_EQ(partial.status, 206);
    EXPECT_EQ(partial.body, "he");
    EXPECT_EQ(partial.content_range, "bytes 0-1/5");
    EXPECT_EQ(transport->requests().back().headers.get("range"), "bytes=0-1");
    EXPECT_EQ(byte_range(10), "bytes=10-");
}

TEST(ClientRead, JsonBodyAndHead) {
    auto [client, transport] = mock_client([](const HttpRequest& r) {
        HttpHeaders h{{"Content-Type", "application/json"}, {"ETag", "W/\"1\""}};
        return make_response(200, h, r.method == "HEAD" ? "" : R"({"name":"Alice"})");
    });
    EXPECT_EQ(client.read(kBase + "/p.json").json()["name"], "Alice");
    EXPECT_EQ(client.head(kBase + "/p.json").etag, "W/\"1\"");
    EXPECT_EQ(transport->requests().back().method, "HEAD");
}

TEST(ClientContainers, ListsAcrossThreePages) {
    auto page = [](int n) {
        nlohmann::json body = {{"@context", "https://www.w3.org/ns/lws/v1"},
                               {"id", "/c/"},
                               {"type", "Container"},
                               {"totalItems", 5},
                               {"items", nlohmann::json::array()}};
        HttpHeaders h{{"Content-Type", "application/lws+json"},
                      {"Link", "<https://www.w3.org/ns/lws#Container>; rel=\"type\""},
                      {"Link", "</c/?page=1>; rel=\"first\""}};
        const int counts[] = {2, 0, 2, 1};  // page 2 is empty: must be skipped transparently
        for (int i = 0; i < counts[n - 1]; ++i)
            body["items"].push_back({{"id", "item-" + std::to_string(n) + "-" + std::to_string(i)}, {"type", "DataResource"},
                                     {"format", "text/plain"}});
        if (n < 4) h.add("Link", "</c/?page=" + std::to_string(n + 1) + ">; rel=\"next\"");
        return json_response(200, body, "application/lws+json", h);
    };
    auto [client, transport] = mock_client([&](const HttpRequest& r) {
        EXPECT_EQ(r.headers.get("accept"), "application/lws+json");
        if (r.url == kBase + "/c/" || r.url == kBase + "/c/?page=1") return page(1);
        if (r.url == kBase + "/c/?page=2") return page(2);
        if (r.url == kBase + "/c/?page=3") return page(3);
        if (r.url == kBase + "/c/?page=4") return page(4);
        return make_response(404);
    });
    const auto first = client.read_container(kBase + "/c/");
    EXPECT_EQ(first.total_items, 5);
    EXPECT_EQ(first.next, kBase + "/c/?page=2");
    EXPECT_EQ(first.items[0].id, kBase + "/c/item-1-0");

    std::vector<std::string> ids;
    for (const auto& item : client.list_container(kBase + "/c/")) ids.push_back(item.id);
    EXPECT_EQ(ids, (std::vector<std::string>{kBase + "/c/item-1-0", kBase + "/c/item-1-1", kBase + "/c/item-3-0",
                                             kBase + "/c/item-3-1", kBase + "/c/item-4-0"}));
    // Lazy: only the first page is fetched before iteration advances.
    transport->clear();
    auto range = client.list_container(kBase + "/c/");
    auto it = range.begin();
    EXPECT_EQ(transport->requests().size(), 1u);
    EXPECT_EQ(it->id, kBase + "/c/item-1-0");
    static_assert(std::ranges::input_range<ContainerRange>);
    EXPECT_EQ(range.to_vector().size(), 5u);
}

TEST(ClientCreate, CreatesDataResourceAndContainer) {
    auto [client, transport] = mock_client([](const HttpRequest& r) {
        if (r.method != "POST") return make_response(400);
        HttpHeaders h{{"Location", r.headers.get_combined("link").value_or("").find("Container") != std::string::npos ? "notes/" : "notes/a.txt"}};
        h.add("Link", "</root/notes/a.txt.meta>; rel=\"linkset\"; type=\"application/linkset+json\"");
        h.add("Link", "</root/>; rel=\"up\"");
        return make_response(201, h);
    });
    CreateOptions opts;
    opts.slug = "café notes.txt";
    opts.types = {"https://schema.org/Note"};
    opts.links = {Link{"https://example.org/license", "license", {}}};
    const auto created = client.create(kBase + "/root/", "milk\neggs", "text/plain", opts);
    EXPECT_EQ(created.location, kBase + "/root/notes/a.txt");
    EXPECT_EQ(created.metadata.parent, kBase + "/root/");
    EXPECT_EQ(created.metadata.linkset, kBase + "/root/notes/a.txt.meta");
    const auto req = transport->requests().back();
    EXPECT_EQ(req.body, "milk\neggs");
    EXPECT_EQ(req.headers.get("content-type"), "text/plain");
    EXPECT_EQ(req.headers.get("slug"), "caf%C3%A9 notes.txt");
    EXPECT_EQ(req.headers.get_all("link"),
              (std::vector<std::string>{R"(<https://schema.org/Note>; rel="type")",
                                        R"(<https://example.org/license>; rel="license")"}));

    const auto container = client.create_container(kBase + "/root/", {.slug = "notes"});
    EXPECT_EQ(container.location, kBase + "/root/notes/");
    const auto creq = transport->requests().back();
    EXPECT_TRUE(creq.body.empty());
    EXPECT_FALSE(creq.headers.contains("content-type"));
    EXPECT_EQ(creq.headers.get("link"), R"(<https://www.w3.org/ns/lws#Container>; rel="type")");

    client.create_json(kBase + "/root/", {{"a", 1}});
    EXPECT_EQ(transport->requests().back().headers.get("content-type"), "application/json");
    EXPECT_EQ(transport->requests().back().body, R"({"a":1})");
}

TEST(ClientCreate, MissingLocationIsProtocolError) {
    auto [client, transport] = mock_client([](const HttpRequest&) { return make_response(201); });
    EXPECT_THROW(client.create(kBase + "/root/", "x", "text/plain"), ProtocolError);
}

TEST(ClientUpdate, PutPatchConditionalAndSetLinkset) {
    auto [client, transport] = mock_client([](const HttpRequest& r) {
        if (r.headers.get("if-match") == "\"stale\"") return make_response(412);
        return make_response(204, {{"ETag", "\"v2\""}});
    });
    const auto put = client.update(kBase + "/a.json", R"({"x":1})", "application/json", {.if_match = "\"v1\""});
    EXPECT_EQ(put.status, 204);
    EXPECT_EQ(put.etag, "\"v2\"");
    auto req = transport->requests().back();
    EXPECT_EQ(req.method, "PUT");
    EXPECT_EQ(req.headers.get("if-match"), "\"v1\"");
    EXPECT_THROW(client.update(kBase + "/a.json", "{}", "application/json", {.if_match = "\"stale\""}),
                 PreconditionFailedError);

    UpdateOptions with_links;
    with_links.links = {Link{"https://example.org/s", "describedby", {}}};
    with_links.set_linkset = true;
    client.patch(kBase + "/a.json", JsonPatch{}.replace("/age", 31).add("/city", "Boston"), with_links);
    req = transport->requests().back();
    EXPECT_EQ(req.method, "PATCH");
    EXPECT_EQ(req.headers.get("content-type"), "application/json-patch+json");
    EXPECT_EQ(nlohmann::json::parse(req.body),
              nlohmann::json::parse(R"([{"op":"replace","path":"/age","value":31},{"op":"add","path":"/city","value":"Boston"}])"));
    EXPECT_EQ(req.headers.get("prefer"), "set-linkset");
    EXPECT_EQ(req.headers.get("link"), R"(<https://example.org/s>; rel="describedby")");

    client.patch(kBase + "/a.ttl", "INSERT DATA {}", "application/sparql-update");
    EXPECT_EQ(transport->requests().back().headers.get("content-type"), "application/sparql-update");
}

TEST(ClientDelete, RecursiveAndConflict) {
    const auto problem = fixture("responses/problem-details.json");
    auto [client, transport] = mock_client([&](const HttpRequest& r) {
        if (r.headers.get("depth") == "infinity") return make_response(204);
        return json_response(409, problem["body"], "application/problem+json");
    });
    try {
        client.remove(kBase + "/alice/notes/");
        FAIL();
    } catch (const ConflictError& e) {
        EXPECT_EQ(e.problem()->title, "Container not empty");
        EXPECT_EQ(e.method(), "DELETE");
    }
    client.remove(kBase + "/alice/notes/", {.if_match = "\"e\"", .recursive = true});
    EXPECT_EQ(transport->requests().back().headers.get("if-match"), "\"e\"");
}

TEST(ClientLinkset, ReadUpdatePatch) {
    const auto f = fixture("responses/linkset.json");
    auto [client, transport] = mock_client([&](const HttpRequest& r) {
        if (r.url == kBase + "/alice/personalinfo.json" && r.method == "HEAD")
            return make_response(200, {{"Link", "<personalinfo.json.meta>; rel=\"linkset\"; type=\"application/linkset+json\""}});
        if (r.url == kBase + "/alice/personalinfo.json.meta") {
            if (r.method == "GET") return lws::test::response_from_fixture(f);
            if (r.method == "PUT") return make_response(405, {{"Allow", "GET, HEAD, PATCH"}});
            if (r.method == "PATCH") return make_response(204, {{"ETag", "\"ls-8\""}});
        }
        return make_response(404);
    });
    const auto doc = client.read_linkset(kBase + "/alice/personalinfo.json");
    EXPECT_EQ(doc.url, kBase + "/alice/personalinfo.json.meta");
    EXPECT_EQ(doc.etag, "\"ls-7\"");
    EXPECT_EQ(doc.accept_patch, std::vector<std::string>{"application/json-patch+json"});
    EXPECT_EQ(doc.linkset.targets("license").size(), 1u);
    EXPECT_EQ(transport->requests().back().headers.get("accept"), "application/linkset+json");

    const auto patched = client.patch_linkset(
        doc.url, JsonPatch{}.add("/linkset/0/describedby/-", {{"href", "https://example.org/shapes/person"}}),
        {.if_match = doc.etag});
    EXPECT_EQ(patched.etag, "\"ls-8\"");
    EXPECT_EQ(transport->requests().back().headers.get("if-match"), "\"ls-7\"");
    try {
        client.update_linkset(doc.url, doc.linkset);
        FAIL();
    } catch (const MethodNotAllowedError& e) {
        EXPECT_EQ(e.allow(), (std::vector<std::string>{"GET", "HEAD", "PATCH"}));
    }
    EXPECT_EQ(transport->requests().back().headers.get("content-type"), "application/linkset+json");
}

TEST(ClientNotifications, SubscribeListGetUnsubscribe) {
    const auto f = fixture("responses/subscription.json");
    const auto sd = StorageDescription::from_json(fixture("responses/storage-description.json")["body"], kBase + "/");
    auto [client, transport] = mock_client([&](const HttpRequest& r) {
        if (r.method == "POST") {
            EXPECT_EQ(nlohmann::json::parse(r.body), f["expectedRequestBody"]);
            EXPECT_EQ(r.headers.get("content-type"), "application/lws+json");
            return lws::test::response_from_fixture(f["response"]);
        }
        if (r.method == "GET" && r.url.ends_with("/api"))
            return json_response(200, {{"type", "Container"},
                                       {"items", {{{"id", "https://notification.example/subscriptions/9e8d7c6b5a4f"},
                                                   {"type", "DataResource"}}}}});
        if (r.method == "GET") return json_response(200, f["response"]["body"]);
        if (r.method == "DELETE") return make_response(204);
        return make_response(400);
    });
    WebhookSubscriptionRequest req{.topics = f["input"]["topics"].get<std::vector<std::string>>(),
                                   .inbox = f["input"]["inbox"].get<std::string>(),
                                   .expires = f["input"]["expires"].get<std::string>()};
    const auto sub = client.subscribe(sd, req);
    EXPECT_EQ(sub.subscription, "https://notification.example/subscriptions/9e8d7c6b5a4f");
    EXPECT_EQ(transport->requests().back().url, "https://storage.example/notification/api");
    EXPECT_EQ(client.list_subscriptions("https://storage.example/notification/api").to_vector().size(), 1u);
    EXPECT_EQ(client.get_subscription(sub.subscription).expires, "2026-06-09T12:00:00Z");
    client.unsubscribe(sub.subscription);
    EXPECT_EQ(transport->requests().back().method, "DELETE");

    auto unsupported = sd;
    unsupported.services.erase(std::remove_if(unsupported.services.begin(), unsupported.services.end(),
                                              [](const Service& s) { return s.has_type("NotificationService"); }),
                               unsupported.services.end());
    EXPECT_THROW(client.subscribe(unsupported, req), ProtocolError);
}

TEST(ClientAccess, RequestsAndGrants) {
    const auto f = fixture("responses/access.json");
    auto [client, transport] = mock_client([&](const HttpRequest& r) {
        if (r.method == "POST" && r.url.ends_with("/request/")) return make_response(201, {{"Location", "r1"}});
        if (r.method == "POST" && r.url.ends_with("/grant/")) return make_response(201, {{"Location", "/grant/g1"}});
        if (r.method == "GET" && r.url.ends_with("/request/r1")) return json_response(200, f["request"]);
        if (r.method == "GET" && r.url.ends_with("/grant/g1")) return json_response(200, f["grant"]);
        if (r.method == "GET") return json_response(200, {{"type", "Container"}, {"items", {{{"id", "r1"}, {"type", "DataResource"}}}}});
        if (r.method == "DELETE") return make_response(204);
        return make_response(400);
    });
    const auto request = AccessRequest::from_json(f["request"]);
    const auto url = client.request_access("https://access.example/request/", request);
    EXPECT_EQ(url, "https://access.example/request/r1");
    EXPECT_EQ(nlohmann::json::parse(transport->requests().back().body), f["request"]);
    EXPECT_EQ(client.get_access_request(url).storage, "https://storage.example/");
    EXPECT_EQ(client.list_access_requests("https://access.example/request/").to_vector().at(0).id, url);
    client.cancel_access_request(url);

    const auto grant_url = client.grant_access("https://access.example/grant/", AccessGrant::from_json(f["grant"]));
    EXPECT_EQ(grant_url, "https://access.example/grant/g1");
    EXPECT_EQ(client.get_access_grant(grant_url).access.at(0).actions, std::vector<std::string>{"read"});
    EXPECT_EQ(client.list_access_grants("https://access.example/grant/").to_vector().size(), 1u);
    client.revoke_access_grant(grant_url);
    EXPECT_EQ(transport->requests().back().method, "DELETE");
}

TEST(ClientTypeIndex, ListSearchAndOptions) {
    const auto f = fixture("responses/type-index.json");
    auto [client, transport] = mock_client([&](const HttpRequest& r) {
        if (r.url == "https://example.org/types/index") return lws::test::response_from_fixture(f["typeIndex"]);
        if (r.url == "https://example.org/types/index?page=2")
            return json_response(200, {{"type", "TypeIndex"}, {"items", {{{"id", "https://schema.org/Place"}}}}});
        if (r.method == "QUERY") {
            EXPECT_EQ(r.headers.get("content-type"), "application/lws-query+json");
            EXPECT_EQ(r.headers.get("accept"), "application/lws+json");
            EXPECT_EQ(nlohmann::json::parse(r.body), nlohmann::json::parse(R"({"type":["https://schema.org/Person"]})"));
            return lws::test::response_from_fixture(f["search"]);
        }
        if (r.method == "GET" && r.url == "https://example.org/types/search?cursor=b71e90")
            return json_response(200, {{"type", "ContainerPage"}, {"items", {{{"id", "https://example.org/data/x"}, {"type", "DataResource"}}}}});
        if (r.method == "OPTIONS")
            return make_response(204, {{"Allow", "OPTIONS, QUERY"}, {"Accept-Query", "application/lws-query+json, application/sparql-query"}});
        return make_response(404);
    });
    const auto types = client.list_types("https://example.org/types/index").to_vector();
    EXPECT_EQ(types, (std::vector<std::string>{"https://schema.org/Person", "https://schema.org/Event",
                                               "https://schema.org/Message", "https://schema.org/Place"}));
    const auto query = TypeQuery::of_types({"https://schema.org/Person"});
    const auto page = client.search_types("https://example.org/types/search", query);
    EXPECT_EQ(page.items.size(), 3u);
    EXPECT_EQ(transport->requests().back().method, "QUERY");
    const auto all = client.search_all("https://example.org/types/search", query).to_vector();
    ASSERT_EQ(all.size(), 4u);
    EXPECT_EQ(all.back().id, "https://example.org/data/x");
    EXPECT_EQ(transport->requests().back().method, "GET");
    EXPECT_EQ(client.accepted_query_formats("https://example.org/types/search"),
              (std::vector<std::string>{"application/lws-query+json", "application/sparql-query"}));
}

TEST(ClientErrors, StatusMapping) {
    std::atomic<int> status{0};
    auto [client, transport] = mock_client([&](const HttpRequest&) {
        return make_response(status, {{"Allow", "GET"}, {"Accept-Patch", "application/json-patch+json"},
                                      {"Accept-Query", "application/lws-query+json"}}, "oops");
    });
    auto expect = [&]<typename E>(int s) {
        status = s;
        try {
            client.read(kBase + "/x");
            ADD_FAILURE() << "no exception for " << s;
        } catch (const E& e) {
            EXPECT_EQ(e.status(), s);
            EXPECT_EQ(e.body(), "oops");
        } catch (const std::exception& e) {
            ADD_FAILURE() << "wrong exception for " << s << ": " << e.what();
        }
    };
    expect.operator()<BadRequestError>(400);
    expect.operator()<UnauthorizedError>(401);
    expect.operator()<ForbiddenError>(403);
    expect.operator()<NotFoundError>(404);
    expect.operator()<MethodNotAllowedError>(405);
    expect.operator()<NotAcceptableError>(406);
    expect.operator()<ConflictError>(409);
    expect.operator()<GoneError>(410);
    expect.operator()<PreconditionFailedError>(412);
    expect.operator()<UnsupportedMediaTypeError>(415);
    expect.operator()<UnprocessableContentError>(422);
    expect.operator()<NotImplementedError>(501);
    expect.operator()<InsufficientStorageError>(507);
    expect.operator()<HttpError>(500);
    status = 415;
    try {
        client.patch(kBase + "/x", JsonPatch{});
    } catch (const UnsupportedMediaTypeError& e) {
        EXPECT_EQ(e.accept_patch(), std::vector<std::string>{"application/json-patch+json"});
        EXPECT_EQ(e.accept_query(), std::vector<std::string>{"application/lws-query+json"});
    }
}

TEST(ClientErrors, TransportErrorsPropagate) {
    auto [client, transport] = mock_client([](const HttpRequest&) -> HttpResponse { throw TransportError("boom"); });
    EXPECT_THROW(client.read(kBase + "/x"), TransportError);
}

TEST(ClientRedirects, FollowsSafeMethodsWithoutLeakingCredentials) {
    auto auth = std::make_shared<BearerTokenAuthenticator>("secret", kBase + "/");
    auto [client, transport] = mock_client(
        [](const HttpRequest& r) {
            if (r.url == kBase + "/old") return make_response(301, {{"Location", "/new"}});
            if (r.url == kBase + "/new") return make_response(302, {{"Location", "https://elsewhere.example/x"}});
            if (r.url == "https://elsewhere.example/x") return make_response(200, {}, "ok");
            if (r.method == "POST") return make_response(307, {{"Location", "/other"}});
            return make_response(404);
        },
        auth);
    EXPECT_EQ(client.read(kBase + "/old").body, "ok");
    const auto reqs = transport->requests();
    ASSERT_EQ(reqs.size(), 3u);
    EXPECT_EQ(reqs[0].headers.get("authorization"), "Bearer secret");
    EXPECT_EQ(reqs[1].headers.get("authorization"), "Bearer secret");
    EXPECT_FALSE(reqs[2].headers.contains("authorization"));
    // Unsafe methods are not redirected automatically.
    EXPECT_THROW(client.create(kBase + "/c/", "x", "text/plain"), HttpError);
}

TEST(ClientOptionsTest, DefaultHeadersAndPerRequestOverrides) {
    ClientOptions opts;
    auto transport = std::make_shared<test::MockTransport>([](const HttpRequest&) { return make_response(200); });
    opts.transport = transport;
    opts.user_agent = "my-app/1.0";
    opts.default_headers = {{"X-Trace", "default"}, {"Accept-Language", "en"}};
    Client client(opts);
    client.head(kBase + "/x", {.headers = {{"X-Trace", "override"}}});
    const auto req = transport->requests().back();
    EXPECT_EQ(req.headers.get("user-agent"), "my-app/1.0");
    EXPECT_EQ(req.headers.get_all("x-trace"), std::vector<std::string>{"override"});
    EXPECT_EQ(req.headers.get("accept-language"), "en");
    EXPECT_EQ(req.timeout, std::chrono::milliseconds(30000));
}
