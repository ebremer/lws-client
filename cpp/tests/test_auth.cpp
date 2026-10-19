// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// The LWS authorization flow: 401 → protected resource metadata → storage description →
// authorization server metadata → token exchange → retry.

#include <gtest/gtest.h>

#include <atomic>
#include <set>
#include <thread>

#include "test_support.hpp"

using namespace lws;
using lws::test::fixture;
using lws::test::json_response;
using lws::test::make_response;

namespace {

std::map<std::string, std::string> parse_form(const std::string& body) {
    auto decode = [](std::string s) {
        std::string out;
        for (std::size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '+') out += ' ';
            else if (s[i] == '%' && i + 2 < s.size()) {
                out += static_cast<char>(std::stoi(s.substr(i + 1, 2), nullptr, 16));
                i += 2;
            } else out += s[i];
        }
        return out;
    };
    std::map<std::string, std::string> out;
    std::size_t start = 0;
    while (start < body.size()) {
        auto amp = body.find('&', start);
        if (amp == std::string::npos) amp = body.size();
        auto pair = body.substr(start, amp - start);
        auto eq = pair.find('=');
        out[decode(pair.substr(0, eq))] = decode(pair.substr(eq + 1));
        start = amp + 1;
    }
    return out;
}

std::size_t count_url(const test::MockTransport& transport, std::string_view url) {
    const auto reqs = transport.requests();
    return static_cast<std::size_t>(std::count_if(reqs.begin(), reqs.end(), [&](const HttpRequest& r) { return r.url == url; }));
}

nlohmann::json storage_description(const std::string& id, const std::string& root) {
    return {{"@context", {"https://www.w3.org/ns/cid/v1", "https://www.w3.org/ns/lws/v1"}},
            {"id", id},
            {"type", "Storage"},
            {"service", {{{"type", "StorageRoot"}, {"serviceEndpoint", root}}}}};
}

// A fake storage (https://storage.example/, its own storage root, described at its URL) protected by a fake
// AS (https://as.example). Its 401s name the protected resource metadata of the URL requested (RFC 9728) and
// link to the storage; with `legacy`, they carry the as_uri/realm challenge of the drafts before 19 October 2026.
struct FakeLws {
    std::string as_uri = "https://as.example";
    std::string storage = "https://storage.example/";
    bool legacy = false;
    std::vector<std::string> authorization_servers;  ///< in the protected resource metadata; default {as_uri}
    std::vector<std::string> outside;  ///< URL prefixes outside the storage it protects too (service endpoints)
    std::string token_prefix = "tok-";
    nlohmann::json metadata = fixture("responses/oauth.json")["metadata"];
    std::atomic<int> exchanges{0};
    std::set<std::string> valid_tokens;
    std::mutex mutex;
    std::map<std::string, std::string> last_form;
    std::function<HttpResponse(const HttpRequest&)> token_override;

    // issuer and token_endpoint follow as_uri unless a test sets them.
    FakeLws() {
        metadata.erase("issuer");
        metadata.erase("token_endpoint");
    }

    std::string origin() const { return Url::parse(storage)->origin(); }

    HttpResponse handle(const HttpRequest& r) {
        if (r.url == authorization_server_metadata_url(as_uri)) {
            auto md = metadata;
            if (!md.contains("issuer")) md["issuer"] = as_uri;
            if (!md.contains("token_endpoint")) md["token_endpoint"] = as_uri + "/token";
            return json_response(200, md, "application/json");
        }
        if (r.url == as_uri + "/token") {
            if (token_override) return token_override(r);
            const int n = ++exchanges;
            std::lock_guard lock(mutex);
            last_form = parse_form(r.body);
            const std::string token = token_prefix + std::to_string(n);
            valid_tokens.insert(token);
            return json_response(200, {{"access_token", token}, {"token_type", "Bearer"}, {"expires_in", 300}},
                                 "application/json");
        }
        const std::string prm = origin() + std::string(oauth::well_known_oauth_protected_resource);
        if (r.url.starts_with(prm + "/")) {
            const auto servers = authorization_servers.empty() ? std::vector<std::string>{as_uri} : authorization_servers;
            return json_response(200, {{"resource", origin() + r.url.substr(prm.size())}, {"authorization_servers", servers}},
                                 "application/json");
        }
        if (r.url == storage) return json_response(200, storage_description(storage, storage), "application/lws+cid");
        if (r.url.starts_with(storage) ||
            std::any_of(outside.begin(), outside.end(), [&](const std::string& p) { return r.url.starts_with(p); })) {
            const auto auth = r.headers.get("authorization").value_or("");
            {
                std::lock_guard lock(mutex);
                if (auth.starts_with("Bearer ") && valid_tokens.contains(auth.substr(7))) return make_response(200, {}, "secret data");
            }
            if (legacy)
                return make_response(401, {{"WWW-Authenticate", "Bearer as_uri=\"" + as_uri + "\", realm=\"" + storage +
                                                                   "\", error=\"invalid_token\""}});
            const auto path = Url::parse(r.url)->path;
            return make_response(401, {{"WWW-Authenticate", "Bearer resource_metadata=\"" + prm + path + "\", error=\"invalid_token\""},
                                       {"Link", "<" + storage + ">; rel=\"https://www.w3.org/ns/lws#storage\""}});
        }
        return make_response(404);
    }
};

std::pair<Client, std::shared_ptr<test::MockTransport>> client_for(FakeLws& fake, std::shared_ptr<CredentialProvider> creds,
                                                                   TokenExchangeOptions options = {}) {
    auto auth = std::make_shared<TokenExchangeAuthenticator>(std::move(creds), std::move(options));
    return test::mock_client([&fake](const HttpRequest& r) { return fake.handle(r); }, auth);
}

}  // namespace

TEST(ProtectedResourceMetadataModel, ParsesAndRejects) {
    const auto f = fixture("responses/oauth.json");
    const auto& valid = f["protectedResourceMetadata"];
    const auto m = ProtectedResourceMetadata::from_json(valid["body"]);
    EXPECT_EQ(m.resource, valid["expected"]["resource"].get<std::string>());
    EXPECT_EQ(m.authorization_servers, valid["expected"]["authorizationServers"].get<std::vector<std::string>>());
    EXPECT_EQ(m.raw, valid["body"]);  // unknown members kept
    for (auto it = f["protectedResourceMetadataInvalid"].begin(); it != f["protectedResourceMetadataInvalid"].end(); ++it) {
        if (it.key() == "description") continue;
        SCOPED_TRACE(it.key());
        EXPECT_THROW(ProtectedResourceMetadata::from_json(it.value()), AuthenticationError);
    }
}

TEST(TokenExchange, FullFlowThenProactiveReuse) {
    FakeLws fake;
    auto [client, transport] = client_for(fake, std::make_shared<OpenIdCredentials>("id-token-123"));
    EXPECT_EQ(client.read("https://storage.example/a.txt").body, "secret data");
    const auto reqs = transport->requests();
    ASSERT_EQ(reqs.size(), 6u);
    EXPECT_EQ(reqs[0].url, "https://storage.example/a.txt");
    EXPECT_FALSE(reqs[0].headers.contains("authorization"));
    EXPECT_EQ(reqs[1].url, "https://storage.example/.well-known/oauth-protected-resource/a.txt");
    EXPECT_EQ(reqs[1].headers.get("accept"), "application/json");
    EXPECT_EQ(reqs[2].url, "https://storage.example/");
    EXPECT_EQ(reqs[2].headers.get("accept"), "application/lws+cid, application/ld+json;q=0.9, application/json;q=0.8");
    EXPECT_EQ(reqs[3].url, "https://as.example/.well-known/lws-configuration");
    for (std::size_t i = 1; i <= 3; ++i) {
        EXPECT_EQ(reqs[i].method, "GET");
        EXPECT_FALSE(reqs[i].headers.contains("authorization")) << reqs[i].url;
    }
    EXPECT_EQ(reqs[4].method, "POST");
    EXPECT_EQ(reqs[4].url, "https://as.example/token");
    EXPECT_EQ(reqs[4].headers.get("content-type"), "application/x-www-form-urlencoded");
    EXPECT_EQ(fake.last_form["grant_type"], "urn:ietf:params:oauth:grant-type:token-exchange");
    EXPECT_EQ(fake.last_form["resource"], "https://storage.example/");
    EXPECT_EQ(fake.last_form["subject_token"], "id-token-123");
    EXPECT_EQ(fake.last_form["subject_token_type"], "urn:ietf:params:oauth:token-type:id_token");
    EXPECT_EQ(reqs[5].headers.get("authorization"), "Bearer tok-1");

    // Proactive reuse: no new 401, no new exchange, no metadata refetch.
    transport->clear();
    EXPECT_EQ(client.read("https://storage.example/b/c.txt").body, "secret data");
    ASSERT_EQ(transport->requests().size(), 1u);
    EXPECT_EQ(transport->requests()[0].headers.get("authorization"), "Bearer tok-1");
    EXPECT_EQ(fake.exchanges, 1);
    // Never outside its scope.
    EXPECT_THROW(client.read("https://other.example/x"), NotFoundError);
    EXPECT_FALSE(transport->requests().back().headers.contains("authorization"));
}

TEST(TokenExchange, CachedTokenCarriesStorageAndScopes) {
    FakeLws fake;
    auto auth = std::make_shared<TokenExchangeAuthenticator>(std::make_shared<OpenIdCredentials>("id"));
    auto [client, transport] = test::mock_client([&](const HttpRequest& r) {
        // The storage https://storage.example/s1 has its root at https://storage.example/data/, which asks for a
        // token; everything else answers with or without one.
        if (r.url == "https://storage.example/s1") return json_response(200, storage_description(r.url, "https://storage.example/data/"));
        if (r.url.starts_with("https://storage.example/data/") && !r.headers.contains("authorization"))
            return make_response(401, {{"WWW-Authenticate", "Bearer resource_metadata=\"/.well-known/oauth-protected-resource" +
                                                                 Url::parse(r.url)->path + "\""},
                                       {"Link", "</s1>; rel=\"https://www.w3.org/ns/lws#storage\""}});
        if (r.url.starts_with("https://as.example/") || r.url.starts_with("https://storage.example/.well-known/"))
            return fake.handle(r);
        return make_response(200, {}, "ok");
    }, auth);
    EXPECT_EQ(client.read("https://storage.example/data/a").body, "ok");
    EXPECT_EQ(fake.last_form["resource"], "https://storage.example/s1");
    ASSERT_EQ(auth->cached_tokens().size(), 1u);
    const auto token = auth->cached_tokens()[0];
    EXPECT_EQ(token.issuer, "https://as.example");
    EXPECT_EQ(token.storage, "https://storage.example/s1");
    EXPECT_EQ(token.scopes, (std::vector<std::string>{"https://storage.example/s1", "https://storage.example/data/"}));
    // The storage URL counts as a directory; a sibling path does not match.
    transport->clear();
    client.read("https://storage.example/s1/x");
    client.read("https://storage.example/s10");
    client.read("https://storage.example/data/b");
    const auto reqs = transport->requests();
    ASSERT_EQ(reqs.size(), 3u);
    EXPECT_EQ(reqs[0].headers.get("authorization"), "Bearer tok-1");
    EXPECT_FALSE(reqs[1].headers.contains("authorization"));
    EXPECT_EQ(reqs[2].headers.get("authorization"), "Bearer tok-1");
}

TEST(TokenExchange, RetryCarriesTokenOutsideItsScope) {
    // A service endpoint outside the storage (https://storage.example/data/) and its root, on their origin.
    FakeLws fake;
    fake.storage = "https://storage.example/data/";
    fake.outside = {"https://storage.example/services/"};
    auto auth = std::make_shared<TokenExchangeAuthenticator>(std::make_shared<OpenIdCredentials>("id"));
    auto [client, transport] = test::mock_client(
        [&](const HttpRequest& r) {
            if (r.url == "https://storage.example/services/moved" && r.headers.contains("authorization"))
                return make_response(302, {{"Location", "/public/elsewhere"}});
            if (r.url == "https://storage.example/public/elsewhere") return make_response(200, {}, "public");
            return fake.handle(r);
        },
        auth);
    // The URL passed the checks, so the retry carries the token although it lies outside the scope.
    EXPECT_EQ(client.read("https://storage.example/services/inbox").body, "secret data");
    EXPECT_EQ(transport->requests().back().headers.get("authorization"), "Bearer tok-1");
    EXPECT_EQ(fake.last_form["resource"], "https://storage.example/data/");

    // Later requests outside the scope get no token up front; their 401 reuses the cached token.
    transport->clear();
    EXPECT_EQ(client.read("https://storage.example/services/other").body, "secret data");
    auto reqs = transport->requests();
    ASSERT_EQ(reqs.size(), 3u);
    EXPECT_FALSE(reqs[0].headers.contains("authorization"));
    EXPECT_EQ(reqs[1].url, "https://storage.example/.well-known/oauth-protected-resource/services/other");
    EXPECT_EQ(reqs[2].headers.get("authorization"), "Bearer tok-1");
    EXPECT_EQ(fake.exchanges, 1);

    // A redirect from the retry is followed without the token.
    transport->clear();
    EXPECT_EQ(client.read("https://storage.example/services/moved").body, "public");
    reqs = transport->requests();
    ASSERT_EQ(reqs.size(), 4u);
    EXPECT_EQ(reqs[2].headers.get("authorization"), "Bearer tok-1");
    EXPECT_EQ(reqs[3].url, "https://storage.example/public/elsewhere");
    EXPECT_FALSE(reqs[3].headers.contains("authorization"));
}

TEST(TokenExchange, LegacyChallengeFlow) {
    FakeLws fake;
    fake.legacy = true;
    auto [client, transport] = client_for(fake, std::make_shared<OpenIdCredentials>("id-token-123"));
    EXPECT_EQ(client.read("https://storage.example/a.txt").body, "secret data");
    const auto reqs = transport->requests();
    ASSERT_EQ(reqs.size(), 4u);
    EXPECT_EQ(reqs[1].url, "https://as.example/.well-known/lws-configuration");
    EXPECT_EQ(reqs[2].method, "POST");
    EXPECT_EQ(fake.last_form["resource"], "https://storage.example/");
    EXPECT_EQ(reqs[3].headers.get("authorization"), "Bearer tok-1");
    transport->clear();
    EXPECT_EQ(client.read("https://storage.example/b/c.txt").body, "secret data");
    ASSERT_EQ(transport->requests().size(), 1u);
    EXPECT_EQ(transport->requests()[0].headers.get("authorization"), "Bearer tok-1");
}

TEST(TokenExchange, RejectedCachedTokenIsReplacedOnce) {
    FakeLws fake;
    auto auth = std::make_shared<TokenExchangeAuthenticator>(std::make_shared<OpenIdCredentials>("id"));
    auto [client, transport] = test::mock_client([&](const HttpRequest& r) { return fake.handle(r); }, auth);
    client.read("https://storage.example/a");
    fake.valid_tokens.clear();  // server revokes tok-1
    transport->clear();
    EXPECT_EQ(client.read("https://storage.example/a").body, "secret data");
    EXPECT_EQ(fake.exchanges, 2);
    EXPECT_EQ(transport->requests().back().headers.get("authorization"), "Bearer tok-2");
    ASSERT_EQ(auth->cached_tokens().size(), 1u);
    EXPECT_EQ(auth->cached_tokens()[0].value, "tok-2");
    // The protected resource metadata is read again; the storage description and AS metadata are cached.
    EXPECT_EQ(count_url(*transport, "https://storage.example/.well-known/oauth-protected-resource/a"), 1u);
    EXPECT_EQ(count_url(*transport, "https://storage.example/"), 0u);
    EXPECT_EQ(count_url(*transport, "https://as.example/.well-known/lws-configuration"), 0u);
}

TEST(TokenExchange, ClearForgetsTokensMetadataAndDescriptions) {
    FakeLws fake;
    auto auth = std::make_shared<TokenExchangeAuthenticator>(std::make_shared<OpenIdCredentials>("id"));
    auto [client, transport] = test::mock_client([&](const HttpRequest& r) { return fake.handle(r); }, auth);
    client.read("https://storage.example/a");
    auth->clear();
    EXPECT_TRUE(auth->cached_tokens().empty());
    transport->clear();
    client.read("https://storage.example/a");
    EXPECT_EQ(count_url(*transport, "https://storage.example/"), 1u);
    EXPECT_EQ(count_url(*transport, "https://as.example/.well-known/lws-configuration"), 1u);
    EXPECT_EQ(fake.exchanges, 2);
}

TEST(TokenExchange, LongestScopeWins) {
    // Two storages on one origin, each with its own authorization server: https://storage.example/ and,
    // inside it, https://storage.example/alice/.
    FakeLws outer;
    FakeLws inner;
    inner.as_uri = "https://as2.example";
    inner.storage = "https://storage.example/alice/";
    inner.token_prefix = "alice-";
    auto auth = std::make_shared<TokenExchangeAuthenticator>(std::make_shared<OpenIdCredentials>("id"));
    auto [client, transport] = test::mock_client(
        [&](const HttpRequest& r) {
            if (r.url.starts_with("https://as2.example/") || r.url.starts_with(inner.storage) ||
                r.url.starts_with("https://storage.example/.well-known/oauth-protected-resource/alice/"))
                return inner.handle(r);
            return outer.handle(r);
        },
        auth);
    EXPECT_EQ(client.read("https://storage.example/alice/x").body, "secret data");
    EXPECT_EQ(client.read("https://storage.example/b").body, "secret data");
    EXPECT_EQ(auth->cached_tokens().size(), 2u);
    transport->clear();
    client.read("https://storage.example/alice/y");
    client.read("https://storage.example/c");
    const auto reqs = transport->requests();
    ASSERT_EQ(reqs.size(), 2u);
    EXPECT_EQ(reqs[0].headers.get("authorization"), "Bearer alice-1");
    EXPECT_EQ(reqs[1].headers.get("authorization"), "Bearer tok-1");
}

TEST(TokenExchange, LegacyRealmMustContainRequestUrl) {
    FakeLws fake;
    auto auth = std::make_shared<TokenExchangeAuthenticator>(std::make_shared<OpenIdCredentials>("id"));
    auto [client, transport] = test::mock_client(
        [&](const HttpRequest& r) {
            if (r.url.starts_with("https://storage.example/"))
                return make_response(401, {{"WWW-Authenticate",
                                            "Bearer as_uri=\"https://as.example\", realm=\"https://storage.example/other/\""}});
            return fake.handle(r);
        },
        auth);
    EXPECT_THROW(client.read("https://storage.example/mine/x"), AuthenticationError);
    EXPECT_EQ(transport->count("POST"), 0u);
    EXPECT_EQ(transport->count("GET", "https://as.example"), 0u);
}

TEST(TokenExchange, DecoyChallengeKeepsCachedToken) {
    // Touchstone's decoy: inside the storage, it answers 401 linking to a storage whose root is on another
    // origin (or, in the drafts before 19 October 2026, naming a realm that does not contain it).
    FakeLws fake;
    auto auth = std::make_shared<TokenExchangeAuthenticator>(std::make_shared<OpenIdCredentials>("id"));
    auto [client, transport] = test::mock_client(
        [&](const HttpRequest& r) {
            if (r.url == "https://storage.example/decoy")
                return make_response(401, {{"WWW-Authenticate", "Bearer resource_metadata=\"https://storage.example/.well-known/"
                                                                "oauth-protected-resource/decoy\", error=\"invalid_token\""},
                                           {"Link", "<https://storage.example/vault/>; rel=\"https://www.w3.org/ns/lws#storage\""}});
            if (r.url == "https://storage.example/vault/")
                return json_response(200, storage_description(r.url, "https://evil.example/vault/"), "application/lws+cid");
            if (r.url == "https://storage.example/legacy-decoy")
                return make_response(401, {{"WWW-Authenticate", "Bearer as_uri=\"https://as.example\", "
                                                                "realm=\"https://storage.example/vault/\", error=\"invalid_token\""}});
            return fake.handle(r);
        },
        auth);
    EXPECT_EQ(client.read("https://storage.example/a").body, "secret data");
    EXPECT_THROW(client.read("https://storage.example/decoy"), AuthenticationError);
    EXPECT_EQ(transport->requests()[transport->requests().size() - 3].headers.get("authorization"), "Bearer tok-1");
    EXPECT_THROW(client.read("https://storage.example/legacy-decoy"), AuthenticationError);
    transport->clear();
    EXPECT_EQ(client.read("https://storage.example/a").body, "secret data");
    ASSERT_EQ(transport->requests().size(), 1u);
    EXPECT_EQ(transport->requests()[0].headers.get("authorization"), "Bearer tok-1");
    EXPECT_EQ(fake.exchanges, 1);
}

TEST(TokenExchange, InsecureAuthorizationServerRejected) {
    FakeLws fake;
    fake.as_uri = "http://as.example";
    auto [client, transport] = client_for(fake, std::make_shared<OpenIdCredentials>("id"));
    EXPECT_THROW(client.read("https://storage.example/a"), AuthenticationError);
    EXPECT_EQ(transport->count("POST"), 0u);
    EXPECT_EQ(transport->count("GET", "http://as.example"), 0u);

    // Unless the options allow plain http.
    TokenExchangeOptions insecure;
    insecure.allow_insecure_http = true;
    auto [ic, it] = client_for(fake, std::make_shared<OpenIdCredentials>("id"), insecure);
    EXPECT_EQ(ic.read("https://storage.example/a").body, "secret data");

    // Loopback is allowed without opting in.
    FakeLws local;
    local.as_uri = "http://localhost:8787";
    local.storage = "http://localhost:8787/";
    auto [lc, lt] = client_for(local, std::make_shared<OpenIdCredentials>("id"));
    EXPECT_EQ(lc.read("http://localhost:8787/x").body, "secret data");
    EXPECT_EQ(local.last_form["resource"], "http://localhost:8787/");
}

TEST(TokenExchange, FirstAcceptableAuthorizationServer) {
    FakeLws fake;
    fake.authorization_servers = {"http://insecure.example", "https://untrusted.example", "https://as.example"};
    std::vector<std::pair<std::string, std::string>> asked;
    TokenExchangeOptions options;
    options.authorization_server_filter = [&](std::string_view issuer, std::string_view storage) {
        asked.emplace_back(issuer, storage);
        return issuer != "https://untrusted.example";
    };
    auto [client, transport] = client_for(fake, std::make_shared<OpenIdCredentials>("id"), options);
    EXPECT_EQ(client.read("https://storage.example/a").body, "secret data");
    EXPECT_EQ(asked, (std::vector<std::pair<std::string, std::string>>{{"https://untrusted.example", "https://storage.example/"},
                                                                       {"https://as.example", "https://storage.example/"}}));
    EXPECT_EQ(transport->count("GET", "http://insecure.example"), 0u);
    EXPECT_EQ(transport->count("GET", "https://untrusted.example"), 0u);
    EXPECT_EQ(count_url(*transport, "https://as.example/.well-known/lws-configuration"), 1u);
}

TEST(TokenExchange, MetadataIssuerMismatch) {
    FakeLws fake;
    fake.metadata["issuer"] = "https://evil.example";
    auto [client, transport] = client_for(fake, std::make_shared<OpenIdCredentials>("id"));
    EXPECT_THROW(client.read("https://storage.example/a"), AuthenticationError);
    EXPECT_EQ(transport->count("POST"), 0u);
}

TEST(TokenExchange, UnsupportedSubjectTokenType) {
    FakeLws fake;
    auto [client, transport] = client_for(fake, std::make_shared<SamlCredentials>(SamlCredentials::from_xml("<a/>")));
    EXPECT_THROW(client.read("https://storage.example/a"), AuthenticationError);
    fake.metadata.erase("subject_token_types_supported");  // absent → not checked
    auto [client2, t2] = client_for(fake, std::make_shared<SamlCredentials>(SamlCredentials::from_xml("<a/>")));
    EXPECT_EQ(client2.read("https://storage.example/a").body, "secret data");
    EXPECT_EQ(fake.last_form["subject_token_type"], "urn:ietf:params:oauth:token-type:saml2");
    EXPECT_EQ(fake.last_form["subject_token"], base64url_encode("<a/>"));
}

TEST(TokenExchange, TokenEndpointErrors) {
    FakeLws fake;
    const auto err = fixture("responses/oauth.json")["errorResponse"];
    fake.token_override = [&](const HttpRequest&) { return json_response(err["status"], err["body"], "application/json"); };
    auto [client, transport] = client_for(fake, std::make_shared<OpenIdCredentials>("id"));
    try {
        client.read("https://storage.example/a");
        FAIL();
    } catch (const AuthenticationError& e) {
        EXPECT_EQ(e.oauth_error(), "invalid_request");
        EXPECT_EQ(e.error_description(), "resource is not a known storage");
    }
    fake.token_override = [](const HttpRequest&) {
        return json_response(200, {{"access_token", "x"}, {"token_type", "DPoP"}}, "application/json");
    };
    EXPECT_THROW(client.read("https://storage.example/a"), AuthenticationError);
    // A redirect from the token endpoint is not followed.
    fake.token_override = [](const HttpRequest&) { return make_response(307, {{"Location", "https://evil.example/token"}}); };
    EXPECT_THROW(client.read("https://storage.example/a"), AuthenticationError);
    EXPECT_EQ(transport->count("POST", "https://evil.example"), 0u);
}

TEST(TokenExchange, ExpiryFromJwtWhenExpiresInAbsent) {
    FakeLws fake;
    const auto f = fixture("responses/oauth.json")["tokenResponseNoExpiry"];
    fake.token_override = [&](const HttpRequest&) {
        fake.valid_tokens.insert(f["body"]["access_token"].get<std::string>());
        return json_response(200, f["body"], "application/json");
    };
    TokenExchangeOptions options;
    options.clock = [] { return std::chrono::system_clock::time_point(std::chrono::seconds(1735686000)); };
    auto auth = std::make_shared<TokenExchangeAuthenticator>(std::make_shared<OpenIdCredentials>("id"), options);
    auto [client, transport] = test::mock_client([&](const HttpRequest& r) { return fake.handle(r); }, auth);
    client.read("https://storage.example/a");
    ASSERT_EQ(auth->cached_tokens().size(), 1u);
    EXPECT_EQ(std::chrono::duration_cast<std::chrono::seconds>(auth->cached_tokens()[0].expires_at.time_since_epoch()).count(),
              f["expectedExp"].get<std::int64_t>());
}

TEST(TokenExchange, ExpiredTokensAreNotSentProactively) {
    FakeLws fake;
    auto now = std::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::now());
    TokenExchangeOptions options;
    options.clock = [now] { return *now; };
    auto [client, transport] = client_for(fake, std::make_shared<OpenIdCredentials>("id"), options);
    client.read("https://storage.example/a");
    *now += std::chrono::seconds(290);  // within the 30 s refresh skew of a 300 s token
    transport->clear();
    client.read("https://storage.example/a");
    EXPECT_FALSE(transport->requests()[0].headers.contains("authorization"));
    EXPECT_EQ(fake.exchanges, 2);
}

TEST(TokenExchange, AuthorizationServerFilter) {
    FakeLws fake;
    TokenExchangeOptions options;
    options.authorization_server_filter = [](std::string_view issuer, std::string_view) { return issuer == "https://trusted.example"; };
    auto [client, transport] = client_for(fake, std::make_shared<OpenIdCredentials>("id"), options);
    EXPECT_THROW(client.read("https://storage.example/a"), AuthenticationError);
    EXPECT_EQ(transport->count("GET", "https://as.example"), 0u);
}

TEST(TokenExchange, NonLwsChallengeSurfacesUnauthorized) {
    auto auth = std::make_shared<TokenExchangeAuthenticator>(std::make_shared<OpenIdCredentials>("id"));
    auto [client, transport] = test::mock_client(
        [](const HttpRequest&) { return make_response(401, {{"WWW-Authenticate", "Basic realm=\"x\""}}); }, auth);
    try {
        client.read("https://storage.example/a");
        FAIL();
    } catch (const UnauthorizedError& e) {
        ASSERT_EQ(e.challenges().size(), 1u);
        EXPECT_TRUE(e.challenges()[0].is_scheme("basic"));
    }
}

TEST(TokenExchange, ConcurrentRequestsShareOneExchange) {
    FakeLws fake;
    auto [client, transport] = client_for(fake, std::make_shared<OpenIdCredentials>("id"));
    std::vector<std::thread> threads;
    std::atomic<int> ok{0};
    for (int i = 0; i < 8; ++i)
        threads.emplace_back([&, i] {
            if (client.read("https://storage.example/r" + std::to_string(i)).body == "secret data") ++ok;
        });
    for (auto& t : threads) t.join();
    EXPECT_EQ(ok, 8);
    EXPECT_EQ(fake.exchanges, 1);
}

// conformance/fixtures/discovery.json: every case through the authenticator, against a mock transport that
// answers as the fixture's description says, with {A} and {B} two origins.
namespace {

void run_discovery_case(const nlohmann::json& tmpl, const nlohmann::json& token_response, const std::string& a,
                        const std::string& b) {
    std::string text = tmpl.dump();
    for (const auto& [placeholder, origin] : {std::pair{std::string("{A}"), a}, std::pair{std::string("{B}"), b}})
        for (auto at = text.find(placeholder); at != std::string::npos; at = text.find(placeholder, at + origin.size()))
            text.replace(at, placeholder.size(), origin);
    const auto c = nlohmann::json::parse(text);
    SCOPED_TRACE(c["name"].get<std::string>() + " with {A} = " + a);
    const std::string request = c["request"];
    const std::string token_endpoint = a + "/as/token";
    const auto ok = [] { return make_response(200, {{"Content-Type", "text/plain"}}, "ok"); };
    std::atomic<bool> later{false};  // the expected.then requests, answered 200 with or without a token
    auto auth = std::make_shared<TokenExchangeAuthenticator>(std::make_shared<OpenIdCredentials>("id-token"));
    auto [client, transport] = test::mock_client(
        [&](const HttpRequest& r) {
            if (later) return ok();
            if (r.method == "GET" && r.url == request) {
                if (r.headers.get("authorization") == "Bearer token-1") return ok();
                HttpHeaders challenge;
                for (auto it = c["challenge"].begin(); it != c["challenge"].end(); ++it)
                    challenge.add(it.key(), it.value().get<std::string>());
                return make_response(401, challenge);
            }
            if (r.method == "GET" && c["documents"].contains(r.url)) {
                const auto& d = c["documents"][r.url];
                HttpHeaders headers;
                for (auto it = d["headers"].begin(); it != d["headers"].end(); ++it)
                    headers.add(it.key(), it.value().get<std::string>());
                return make_response(d["status"].get<int>(), headers, d["body"].is_null() ? std::string() : d["body"].dump());
            }
            if (r.method == "POST" && r.url == token_endpoint) return json_response(200, token_response, "application/json");
            return make_response(404);
        },
        auth);

    const auto& x = c["expected"];
    const std::string outcome = x["outcome"];
    if (outcome == "ok")
        EXPECT_EQ(client.read(request).body, "ok");
    else if (outcome == "AuthenticationError")
        EXPECT_THROW(client.read(request), AuthenticationError);
    else if (outcome == "UnauthorizedError")
        EXPECT_THROW(client.read(request), UnauthorizedError);
    else
        ADD_FAILURE() << "unknown outcome " << outcome;

    const auto reqs = transport->requests();
    std::vector<HttpRequest> posts;
    for (const auto& r : reqs) {
        if (r.method == "POST") posts.push_back(r);
        // Discovery requests carry no credentials.
        if (r.url != request) {
            EXPECT_FALSE(r.headers.contains("authorization")) << r.url;
        }
    }
    if (x["tokenRequest"].is_null()) {
        EXPECT_TRUE(posts.empty());
    } else {
        ASSERT_EQ(posts.size(), 1u);
        EXPECT_EQ(posts[0].url, x["tokenRequest"]["endpoint"].get<std::string>());
        EXPECT_EQ(parse_form(posts[0].body)["resource"], x["tokenRequest"]["resource"].get<std::string>());
    }
    for (const auto& url : x["notFetched"]) EXPECT_EQ(count_url(*transport, url.get<std::string>()), 0u) << url;

    if (!x.contains("then")) return;
    later = true;
    for (const auto& t : x["then"]) {
        transport->clear();
        client.read(t["request"].get<std::string>());
        const auto sent = transport->requests();
        ASSERT_EQ(sent.size(), 1u);
        EXPECT_EQ(sent[0].headers.get("authorization") == std::optional<std::string>("Bearer token-1"),
                  t["sendsToken"].get<bool>())
            << t["request"];
    }
}

}  // namespace

TEST(TokenExchange, DiscoveryFixtures) {
    const auto f = fixture("discovery.json");
    ASSERT_EQ(f["cases"].size(), 17u);
    // Two https origins, and two loopback origins served by one listener (plain http allowed on loopback).
    for (const auto& [a, b] : {std::pair{std::string("https://storage-a.example"), std::string("https://storage-b.example")},
                               std::pair{std::string("http://127.0.0.1:8787"), std::string("http://localhost:8787")}})
        for (const auto& c : f["cases"]) run_discovery_case(c, f["tokenResponse"], a, b);
}

TEST(BearerToken, ScopedToRealmAndRefreshable) {
    std::atomic<int> generation{1};
    auto auth = std::make_shared<BearerTokenAuthenticator>(
        [&] { return "t" + std::to_string(generation.load()); }, std::optional<std::string>("https://storage.example/"));
    auto [client, transport] = test::mock_client(
        [&](const HttpRequest& r) {
            if (r.headers.get("authorization") == "Bearer t2" || r.url.starts_with("https://other.example"))
                return make_response(200);
            generation = 2;  // simulate a refreshed token becoming available
            return make_response(401);
        },
        auth);
    client.head("https://storage.example/x");
    const auto reqs = transport->requests();
    ASSERT_EQ(reqs.size(), 2u);
    EXPECT_EQ(reqs[0].headers.get("authorization"), "Bearer t1");
    EXPECT_EQ(reqs[1].headers.get("authorization"), "Bearer t2");
    client.head("https://other.example/x");
    EXPECT_FALSE(transport->requests().back().headers.contains("authorization"));
}

TEST(Credentials, OpenIdAndSamlProviders) {
    CredentialContext ctx{"https://as.example", "https://s.example/", {}};
    OpenIdCredentials openid([](const CredentialContext& c) { return "token-for-" + c.issuer + "-" + c.storage; });
    EXPECT_EQ(openid.subject_token(ctx), "token-for-https://as.example-https://s.example/");
    EXPECT_EQ(openid.token_type(), oauth::token_type_id_token);
    auto saml = SamlCredentials::from_xml("<saml:Assertion/>");
    EXPECT_EQ(saml.token_type(), oauth::token_type_saml2);
    EXPECT_EQ(base64url_decode(saml.subject_token(ctx)), "<saml:Assertion/>");
    EXPECT_FALSE(decode_jwt_payload("not-a-jwt"));
    EXPECT_EQ((*decode_jwt_payload("eyJhbGciOiJub25lIn0.eyJleHAiOjF9.x"))["exp"], 1);
}
