// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// The LWS authorization flow: 401 → metadata → token exchange → retry.

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

// A fake storage (https://storage.example/) protected by a fake AS (https://as.example).
struct FakeLws {
    std::string as_uri = "https://as.example";
    std::string realm = "https://storage.example/";
    nlohmann::json metadata = fixture("responses/oauth.json")["metadata"];
    std::atomic<int> exchanges{0};
    std::set<std::string> valid_tokens;
    std::mutex mutex;
    std::map<std::string, std::string> last_form;
    std::function<HttpResponse(const HttpRequest&)> token_override;

    FakeLws() {
        metadata["issuer"] = as_uri;
        metadata["token_endpoint"] = "https://as.example/token";
    }

    HttpResponse handle(const HttpRequest& r) {
        if (r.url == "https://as.example/.well-known/lws-configuration") return json_response(200, metadata, "application/json");
        if (r.url == "https://as.example/token") {
            if (token_override) return token_override(r);
            const int n = ++exchanges;
            std::lock_guard lock(mutex);
            last_form = parse_form(r.body);
            const std::string token = "tok-" + std::to_string(n);
            valid_tokens.insert(token);
            return json_response(200, {{"access_token", token}, {"token_type", "Bearer"}, {"expires_in", 300}},
                                 "application/json");
        }
        if (r.url.starts_with(realm)) {
            const auto auth = r.headers.get("authorization").value_or("");
            {
                std::lock_guard lock(mutex);
                if (auth.starts_with("Bearer ") && valid_tokens.contains(auth.substr(7))) return make_response(200, {}, "secret data");
            }
            return make_response(401, {{"WWW-Authenticate", "Bearer as_uri=\"" + as_uri + "\", realm=\"" + realm +
                                                               "\", error=\"invalid_token\""}});
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

TEST(TokenExchange, FullFlowThenProactiveReuse) {
    FakeLws fake;
    auto [client, transport] = client_for(fake, std::make_shared<OpenIdCredentials>("id-token-123"));
    EXPECT_EQ(client.read("https://storage.example/a.txt").body, "secret data");
    const auto reqs = transport->requests();
    ASSERT_EQ(reqs.size(), 4u);
    EXPECT_EQ(reqs[0].url, "https://storage.example/a.txt");
    EXPECT_FALSE(reqs[0].headers.contains("authorization"));
    EXPECT_EQ(reqs[1].url, "https://as.example/.well-known/lws-configuration");
    EXPECT_EQ(reqs[2].method, "POST");
    EXPECT_EQ(reqs[2].headers.get("content-type"), "application/x-www-form-urlencoded");
    EXPECT_EQ(fake.last_form["grant_type"], "urn:ietf:params:oauth:grant-type:token-exchange");
    EXPECT_EQ(fake.last_form["resource"], "https://storage.example/");
    EXPECT_EQ(fake.last_form["subject_token"], "id-token-123");
    EXPECT_EQ(fake.last_form["subject_token_type"], "urn:ietf:params:oauth:token-type:id_token");
    EXPECT_EQ(reqs[3].headers.get("authorization"), "Bearer tok-1");

    // Proactive reuse: no new 401, no new exchange, no metadata refetch.
    transport->clear();
    EXPECT_EQ(client.read("https://storage.example/b/c.txt").body, "secret data");
    ASSERT_EQ(transport->requests().size(), 1u);
    EXPECT_EQ(transport->requests()[0].headers.get("authorization"), "Bearer tok-1");
    EXPECT_EQ(fake.exchanges, 1);
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
}

TEST(TokenExchange, RealmMustContainRequestUrl) {
    FakeLws fake;
    fake.realm = "https://storage.example/";
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
    // Touchstone's decoy: inside the storage, it answers 401 naming a realm that does not contain it.
    FakeLws fake;
    auto auth = std::make_shared<TokenExchangeAuthenticator>(std::make_shared<OpenIdCredentials>("id"));
    auto [client, transport] = test::mock_client(
        [&](const HttpRequest& r) {
            if (r.url == "https://storage.example/decoy")
                return make_response(401, {{"WWW-Authenticate", "Bearer as_uri=\"https://as.example\", "
                                                                "realm=\"https://storage.example/vault/\", error=\"invalid_token\""}});
            return fake.handle(r);
        },
        auth);
    EXPECT_EQ(client.read("https://storage.example/a").body, "secret data");
    EXPECT_THROW(client.read("https://storage.example/decoy"), AuthenticationError);
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

    // Loopback is allowed without opting in.
    FakeLws local;
    local.as_uri = "http://localhost:8787";
    local.realm = "http://localhost:8787/";
    local.metadata["issuer"] = local.as_uri;
    local.metadata["token_endpoint"] = "http://localhost:8787/oauth/token";
    auto [lc, lt] = test::mock_client(
        [&](const HttpRequest& r) {
            HttpRequest copy = r;
            if (r.url == "http://localhost:8787/.well-known/lws-configuration") return json_response(200, local.metadata);
            if (r.url == "http://localhost:8787/oauth/token") {
                copy.url = "https://as.example/token";
                return local.handle(copy);
            }
            return local.handle(r);
        },
        std::make_shared<TokenExchangeAuthenticator>(std::make_shared<OpenIdCredentials>("id")));
    EXPECT_EQ(lc.read("http://localhost:8787/x").body, "secret data");
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
    options.authorization_server_filter = [](std::string_view as, std::string_view) { return as == "https://trusted.example"; };
    auto [client, transport] = client_for(fake, std::make_shared<OpenIdCredentials>("id"), options);
    EXPECT_THROW(client.read("https://storage.example/a"), AuthenticationError);
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
    OpenIdCredentials openid([](const CredentialContext& c) { return "token-for-" + c.issuer; });
    EXPECT_EQ(openid.subject_token(ctx), "token-for-https://as.example");
    EXPECT_EQ(openid.token_type(), oauth::token_type_id_token);
    auto saml = SamlCredentials::from_xml("<saml:Assertion/>");
    EXPECT_EQ(saml.token_type(), oauth::token_type_saml2);
    EXPECT_EQ(base64url_decode(saml.subject_token(ctx)), "<saml:Assertion/>");
    EXPECT_FALSE(decode_jwt_payload("not-a-jwt"));
    EXPECT_EQ((*decode_jwt_payload("eyJhbGciOiJub25lIn0.eyJleHAiOjF9.x"))["exp"], 1);
}
