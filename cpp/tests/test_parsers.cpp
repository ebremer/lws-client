// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Parser and builder tests driven by the shared conformance fixtures.

#include <gtest/gtest.h>

#include "test_support.hpp"

using namespace lws;
using lws::test::fixture;

// ---- Link (RFC 8288) ----------------------------------------------------------------------

TEST(LinkHeader, ConformanceFixtures) {
    const auto f = fixture("link-headers.json");
    for (const auto& c : f["cases"]) {
        SCOPED_TRACE(c["name"].get<std::string>());
        std::vector<std::string> headers = c["headers"].get<std::vector<std::string>>();
        const auto links = parse_link_headers(headers, c["base"].get<std::string>());
        ASSERT_EQ(links.size(), c["expected"].size());
        for (std::size_t i = 0; i < links.size(); ++i) {
            const auto& e = c["expected"][i];
            EXPECT_EQ(links[i].href, e["href"].get<std::string>());
            EXPECT_EQ(links[i].rel, e["rel"].get<std::string>());
            std::map<std::string, std::string> params = e["params"].get<std::map<std::string, std::string>>();
            EXPECT_EQ(links[i].params, params);
        }
    }
}

TEST(LinkHeader, SerializeRoundTrip) {
    Link link{"https://example.org/a", "describedby", {{"title", "say \"hi\""}, {"type", "text/html"}}};
    const auto header = link.to_header();
    EXPECT_EQ(header, R"(<https://example.org/a>; rel="describedby"; title="say \"hi\""; type="text/html")");
    const auto parsed = parse_link_header(header, "https://example.org/");
    ASSERT_EQ(parsed.size(), 1u);
    EXPECT_EQ(parsed[0], link);
    EXPECT_EQ(parsed[0].type(), "text/html");
}

TEST(LinkHeader, AnchorResolution) {
    const auto links = parse_link_header(R"(<https://example.org/f>; rel="describedby"; anchor="#frag")", "https://example.org/doc");
    ASSERT_EQ(links.size(), 1u);
    EXPECT_EQ(links[0].anchor("https://example.org/doc"), "https://example.org/doc#frag");
}

// ---- WWW-Authenticate ---------------------------------------------------------------------

TEST(WwwAuthenticate, ConformanceFixtures) {
    const auto f = fixture("www-authenticate.json");
    for (const auto& c : f["cases"]) {
        SCOPED_TRACE(c["name"].get<std::string>());
        const auto challenges = parse_www_authenticate(c["headers"].get<std::vector<std::string>>());
        ASSERT_EQ(challenges.size(), c["expected"].size());
        for (std::size_t i = 0; i < challenges.size(); ++i) {
            const auto& e = c["expected"][i];
            EXPECT_TRUE(iequals(challenges[i].scheme, e["scheme"].get<std::string>()));
            EXPECT_EQ(challenges[i].params, (e["params"].get<std::map<std::string, std::string>>()));
            if (e.contains("token68"))
                EXPECT_EQ(challenges[i].token68, e["token68"].get<std::string>());
            else
                EXPECT_FALSE(challenges[i].token68.has_value());
        }
    }
}

TEST(WwwAuthenticate, Accessors) {
    const auto ch = parse_www_authenticate(R"(Bearer as_uri="https://as.example", realm="https://s.example/", error="invalid_token")");
    ASSERT_EQ(ch.size(), 1u);
    EXPECT_TRUE(ch[0].is_scheme("bearer"));
    EXPECT_EQ(ch[0].as_uri(), "https://as.example");
    EXPECT_EQ(ch[0].realm(), "https://s.example/");
    EXPECT_EQ(ch[0].error(), "invalid_token");
    EXPECT_FALSE(ch[0].error_description());
}

// ---- Structured fields ----------------------------------------------------------------------

namespace {
nlohmann::json typed(const sf::BareItem& v) {
    struct V {
        nlohmann::json operator()(std::int64_t x) const { return {{"integer", x}}; }
        nlohmann::json operator()(double x) const { return {{"decimal", x}}; }
        nlohmann::json operator()(const std::string& x) const { return {{"string", x}}; }
        nlohmann::json operator()(const sf::Token& x) const { return {{"token", x.value}}; }
        nlohmann::json operator()(const sf::ByteSequence& x) const { return {{"bytes", base64_encode(x.bytes)}}; }
        nlohmann::json operator()(bool x) const { return {{"boolean", x}}; }
        nlohmann::json operator()(const sf::Date& x) const { return {{"date", x.seconds}}; }
        nlohmann::json operator()(const sf::DisplayString& x) const { return {{"displaystring", x.value}}; }
    };
    return std::visit(V{}, v);
}
nlohmann::json typed(const sf::Parameters& p) {
    nlohmann::json out = nlohmann::json::object();
    for (const auto& [k, v] : p) out[k] = typed(v);
    return out;
}
nlohmann::json typed(const sf::Item& i) { return {{"item", typed(i.value)}, {"params", typed(i.params)}}; }
nlohmann::json typed(const sf::Member& m) {
    if (const auto* i = std::get_if<sf::Item>(&m)) return typed(*i);
    const auto& l = std::get<sf::InnerList>(m);
    nlohmann::json items = nlohmann::json::array();
    for (const auto& i : l.items) items.push_back(typed(i));
    return {{"innerList", items}, {"params", typed(l.params)}};
}
// Canonicalise base64 in expected values (padding).
void canonical_bytes(nlohmann::json& j) {
    if (j.is_object()) {
        for (auto it = j.begin(); it != j.end(); ++it) {
            if (it.key() == "bytes" && it.value().is_string())
                it.value() = base64_encode(base64_decode(it.value().get<std::string>()));
            else
                canonical_bytes(it.value());
        }
    } else if (j.is_array()) {
        for (auto& v : j) canonical_bytes(v);
    }
}
}  // namespace

TEST(StructuredFields, ConformanceFixtures) {
    const auto f = fixture("structured-fields.json");
    for (const auto& c : f["cases"]) {
        SCOPED_TRACE(c["name"].get<std::string>());
        const auto input = c["input"].get<std::string>();
        if (c.value("error", false)) {
            EXPECT_THROW(sf::parse_dictionary(input), ParseError);
            continue;
        }
        const auto dict = sf::parse_dictionary(input);
        nlohmann::json actual = nlohmann::json::object();
        for (const auto& [k, m] : dict) actual[k] = typed(m);
        auto expected = c["expected"];
        canonical_bytes(expected);
        EXPECT_EQ(actual, expected);
        if (c.contains("serialized")) {
            for (auto it = c["serialized"].begin(); it != c["serialized"].end(); ++it) {
                const auto* m = sf::find(dict, it.key());
                ASSERT_NE(m, nullptr);
                EXPECT_EQ(sf::serialize(*m), it.value().get<std::string>());
            }
        }
    }
}

// ---- JSON Patch / Pointer -------------------------------------------------------------------

TEST(JsonPatch, ConformanceFixtures) {
    const auto f = fixture("json-patch.json");
    for (const auto& c : f["pointerEscapes"])
        EXPECT_EQ(JsonPointer::escape(c["segment"].get<std::string>()), c["escaped"].get<std::string>());
    for (const auto& c : f["pointers"])
        EXPECT_EQ(JsonPointer::from_segments(c["segments"].get<std::vector<std::string>>()), c["pointer"].get<std::string>());
    JsonPatch patch;
    patch.add("/linkset/0/license", nlohmann::json::array({{{"href", "https://creativecommons.org/licenses/by/4.0/"}}}))
        .remove("/linkset/0/describedby/0")
        .replace("/name", "Alice")
        .move("/a", "/b")
        .copy("/b", "/c")
        .test("/age", 30);
    EXPECT_EQ(patch.to_json(), f["patch"]["operations"]);
    EXPECT_EQ(patch.size(), 6u);
}

// ---- Type queries ---------------------------------------------------------------------------

TEST(TypeQuery, ConformanceFixtures) {
    const auto f = fixture("type-queries.json");
    for (const auto& c : f["cases"]) {
        SCOPED_TRACE(c["name"].get<std::string>());
        auto build = [&] {
            TypeQuery q;
            for (const auto& step : c["steps"]) {
                const auto key = step["key"].get<std::string>();
                if (step.contains("allOf")) {
                    const auto v = step["allOf"].get<std::vector<std::string>>();
                    key == "type" ? q.all_of(v) : q.relation_all_of(key, v);
                } else {
                    const auto v = step["anyOf"].get<std::vector<std::string>>();
                    key == "type" ? q.any_of(v) : q.relation_any_of(key, v);
                }
            }
            return q;
        };
        if (c.value("error", false)) {
            EXPECT_THROW(build(), std::invalid_argument);
        } else {
            EXPECT_EQ(build().to_json(), c["json"]);
        }
    }
}

// ---- URLs, realms, metadata URLs --------------------------------------------------------------

TEST(Url, Rfc3986ReferenceResolution) {
    const std::string base = "http://a/b/c/d;p?q";
    const std::pair<const char*, const char*> cases[] = {
        {"g:h", "g:h"},           {"g", "http://a/b/c/g"},       {"./g", "http://a/b/c/g"},
        {"g/", "http://a/b/c/g/"}, {"/g", "http://a/g"},           {"//g", "http://g"},
        {"?y", "http://a/b/c/d;p?y"}, {"g?y", "http://a/b/c/g?y"}, {"#s", "http://a/b/c/d;p?q#s"},
        {"g#s", "http://a/b/c/g#s"}, {";x", "http://a/b/c/;x"},   {"", "http://a/b/c/d;p?q"},
        {".", "http://a/b/c/"},   {"./", "http://a/b/c/"},       {"..", "http://a/b/"},
        {"../g", "http://a/b/g"}, {"../..", "http://a/"},         {"../../g", "http://a/g"},
        {"../../../g", "http://a/g"}, {"/./g", "http://a/g"},     {"g.", "http://a/b/c/g."},
        {"g;x=1/../y", "http://a/b/c/y"},
    };
    for (const auto& [ref, expected] : cases) EXPECT_EQ(resolve_url(base, ref), expected) << ref;
}

TEST(Url, ParseComponents) {
    auto u = Url::parse("HTTPS://User@Storage.Example:8443/a/b?x=1#frag");
    ASSERT_TRUE(u);
    EXPECT_EQ(u->scheme, "https");
    EXPECT_EQ(u->host, "storage.example");
    EXPECT_EQ(u->port, "8443");
    EXPECT_EQ(u->path, "/a/b");
    EXPECT_EQ(u->query, "x=1");
    EXPECT_EQ(u->fragment, "frag");
    EXPECT_EQ(u->origin(), "https://storage.example:8443");
    EXPECT_EQ(Url::parse("https://h:443/")->authority_for_signature(), "h");
    EXPECT_EQ(Url::parse("http://[::1]:8080/x")->host, "[::1]");
    EXPECT_TRUE(is_absolute_iri("did:key:z6Mk"));
    EXPECT_FALSE(is_absolute_iri("Person"));
    EXPECT_TRUE(is_loopback("http://localhost:8787/"));
    EXPECT_TRUE(is_loopback("http://127.0.0.1/"));
    EXPECT_FALSE(is_loopback("https://storage.example/"));
}

TEST(Url, RealmChecksAndMetadataUrls) {
    const auto f = fixture("responses/oauth.json");
    for (const auto& c : f["realmChecks"]) {
        EXPECT_EQ(url_within_realm(c["url"].get<std::string>(), c["realm"].get<std::string>()), c["contained"].get<bool>())
            << c["url"] << " in " << c["realm"];
    }
    for (const auto& c : f["metadataUrls"])
        EXPECT_EQ(authorization_server_metadata_url(c["issuer"].get<std::string>()), c["url"].get<std::string>());
}

// ---- Encodings ----------------------------------------------------------------------------

TEST(Encoding, Base64Variants) {
    EXPECT_EQ(base64_encode("test"), "dGVzdA==");
    EXPECT_EQ(base64_decode("dGVzdA=="), "test");
    EXPECT_EQ(base64_decode("dGVzdA"), "test");
    EXPECT_EQ(base64url_encode("\xfb\xff"), "-_8");
    EXPECT_EQ(base64url_decode("-_8"), "\xfb\xff");
    EXPECT_THROW(base64_decode("@@@@"), ParseError);
    const std::string bytes("\0\0\x01\x02\xff", 5);
    EXPECT_EQ(base58btc_decode(base58btc_encode(bytes)), bytes);
    EXPECT_EQ(base58btc_encode("hello world"), "StV1DL6CwTryKyV");
}

TEST(Encoding, SlugAndForm) {
    EXPECT_EQ(slug_encode("hello.txt"), "hello.txt");
    EXPECT_EQ(slug_encode("caf\xc3\xa9 100%"), "caf%C3%A9 100%25");
    EXPECT_EQ(form_url_encode("urn:ietf:params:oauth:grant-type:token-exchange"),
              "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange");
    EXPECT_EQ(form_url_encode("a b+c"), "a+b%2Bc");
}

TEST(Encoding, Rfc3339) {
    const auto t = parse_rfc3339("2026-03-26T10:30:00Z");
    ASSERT_TRUE(t);
    EXPECT_EQ(std::chrono::duration_cast<std::chrono::seconds>(t->time_since_epoch()).count(), 1774521000);
    EXPECT_EQ(format_rfc3339(*t), "2026-03-26T10:30:00Z");
    EXPECT_EQ(parse_rfc3339("2026-03-26T12:30:00.250+02:00").value() - *t, std::chrono::milliseconds(250));
    EXPECT_FALSE(parse_rfc3339("not-a-date"));
    EXPECT_FALSE(parse_rfc3339("2026-13-01T00:00:00Z"));
    EXPECT_FALSE(parse_rfc3339("2026-03-26T10:30:00"));
}

TEST(Constants, TypeMatching) {
    EXPECT_TRUE(type_matches("Container", types::container));
    EXPECT_TRUE(type_matches("lws:Container", "Container"));
    EXPECT_TRUE(type_matches("https://www.w3.org/ns/lws#DataResource", "DataResource"));
    EXPECT_FALSE(type_matches("Container", types::data_resource));
    EXPECT_FALSE(type_matches("http://example.org/Container", "Container"));
    EXPECT_TRUE(type_matches("StorageRoot", "https://www.w3.org/ns/lws#StorageRoot"));
}

TEST(HttpHeaders, CaseInsensitiveMultimap) {
    HttpHeaders h;
    h.add("Link", "<a>; rel=up").add("link", "<b>; rel=type").add("Allow", "GET, HEAD,PUT");
    EXPECT_EQ(h.get_all("LINK").size(), 2u);
    EXPECT_EQ(h.get_combined("link"), "<a>; rel=up, <b>; rel=type");
    EXPECT_EQ(h.get_list("allow"), (std::vector<std::string>{"GET", "HEAD", "PUT"}));
    h.set("LINK", "<c>");
    EXPECT_EQ(h.get_all("link"), std::vector<std::string>{"<c>"});
    h.remove("link");
    EXPECT_FALSE(h.contains("Link"));
}
