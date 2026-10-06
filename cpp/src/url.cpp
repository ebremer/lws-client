// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include "lws/url.hpp"

#include <algorithm>
#include <cctype>

#include "lws/constants.hpp"

namespace lws {
namespace {

std::string lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    return out;
}

std::size_t scheme_length(std::string_view text) noexcept {
    if (text.empty() || !std::isalpha(static_cast<unsigned char>(text[0]))) return 0;
    for (std::size_t i = 1; i < text.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if (c == ':') return i;
        if (!std::isalnum(c) && c != '+' && c != '-' && c != '.') return 0;
    }
    return 0;
}

// RFC 3986 §5.2.4
std::string remove_dot_segments(std::string_view input) {
    std::string in(input);
    std::string out;
    while (!in.empty()) {
        if (in.starts_with("../")) {
            in.erase(0, 3);
        } else if (in.starts_with("./")) {
            in.erase(0, 2);
        } else if (in.starts_with("/./")) {
            in.replace(0, 3, "/");
        } else if (in == "/.") {
            in = "/";
        } else if (in.starts_with("/../")) {
            in.replace(0, 4, "/");
            auto pos = out.rfind('/');
            out.erase(pos == std::string::npos ? 0 : pos);
        } else if (in == "/..") {
            in = "/";
            auto pos = out.rfind('/');
            out.erase(pos == std::string::npos ? 0 : pos);
        } else if (in == "." || in == "..") {
            in.clear();
        } else {
            std::size_t start = in[0] == '/' ? 1 : 0;
            std::size_t next = in.find('/', start);
            if (next == std::string::npos) next = in.size();
            out.append(in, 0, next);
            in.erase(0, next);
        }
    }
    return out;
}

int default_port(std::string_view scheme) noexcept {
    if (scheme == "http" || scheme == "ws") return 80;
    if (scheme == "https" || scheme == "wss") return 443;
    return -1;
}

}  // namespace

std::optional<Url> Url::parse(std::string_view text) {
    Url url;
    std::string_view rest = text;
    if (auto n = scheme_length(rest); n > 0) {
        url.scheme = lower(rest.substr(0, n));
        rest.remove_prefix(n + 1);
    }
    if (auto hash = rest.find('#'); hash != std::string_view::npos) {
        url.fragment = std::string(rest.substr(hash + 1));
        rest = rest.substr(0, hash);
    }
    if (auto q = rest.find('?'); q != std::string_view::npos) {
        url.query = std::string(rest.substr(q + 1));
        rest = rest.substr(0, q);
    }
    if (rest.starts_with("//")) {
        rest.remove_prefix(2);
        auto slash = rest.find('/');
        std::string_view authority = rest.substr(0, slash);
        rest = slash == std::string_view::npos ? std::string_view{} : rest.substr(slash);
        url.authority = std::string(authority);
        std::string_view hostport = authority;
        if (auto at = hostport.rfind('@'); at != std::string_view::npos) hostport.remove_prefix(at + 1);
        if (hostport.starts_with("[")) {
            auto close = hostport.find(']');
            if (close == std::string_view::npos) return std::nullopt;
            url.host = lower(hostport.substr(0, close + 1));
            hostport.remove_prefix(close + 1);
            if (!hostport.empty()) {
                if (hostport[0] != ':') return std::nullopt;
                url.port = std::string(hostport.substr(1));
            }
        } else {
            auto colon = hostport.rfind(':');
            if (colon != std::string_view::npos) {
                url.port = std::string(hostport.substr(colon + 1));
                hostport = hostport.substr(0, colon);
            }
            url.host = lower(hostport);
        }
        if (!std::all_of(url.port.begin(), url.port.end(), [](unsigned char c) { return std::isdigit(c); }))
            return std::nullopt;
    }
    url.path = std::string(rest);
    return url;
}

std::string Url::str() const {
    std::string out;
    if (!scheme.empty()) out += scheme + ":";
    if (authority) {
        out += "//";
        // Rebuild with normalised host while keeping userinfo.
        std::string_view a = *authority;
        if (auto at = a.rfind('@'); at != std::string_view::npos) out.append(a.substr(0, at + 1));
        out += host;
        if (!port.empty()) out += ":" + port;
    }
    out += path;
    if (query) out += "?" + *query;
    if (fragment) out += "#" + *fragment;
    return out;
}

int Url::effective_port() const noexcept {
    if (!port.empty()) {
        try {
            return std::stoi(port);
        } catch (...) {
            return -1;
        }
    }
    return default_port(scheme);
}

std::string Url::origin() const {
    std::string out = scheme + "://" + host;
    if (const int p = effective_port(); p != default_port(scheme) && p >= 0) out += ":" + std::to_string(p);
    return out;
}

std::string Url::authority_for_signature() const {
    std::string out = host;
    if (const int p = effective_port(); p != default_port(scheme) && p >= 0) out += ":" + std::to_string(p);
    return out;
}

std::string resolve_url(std::string_view base, std::string_view reference) {
    auto r = Url::parse(reference);
    if (!r) return std::string(reference);
    Url t;
    if (r->is_absolute()) {
        t = *r;
        t.path = remove_dot_segments(r->path);
        return t.str();
    }
    auto b = Url::parse(base);
    if (!b || !b->is_absolute()) return std::string(reference);
    if (r->authority) {
        t = *r;
        t.path = remove_dot_segments(r->path);
    } else {
        if (r->path.empty()) {
            t.path = b->path;
            t.query = r->query ? r->query : b->query;
        } else {
            if (r->path.starts_with("/")) {
                t.path = remove_dot_segments(r->path);
            } else {
                std::string merged;
                if (b->authority && b->path.empty()) {
                    merged = "/" + r->path;
                } else {
                    auto slash = b->path.rfind('/');
                    merged = (slash == std::string::npos ? std::string() : b->path.substr(0, slash + 1)) + r->path;
                }
                t.path = remove_dot_segments(merged);
            }
            t.query = r->query;
        }
        t.authority = b->authority;
        t.host = b->host;
        t.port = b->port;
    }
    t.scheme = b->scheme;
    t.fragment = r->fragment;
    return t.str();
}

bool is_absolute_iri(std::string_view text) noexcept { return scheme_length(text) > 0; }

std::string strip_fragment(std::string_view url) {
    auto hash = url.find('#');
    return std::string(url.substr(0, hash));
}

bool is_loopback(std::string_view url) {
    auto u = Url::parse(url);
    if (!u) return false;
    const std::string& h = u->host;
    return h == "localhost" || h.ends_with(".localhost") || h.starts_with("127.") || h == "[::1]";
}

bool url_within_realm(std::string_view url, std::string_view realm) {
    auto u = Url::parse(url);
    auto r = Url::parse(realm);
    if (!u || !r || !u->is_absolute() || !r->is_absolute()) return false;
    if (u->scheme != r->scheme || u->host != r->host || u->effective_port() != r->effective_port()) return false;
    std::string realm_path = r->path.empty() ? "/" : r->path;
    std::string path = u->path.empty() ? "/" : u->path;
    if (path == realm_path) return true;
    if (!realm_path.ends_with('/')) realm_path += '/';
    return path.starts_with(realm_path);
}

std::string authorization_server_metadata_url(std::string_view issuer) {
    auto u = Url::parse(issuer);
    if (!u || !u->is_absolute()) return std::string(issuer) + std::string(oauth::well_known_lws_configuration);
    std::string path = u->path;
    if (path == "/") path.clear();
    while (path.ends_with('/')) path.pop_back();
    Url out = *u;
    out.path = std::string(oauth::well_known_lws_configuration) + path;
    out.query.reset();
    out.fragment.reset();
    return out.str();
}

bool type_matches(std::string_view actual, std::string_view expected) noexcept {
    auto normalize = [](std::string_view t) -> std::string {
        if (t.starts_with(ns::lws)) return std::string(t);
        if (t.starts_with("lws:")) return std::string(ns::lws) + std::string(t.substr(4));
        if (t.find(':') == std::string_view::npos) return std::string(ns::lws) + std::string(t);
        return std::string(t);
    };
    if (actual == expected) return true;
    try {
        return normalize(actual) == normalize(expected);
    } catch (...) {
        return false;
    }
}

}  // namespace lws
