// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include "lws/link.hpp"

#include <algorithm>
#include <cctype>

#include "lws/http.hpp"
#include "lws/url.hpp"

namespace lws {
namespace {

bool is_space(char c) noexcept { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

bool is_tchar(char c) noexcept {
    const auto u = static_cast<unsigned char>(c);
    if (std::isalnum(u)) return true;
    switch (c) {
        case '!': case '#': case '$': case '%': case '&': case '\'': case '*': case '+': case '-':
        case '.': case '^': case '_': case '`': case '|': case '~':
            return true;
        default:
            return false;
    }
}

std::string lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    return out;
}

// Small cursor over a header value.
struct Cursor {
    std::string_view s;
    std::size_t i = 0;

    bool done() const noexcept { return i >= s.size(); }
    char peek() const noexcept { return done() ? '\0' : s[i]; }
    void skip_ws() noexcept {
        while (!done() && is_space(s[i])) ++i;
    }
    std::string token() {
        std::size_t start = i;
        while (!done() && is_tchar(s[i])) ++i;
        return std::string(s.substr(start, i - start));
    }
    // Reads a quoted-string starting at '"'; returns the unescaped value.
    std::string quoted() {
        std::string out;
        ++i;  // opening quote
        while (!done()) {
            char c = s[i++];
            if (c == '\\' && !done()) {
                out += s[i++];
            } else if (c == '"') {
                return out;
            } else {
                out += c;
            }
        }
        return out;  // unterminated — be lenient
    }
};

}  // namespace

std::optional<std::string> Link::type() const {
    if (auto it = params.find("type"); it != params.end()) return it->second;
    return std::nullopt;
}

std::optional<std::string> Link::anchor(std::string_view base) const {
    if (auto it = params.find("anchor"); it != params.end()) return resolve_url(base, it->second);
    return std::nullopt;
}

std::string Link::to_header() const {
    auto quote = [](std::string_view v) {
        std::string out = "\"";
        for (char c : v) {
            if (c == '"' || c == '\\') out += '\\';
            out += c;
        }
        return out + "\"";
    };
    std::string out = "<" + href + ">; rel=" + quote(rel);
    for (const auto& [name, value] : params) {
        if (name == "rel") continue;
        out += "; " + name;
        if (!value.empty()) out += "=" + quote(value);
    }
    return out;
}

std::vector<Link> parse_link_header(std::string_view value, std::string_view base) {
    std::vector<Link> links;
    Cursor c{value};
    while (true) {
        c.skip_ws();
        while (c.peek() == ',') {
            ++c.i;
            c.skip_ws();
        }
        if (c.done()) break;
        if (c.peek() != '<') {
            // Malformed link-value: skip to the next top-level comma.
            while (!c.done() && c.peek() != ',') {
                if (c.peek() == '"') c.quoted();
                else ++c.i;
            }
            continue;
        }
        ++c.i;
        const std::size_t close = value.find('>', c.i);
        if (close == std::string_view::npos) break;
        std::string target(value.substr(c.i, close - c.i));
        c.i = close + 1;
        std::map<std::string, std::string> params;
        std::optional<std::string> rel_value;
        while (true) {
            c.skip_ws();
            if (c.peek() != ';') break;
            ++c.i;
            c.skip_ws();
            std::string name = lower(c.token());
            c.skip_ws();
            std::string param_value;
            if (c.peek() == '=') {
                ++c.i;
                c.skip_ws();
                if (c.peek() == '"') {
                    param_value = c.quoted();
                } else {
                    std::size_t start = c.i;
                    while (!c.done() && c.peek() != ';' && c.peek() != ',' && !is_space(c.peek())) ++c.i;
                    param_value = std::string(value.substr(start, c.i - start));
                }
            }
            if (name.empty()) continue;
            if (name == "rel") {
                if (!rel_value) rel_value = param_value;  // first occurrence wins (RFC 8288 §3.3)
            } else if (!params.contains(name)) {
                params.emplace(std::move(name), std::move(param_value));
            }
        }
        // Skip anything up to the next top-level comma.
        while (!c.done() && c.peek() != ',') {
            if (c.peek() == '"') c.quoted();
            else ++c.i;
        }
        if (!rel_value) continue;
        const std::string href = resolve_url(base, target);
        std::string_view rels = *rel_value;
        std::size_t pos = 0;
        while (pos < rels.size()) {
            while (pos < rels.size() && is_space(rels[pos])) ++pos;
            std::size_t end = pos;
            while (end < rels.size() && !is_space(rels[end])) ++end;
            if (end > pos) {
                std::string rel(rels.substr(pos, end - pos));
                if (rel.find(':') == std::string::npos) rel = lower(rel);
                links.push_back(Link{href, std::move(rel), params});
            }
            pos = end;
        }
    }
    return links;
}

std::vector<Link> parse_link_headers(const std::vector<std::string>& values, std::string_view base) {
    std::vector<Link> out;
    for (const auto& v : values) {
        auto links = parse_link_header(v, base);
        out.insert(out.end(), std::make_move_iterator(links.begin()), std::make_move_iterator(links.end()));
    }
    return out;
}

// ---------------------------------------------------------------------------------------------
// WWW-Authenticate
// ---------------------------------------------------------------------------------------------

bool AuthChallenge::is_scheme(std::string_view name) const noexcept { return iequals(scheme, name); }

std::optional<std::string> AuthChallenge::param(std::string_view name) const {
    if (auto it = params.find(lower(name)); it != params.end()) return it->second;
    return std::nullopt;
}

namespace {

bool is_token68_char(char c) noexcept {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '.' || c == '_' || c == '~' || c == '+' ||
           c == '/';
}

// Returns true (and the token68 value) if a token68 starts at the cursor position.
bool try_token68(Cursor& c, std::string& out) {
    std::size_t j = c.i;
    while (j < c.s.size() && is_token68_char(c.s[j])) ++j;
    if (j == c.i) return false;
    std::size_t k = j;
    while (k < c.s.size() && c.s[k] == '=') ++k;
    std::size_t after = k;
    while (after < c.s.size() && is_space(c.s[after])) ++after;
    const bool at_end = after >= c.s.size() || c.s[after] == ',';
    if (!at_end) return false;  // e.g. "realm=..." — an auth-param
    out = std::string(c.s.substr(c.i, k - c.i));
    c.i = k;
    return true;
}

// Looks ahead: is there an auth-param (token BWS '=' not followed by '=' or end) at the cursor?
bool at_auth_param(const Cursor& c) {
    std::size_t j = c.i;
    while (j < c.s.size() && is_tchar(c.s[j])) ++j;
    if (j == c.i) return false;
    while (j < c.s.size() && is_space(c.s[j])) ++j;
    if (j >= c.s.size() || c.s[j] != '=') return false;
    ++j;
    while (j < c.s.size() && is_space(c.s[j])) ++j;
    return j < c.s.size() && c.s[j] != '=' && c.s[j] != ',';
}

}  // namespace

std::vector<AuthChallenge> parse_www_authenticate(std::string_view value) {
    std::vector<AuthChallenge> out;
    Cursor c{value};
    while (true) {
        c.skip_ws();
        while (c.peek() == ',') {
            ++c.i;
            c.skip_ws();
        }
        if (c.done()) break;
        AuthChallenge ch;
        ch.scheme = c.token();
        if (ch.scheme.empty()) {
            ++c.i;  // skip junk
            continue;
        }
        // Require whitespace between scheme and its credentials.
        c.skip_ws();
        if (!c.done() && c.peek() != ',') {
            std::string t68;
            if (!at_auth_param(c) && try_token68(c, t68)) {
                ch.token68 = std::move(t68);
            } else {
                // auth-param list
                while (true) {
                    c.skip_ws();
                    if (!at_auth_param(c)) break;
                    std::string name = lower(c.token());
                    c.skip_ws();
                    ++c.i;  // '='
                    c.skip_ws();
                    std::string v;
                    if (c.peek() == '"') {
                        v = c.quoted();
                    } else {
                        v = c.token();
                    }
                    if (!ch.params.contains(name)) ch.params.emplace(std::move(name), std::move(v));
                    c.skip_ws();
                    if (c.peek() != ',') break;
                    // Lookahead past commas: another param of this challenge, or a new challenge?
                    std::size_t save = c.i;
                    while (c.peek() == ',' || is_space(c.peek())) ++c.i;
                    if (!at_auth_param(c)) {
                        c.i = save;
                        break;
                    }
                }
            }
        }
        out.push_back(std::move(ch));
        // Advance to the next top-level comma (or end).
        c.skip_ws();
        if (!c.done() && c.peek() != ',') {
            // Unexpected content; skip it safely.
            while (!c.done() && c.peek() != ',') {
                if (c.peek() == '"') c.quoted();
                else ++c.i;
            }
        }
    }
    return out;
}

std::vector<AuthChallenge> parse_www_authenticate(const std::vector<std::string>& values) {
    std::vector<AuthChallenge> out;
    for (const auto& v : values) {
        auto part = parse_www_authenticate(std::string_view(v));
        out.insert(out.end(), std::make_move_iterator(part.begin()), std::make_move_iterator(part.end()));
    }
    return out;
}

}  // namespace lws
