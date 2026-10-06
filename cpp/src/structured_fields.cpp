// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include "lws/structured_fields.hpp"

#include <cctype>
#include <cmath>
#include <cstdio>

#include "lws/encoding.hpp"
#include "lws/errors.hpp"

namespace lws::sf {
namespace {

bool is_lcalpha(char c) noexcept { return c >= 'a' && c <= 'z'; }
bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }
bool is_alpha(char c) noexcept { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
bool is_tchar(char c) noexcept {
    if (is_alpha(c) || is_digit(c)) return true;
    switch (c) {
        case '!': case '#': case '$': case '%': case '&': case '\'': case '*': case '+': case '-':
        case '.': case '^': case '_': case '`': case '|': case '~':
            return true;
        default:
            return false;
    }
}

[[noreturn]] void fail(const char* what) { throw ParseError(std::string("structured field: ") + what); }

class Parser {
public:
    explicit Parser(std::string_view s) : s_(s) {}

    Dictionary dictionary() {
        Dictionary dict;
        skip_sp();
        if (done()) return dict;
        while (true) {
            std::string key = parse_key();
            Member member;
            if (peek() == '=') {
                ++i_;
                member = item_or_inner_list();
            } else {
                member = Item{true, parameters()};
            }
            auto it = std::find_if(dict.begin(), dict.end(), [&](const auto& m) { return m.first == key; });
            if (it != dict.end())
                it->second = std::move(member);
            else
                dict.emplace_back(std::move(key), std::move(member));
            skip_ows();
            if (done()) return dict;
            if (peek() != ',') fail("expected ','");
            ++i_;
            skip_ows();
            if (done()) fail("trailing comma");
        }
    }

private:
    bool done() const noexcept { return i_ >= s_.size(); }
    char peek() const noexcept { return done() ? '\0' : s_[i_]; }
    void skip_sp() noexcept {
        while (!done() && s_[i_] == ' ') ++i_;
    }
    void skip_ows() noexcept {
        while (!done() && (s_[i_] == ' ' || s_[i_] == '\t')) ++i_;
    }

    std::string parse_key() {
        if (!(is_lcalpha(peek()) || peek() == '*')) fail("invalid key");
        std::size_t start = i_;
        while (!done() && (is_lcalpha(peek()) || is_digit(peek()) || peek() == '_' || peek() == '-' ||
                           peek() == '.' || peek() == '*'))
            ++i_;
        return std::string(s_.substr(start, i_ - start));
    }

    Member item_or_inner_list() {
        if (peek() == '(') return inner_list();
        return item();
    }

    InnerList inner_list() {
        ++i_;  // '('
        InnerList list;
        while (!done()) {
            skip_sp();
            if (peek() == ')') {
                ++i_;
                list.params = parameters();
                return list;
            }
            list.items.push_back(item());
            if (!(peek() == ' ' || peek() == ')')) fail("invalid inner list");
        }
        fail("unterminated inner list");
    }

    Item item() {
        Item it;
        it.value = bare_item();
        it.params = parameters();
        return it;
    }

    Parameters parameters() {
        Parameters params;
        while (peek() == ';') {
            ++i_;
            skip_sp();
            std::string key = parse_key();
            BareItem value = true;
            if (peek() == '=') {
                ++i_;
                value = bare_item();
            }
            auto it = std::find_if(params.begin(), params.end(), [&](const auto& p) { return p.first == key; });
            if (it != params.end())
                it->second = std::move(value);
            else
                params.emplace_back(std::move(key), std::move(value));
        }
        return params;
    }

    BareItem bare_item() {
        const char c = peek();
        if (c == '-' || is_digit(c)) return number();
        if (c == '"') return string();
        if (c == '*' || is_alpha(c)) return token();
        if (c == ':') return byte_sequence();
        if (c == '?') return boolean();
        if (c == '@') {
            ++i_;
            auto n = number();
            if (!std::holds_alternative<std::int64_t>(n)) fail("invalid date");
            return Date{std::get<std::int64_t>(n)};
        }
        if (c == '%') return display_string();
        fail("invalid bare item");
    }

    BareItem number() {
        bool negative = false;
        if (peek() == '-') {
            negative = true;
            ++i_;
        }
        if (!is_digit(peek())) fail("invalid number");
        std::size_t start = i_;
        bool decimal = false;
        std::size_t int_digits = 0;
        while (!done()) {
            const char c = peek();
            if (is_digit(c)) {
                ++i_;
            } else if (c == '.' && !decimal) {
                if (i_ - start > 12) fail("decimal integer part too long");
                int_digits = i_ - start;
                decimal = true;
                ++i_;
            } else {
                break;
            }
            if (!decimal && i_ - start > 15) fail("integer too long");
            if (decimal && i_ - start > 16) fail("decimal too long");
        }
        std::string text(s_.substr(start, i_ - start));
        if (!decimal) {
            std::int64_t v = std::stoll(text);
            return negative ? -v : v;
        }
        if (text.back() == '.') fail("decimal without fraction");
        if (text.size() - int_digits - 1 > 3) fail("decimal fraction too long");
        double v = std::stod(text);
        return negative ? -v : v;
    }

    std::string string() {
        ++i_;  // '"'
        std::string out;
        while (!done()) {
            const char c = s_[i_++];
            if (c == '\\') {
                if (done()) fail("unterminated escape");
                const char n = s_[i_++];
                if (n != '"' && n != '\\') fail("invalid escape");
                out += n;
            } else if (c == '"') {
                return out;
            } else if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7E) {
                fail("invalid string character");
            } else {
                out += c;
            }
        }
        fail("unterminated string");
    }

    Token token() {
        std::size_t start = i_;
        ++i_;
        while (!done() && (is_tchar(peek()) || peek() == ':' || peek() == '/')) ++i_;
        return Token{std::string(s_.substr(start, i_ - start))};
    }

    ByteSequence byte_sequence() {
        ++i_;  // ':'
        std::size_t end = s_.find(':', i_);
        if (end == std::string_view::npos) fail("unterminated byte sequence");
        std::string_view b64 = s_.substr(i_, end - i_);
        i_ = end + 1;
        try {
            return ByteSequence{base64_decode(b64)};
        } catch (const ParseError&) {
            fail("invalid byte sequence");
        }
    }

    bool boolean() {
        ++i_;  // '?'
        const char c = peek();
        if (c == '1') {
            ++i_;
            return true;
        }
        if (c == '0') {
            ++i_;
            return false;
        }
        fail("invalid boolean");
    }

    DisplayString display_string() {
        ++i_;  // '%'
        if (peek() != '"') fail("invalid display string");
        ++i_;
        std::string out;
        while (!done()) {
            const char c = s_[i_++];
            if (c == '%') {
                if (i_ + 2 > s_.size()) fail("invalid display string escape");
                out += static_cast<char>(std::stoi(std::string(s_.substr(i_, 2)), nullptr, 16));
                i_ += 2;
            } else if (c == '"') {
                return DisplayString{out};
            } else {
                out += c;
            }
        }
        fail("unterminated display string");
    }

    std::string_view s_;
    std::size_t i_ = 0;
};

}  // namespace

Dictionary parse_dictionary(std::string_view input) {
    // Trim leading/trailing whitespace of the whole field value.
    while (!input.empty() && (input.front() == ' ' || input.front() == '\t')) input.remove_prefix(1);
    while (!input.empty() && (input.back() == ' ' || input.back() == '\t')) input.remove_suffix(1);
    return Parser(input).dictionary();
}

const Member* find(const Dictionary& dictionary, std::string_view key) noexcept {
    for (const auto& [k, v] : dictionary)
        if (k == key) return &v;
    return nullptr;
}

const BareItem* find(const Parameters& params, std::string_view key) noexcept {
    for (const auto& [k, v] : params)
        if (k == key) return &v;
    return nullptr;
}

std::string serialize(const BareItem& item) {
    struct Visitor {
        std::string operator()(std::int64_t v) const { return std::to_string(v); }
        std::string operator()(double v) const {
            char buf[64];
            const double rounded = std::round(v * 1000.0) / 1000.0;
            std::snprintf(buf, sizeof buf, "%.3f", rounded);
            std::string s = buf;
            while (s.size() > 1 && s.back() == '0' && s[s.size() - 2] != '.') s.pop_back();
            return s;
        }
        std::string operator()(const std::string& v) const {
            std::string out = "\"";
            for (char c : v) {
                if (c == '"' || c == '\\') out += '\\';
                out += c;
            }
            return out + "\"";
        }
        std::string operator()(const Token& v) const { return v.value; }
        std::string operator()(const ByteSequence& v) const { return ":" + base64_encode(v.bytes) + ":"; }
        std::string operator()(bool v) const { return v ? "?1" : "?0"; }
        std::string operator()(const Date& v) const { return "@" + std::to_string(v.seconds); }
        std::string operator()(const DisplayString& v) const {
            static constexpr char hex[] = "0123456789abcdef";
            std::string out = "%\"";
            for (unsigned char c : v.value) {
                if (c == '%' || c == '"' || c < 0x20 || c > 0x7E) {
                    out += '%';
                    out += hex[c >> 4];
                    out += hex[c & 15];
                } else {
                    out += static_cast<char>(c);
                }
            }
            return out + "\"";
        }
    };
    return std::visit(Visitor{}, item);
}

std::string serialize(const Parameters& params) {
    std::string out;
    for (const auto& [key, value] : params) {
        out += ";" + key;
        if (const bool* b = std::get_if<bool>(&value); b && *b) continue;
        out += "=" + serialize(value);
    }
    return out;
}

std::string serialize(const Item& item) { return serialize(item.value) + serialize(item.params); }

std::string serialize(const InnerList& list) {
    std::string out = "(";
    for (std::size_t i = 0; i < list.items.size(); ++i) {
        if (i) out += ' ';
        out += serialize(list.items[i]);
    }
    return out + ")" + serialize(list.params);
}

std::string serialize(const Member& member) {
    return std::visit([](const auto& m) { return serialize(m); }, member);
}

}  // namespace lws::sf
