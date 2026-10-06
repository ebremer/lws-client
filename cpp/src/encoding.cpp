// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include "lws/encoding.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <ctime>

#include "lws/errors.hpp"

namespace lws {
namespace {

constexpr char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr char kB64Url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
constexpr char kB58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string encode64(std::string_view in, const char* alphabet, bool pad) {
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    std::size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        const std::uint32_t n = (std::uint32_t(std::uint8_t(in[i])) << 16) | (std::uint32_t(std::uint8_t(in[i + 1])) << 8) |
                                std::uint8_t(in[i + 2]);
        out += alphabet[(n >> 18) & 63];
        out += alphabet[(n >> 12) & 63];
        out += alphabet[(n >> 6) & 63];
        out += alphabet[n & 63];
    }
    const std::size_t rest = in.size() - i;
    if (rest == 1) {
        const std::uint32_t n = std::uint32_t(std::uint8_t(in[i])) << 16;
        out += alphabet[(n >> 18) & 63];
        out += alphabet[(n >> 12) & 63];
        if (pad) out += "==";
    } else if (rest == 2) {
        const std::uint32_t n = (std::uint32_t(std::uint8_t(in[i])) << 16) | (std::uint32_t(std::uint8_t(in[i + 1])) << 8);
        out += alphabet[(n >> 18) & 63];
        out += alphabet[(n >> 12) & 63];
        out += alphabet[(n >> 6) & 63];
        if (pad) out += '=';
    }
    return out;
}

int decode_char(char c, bool url) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (!url && c == '+') return 62;
    if (!url && c == '/') return 63;
    if (url && c == '-') return 62;
    if (url && c == '_') return 63;
    return -1;
}

std::string decode64(std::string_view in, bool url) {
    while (!in.empty() && in.back() == '=') in.remove_suffix(1);
    if (in.size() % 4 == 1) throw ParseError("invalid base64 length");
    std::string out;
    out.reserve(in.size() * 3 / 4);
    std::uint32_t buffer = 0;
    int bits = 0;
    for (char c : in) {
        const int v = decode_char(c, url);
        if (v < 0) throw ParseError("invalid base64 character");
        buffer = (buffer << 6) | std::uint32_t(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += static_cast<char>((buffer >> bits) & 0xFF);
        }
    }
    return out;
}

bool is_unreserved(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
           c == '_' || c == '~';
}

void append_pct(std::string& out, unsigned char c) {
    static constexpr char hex[] = "0123456789ABCDEF";
    out += '%';
    out += hex[c >> 4];
    out += hex[c & 15];
}

// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
std::int64_t days_from_civil(std::int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

}  // namespace

std::string base64_encode(std::string_view bytes) { return encode64(bytes, kB64, true); }
std::string base64_decode(std::string_view text) { return decode64(text, false); }
std::string base64url_encode(std::string_view bytes) { return encode64(bytes, kB64Url, false); }
std::string base64url_decode(std::string_view text) { return decode64(text, true); }

std::string base58btc_encode(std::string_view bytes) {
    std::size_t zeros = 0;
    while (zeros < bytes.size() && bytes[zeros] == 0) ++zeros;
    // Base conversion 256 → 58 on a little-endian digit buffer.
    std::vector<std::uint8_t> digits;
    digits.reserve(bytes.size() * 138 / 100 + 1);
    for (std::size_t i = zeros; i < bytes.size(); ++i) {
        std::uint32_t carry = std::uint8_t(bytes[i]);
        for (auto& d : digits) {
            carry += std::uint32_t(d) << 8;
            d = static_cast<std::uint8_t>(carry % 58);
            carry /= 58;
        }
        while (carry) {
            digits.push_back(static_cast<std::uint8_t>(carry % 58));
            carry /= 58;
        }
    }
    std::string out(zeros, '1');
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) out += kB58[*it];
    return out;
}

std::string base58btc_decode(std::string_view text) {
    std::size_t zeros = 0;
    while (zeros < text.size() && text[zeros] == '1') ++zeros;
    std::vector<std::uint8_t> bytes;  // little-endian
    for (std::size_t i = zeros; i < text.size(); ++i) {
        const char* p = nullptr;
        for (const char* q = kB58; *q; ++q)
            if (*q == text[i]) p = q;
        if (!p) throw ParseError("invalid base58 character");
        std::uint32_t carry = static_cast<std::uint32_t>(p - kB58);
        for (auto& b : bytes) {
            carry += std::uint32_t(b) * 58;
            b = static_cast<std::uint8_t>(carry & 0xFF);
            carry >>= 8;
        }
        while (carry) {
            bytes.push_back(static_cast<std::uint8_t>(carry & 0xFF));
            carry >>= 8;
        }
    }
    std::string out(zeros, '\0');
    for (auto it = bytes.rbegin(); it != bytes.rend(); ++it) out += static_cast<char>(*it);
    return out;
}

std::string form_url_encode(std::string_view text) {
    std::string out;
    out.reserve(text.size() * 3 / 2);
    for (unsigned char c : text) {
        if (is_unreserved(c))
            out += static_cast<char>(c);
        else if (c == ' ')
            out += '+';
        else
            append_pct(out, c);
    }
    return out;
}

std::string slug_encode(std::string_view text) {
    std::string out;
    for (unsigned char c : text) {
        if (c < 0x20 || c > 0x7E || c == '%')
            append_pct(out, c);
        else
            out += static_cast<char>(c);
    }
    return out;
}

std::optional<std::chrono::system_clock::time_point> parse_rfc3339(std::string_view s) noexcept {
    auto digits = [&](std::size_t pos, std::size_t n, int& value) {
        if (pos + n > s.size()) return false;
        value = 0;
        for (std::size_t i = pos; i < pos + n; ++i) {
            if (s[i] < '0' || s[i] > '9') return false;
            value = value * 10 + (s[i] - '0');
        }
        return true;
    };
    int year, month, day, hour, minute, second;
    if (!digits(0, 4, year) || s.size() < 19 || s[4] != '-' || !digits(5, 2, month) || s[7] != '-' ||
        !digits(8, 2, day))
        return std::nullopt;
    if (s[10] != 'T' && s[10] != 't' && s[10] != ' ') return std::nullopt;
    if (!digits(11, 2, hour) || s[13] != ':' || !digits(14, 2, minute) || s[16] != ':' || !digits(17, 2, second))
        return std::nullopt;
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60)
        return std::nullopt;
    std::size_t pos = 19;
    std::int64_t nanos = 0;
    if (pos < s.size() && s[pos] == '.') {
        ++pos;
        std::size_t start = pos;
        std::int64_t scale = 100000000;
        while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') {
            nanos += (s[pos] - '0') * scale;
            scale /= 10;
            ++pos;
        }
        if (pos == start) return std::nullopt;
    }
    std::int64_t offset_seconds = 0;
    if (pos >= s.size()) return std::nullopt;
    if (s[pos] == 'Z' || s[pos] == 'z') {
        ++pos;
    } else if (s[pos] == '+' || s[pos] == '-') {
        int oh, om;
        if (!digits(pos + 1, 2, oh) || pos + 3 >= s.size() || s[pos + 3] != ':' || !digits(pos + 4, 2, om))
            return std::nullopt;
        offset_seconds = (oh * 3600 + om * 60) * (s[pos] == '-' ? -1 : 1);
        pos += 6;
    } else {
        return std::nullopt;
    }
    if (pos != s.size()) return std::nullopt;
    const std::int64_t days = days_from_civil(year, unsigned(month), unsigned(day));
    const std::int64_t secs = days * 86400 + hour * 3600 + minute * 60 + std::min(second, 59) - offset_seconds;
    return std::chrono::system_clock::time_point(std::chrono::duration_cast<std::chrono::system_clock::duration>(
        std::chrono::seconds(secs) + std::chrono::nanoseconds(nanos)));
}

std::string format_rfc3339(std::chrono::system_clock::time_point time) {
    using namespace std::chrono;
    const auto secs = floor<seconds>(time);
    const auto days = floor<std::chrono::days>(secs);
    const year_month_day ymd{days};
    const hh_mm_ss hms{secs - days};
    char buf[32];
    std::snprintf(buf, sizeof buf, "%04d-%02u-%02uT%02d:%02d:%02dZ", int(ymd.year()), unsigned(ymd.month()),
                  unsigned(ymd.day()), int(hms.hours().count()), int(hms.minutes().count()),
                  int(hms.seconds().count()));
    return buf;
}

}  // namespace lws
