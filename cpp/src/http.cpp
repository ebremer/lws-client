// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include "lws/http.hpp"

#include <algorithm>
#include <cctype>

#include "lws/errors.hpp"

namespace lws {

bool iequals(std::string_view a, std::string_view b) noexcept {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](unsigned char x, unsigned char y) {
               return std::tolower(x) == std::tolower(y);
           });
}

HttpHeaders::HttpHeaders(std::initializer_list<value_type> init) : fields_(init) {}

HttpHeaders& HttpHeaders::add(std::string name, std::string value) {
    fields_.emplace_back(std::move(name), std::move(value));
    return *this;
}

HttpHeaders& HttpHeaders::set(std::string name, std::string value) {
    remove(name);
    return add(std::move(name), std::move(value));
}

HttpHeaders& HttpHeaders::remove(std::string_view name) {
    std::erase_if(fields_, [&](const value_type& f) { return iequals(f.first, name); });
    return *this;
}

bool HttpHeaders::contains(std::string_view name) const noexcept {
    return std::any_of(fields_.begin(), fields_.end(), [&](const value_type& f) { return iequals(f.first, name); });
}

std::optional<std::string> HttpHeaders::get(std::string_view name) const {
    for (const auto& f : fields_)
        if (iequals(f.first, name)) return f.second;
    return std::nullopt;
}

std::vector<std::string> HttpHeaders::get_all(std::string_view name) const {
    std::vector<std::string> out;
    for (const auto& f : fields_)
        if (iequals(f.first, name)) out.push_back(f.second);
    return out;
}

std::optional<std::string> HttpHeaders::get_combined(std::string_view name) const {
    std::optional<std::string> out;
    for (const auto& f : fields_) {
        if (!iequals(f.first, name)) continue;
        if (out)
            *out += ", " + f.second;
        else
            out = f.second;
    }
    return out;
}

std::vector<std::string> HttpHeaders::get_list(std::string_view name) const {
    std::vector<std::string> out;
    for (const auto& value : get_all(name)) {
        std::size_t start = 0;
        while (start <= value.size()) {
            std::size_t comma = value.find(',', start);
            if (comma == std::string::npos) comma = value.size();
            std::string item = value.substr(start, comma - start);
            const auto b = item.find_first_not_of(" \t");
            const auto e = item.find_last_not_of(" \t");
            if (b != std::string::npos) out.push_back(item.substr(b, e - b + 1));
            start = comma + 1;
        }
    }
    return out;
}

#if !LWS_WITH_CURL
std::shared_ptr<HttpTransport> make_default_transport() {
    throw Error("lws-client was built without LWS_WITH_CURL; pass an HttpTransport in ClientOptions");
}
#endif

}  // namespace lws
