// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include <curl/curl.h>

#include <mutex>
#include <vector>

#include "lws/errors.hpp"
#include "lws/http.hpp"

namespace lws {
namespace {

void global_init() {
    static std::once_flag once;
    std::call_once(once, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

size_t write_body(char* data, size_t size, size_t count, void* user) {
    static_cast<std::string*>(user)->append(data, size * count);
    return size * count;
}

size_t write_header(char* data, size_t size, size_t count, void* user) {
    auto* response = static_cast<HttpResponse*>(user);
    std::string_view line(data, size * count);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.remove_suffix(1);
    if (line.starts_with("HTTP/")) {
        // A new status line (e.g. after 100 Continue): reset collected headers.
        response->headers = HttpHeaders{};
        return size * count;
    }
    const auto colon = line.find(':');
    if (colon == std::string_view::npos) return size * count;
    std::string_view name = line.substr(0, colon);
    std::string_view value = line.substr(colon + 1);
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
    response->headers.add(std::string(name), std::string(value));
    return size * count;
}

struct SlistDeleter {
    void operator()(curl_slist* list) const noexcept { curl_slist_free_all(list); }
};

}  // namespace

struct CurlTransport::Impl {
    CurlTransportOptions options;
    std::mutex mutex;
    std::vector<CURL*> pool;  // idle easy handles (keep their connection caches warm)

    CURL* acquire() {
        {
            std::lock_guard lock(mutex);
            if (!pool.empty()) {
                CURL* h = pool.back();
                pool.pop_back();
                curl_easy_reset(h);
                return h;
            }
        }
        CURL* h = curl_easy_init();
        if (!h) throw TransportError("curl_easy_init failed");
        return h;
    }
    void release(CURL* h) {
        std::lock_guard lock(mutex);
        if (pool.size() < 16)
            pool.push_back(h);
        else
            curl_easy_cleanup(h);
    }
    ~Impl() {
        for (CURL* h : pool) curl_easy_cleanup(h);
    }
};

CurlTransport::CurlTransport(CurlTransportOptions options) : impl_(std::make_unique<Impl>()) {
    global_init();
    impl_->options = std::move(options);
}

CurlTransport::~CurlTransport() = default;

HttpResponse CurlTransport::send(const HttpRequest& request) {
    CURL* h = impl_->acquire();
    struct Guard {
        Impl* impl;
        CURL* h;
        ~Guard() { impl->release(h); }
    } guard{impl_.get(), h};

    HttpResponse response;
    const auto& o = impl_->options;
    curl_easy_setopt(h, CURLOPT_URL, request.url.c_str());
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(o.connect_timeout.count()));
    const auto timeout = request.timeout.count() > 0 ? request.timeout : o.default_timeout;
    curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout.count()));
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, o.verify_tls ? 1L : 0L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, o.verify_tls ? 2L : 0L);
    if (o.ca_bundle) curl_easy_setopt(h, CURLOPT_CAINFO, o.ca_bundle->c_str());
    if (o.accept_compression && !request.headers.contains("accept-encoding"))
        curl_easy_setopt(h, CURLOPT_ACCEPT_ENCODING, "");

    const bool has_body = !request.body.empty();
    const bool body_method = request.method == "POST" || request.method == "PUT" || request.method == "PATCH" ||
                             request.method == "QUERY";
    if (request.method == "HEAD") {
        curl_easy_setopt(h, CURLOPT_NOBODY, 1L);
    } else if (request.method == "GET" && !has_body) {
        curl_easy_setopt(h, CURLOPT_HTTPGET, 1L);
    } else {
        if (has_body || body_method) {
            curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(request.body.size()));
            curl_easy_setopt(h, CURLOPT_POSTFIELDS, request.body.data());
        }
        curl_easy_setopt(h, CURLOPT_CUSTOMREQUEST, request.method.c_str());
    }

    curl_slist* raw_headers = nullptr;
    for (const auto& [name, value] : request.headers) {
        const std::string line = value.empty() ? name + ";" : name + ": " + value;
        raw_headers = curl_slist_append(raw_headers, line.c_str());
    }
    raw_headers = curl_slist_append(raw_headers, "Expect:");
    if ((has_body || body_method) && !request.headers.contains("content-type"))
        raw_headers = curl_slist_append(raw_headers, "Content-Type:");
    std::unique_ptr<curl_slist, SlistDeleter> header_list(raw_headers);
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, header_list.get());

    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_body);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, write_header);
    curl_easy_setopt(h, CURLOPT_HEADERDATA, &response);

    const CURLcode rc = curl_easy_perform(h);
    if (rc != CURLE_OK)
        throw TransportError(request.method + " " + request.url + ": " + curl_easy_strerror(rc));
    long status = 0;
    curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &status);
    response.status = static_cast<int>(status);
    char* effective = nullptr;
    curl_easy_getinfo(h, CURLINFO_EFFECTIVE_URL, &effective);
    response.url = effective ? effective : request.url;
    return response;
}

std::shared_ptr<HttpTransport> make_default_transport() { return std::make_shared<CurlTransport>(); }

}  // namespace lws
