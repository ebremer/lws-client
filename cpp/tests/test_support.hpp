// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Test helpers: fixture loading and an in-process mock HTTP transport.
#pragma once

#include <fstream>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "lws/lws.hpp"

namespace lws::test {

inline std::string fixture_path(const std::string& relative) { return std::string(LWS_FIXTURES_DIR) + "/" + relative; }

inline std::string read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open fixture " + path);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

inline nlohmann::json fixture(const std::string& relative) {
    return nlohmann::json::parse(read_file(fixture_path(relative)));
}

/// Builds an HttpResponse from a fixture object with "url", "status", "headers" (string or
/// array values) and "body" (JSON value, or string used verbatim).
inline HttpResponse response_from_fixture(const nlohmann::json& f) {
    HttpResponse r;
    r.url = f.value("url", "");
    r.status = f.value("status", 200);
    if (f.contains("headers")) {
        for (auto it = f["headers"].begin(); it != f["headers"].end(); ++it) {
            if (it.value().is_array())
                for (const auto& v : it.value()) r.headers.add(it.key(), v.get<std::string>());
            else
                r.headers.add(it.key(), it.value().get<std::string>());
        }
    }
    if (f.contains("body")) r.body = f["body"].is_string() ? f["body"].get<std::string>() : f["body"].dump();
    return r;
}

inline HttpResponse make_response(int status, HttpHeaders headers = {}, std::string body = {}) {
    HttpResponse r;
    r.status = status;
    r.headers = std::move(headers);
    r.body = std::move(body);
    return r;
}

inline HttpResponse json_response(int status, const nlohmann::json& body, std::string content_type = "application/lws+json",
                                  HttpHeaders headers = {}) {
    headers.set("Content-Type", std::move(content_type));
    return make_response(status, std::move(headers), body.dump());
}

/// A transport that records requests and answers them with a handler.
class MockTransport final : public HttpTransport {
public:
    using Handler = std::function<HttpResponse(const HttpRequest&)>;
    explicit MockTransport(Handler handler) : handler_(std::move(handler)) {}

    HttpResponse send(const HttpRequest& request) override {
        HttpResponse response;
        {
            std::lock_guard lock(mutex_);
            requests_.push_back(request);
        }
        response = handler_(request);
        if (response.url.empty()) response.url = request.url;
        return response;
    }

    std::vector<HttpRequest> requests() const {
        std::lock_guard lock(mutex_);
        return requests_;
    }
    std::size_t count(std::string_view method, std::string_view url_prefix = {}) const {
        std::lock_guard lock(mutex_);
        std::size_t n = 0;
        for (const auto& r : requests_)
            if (r.method == method && r.url.starts_with(url_prefix)) ++n;
        return n;
    }
    void clear() {
        std::lock_guard lock(mutex_);
        requests_.clear();
    }

private:
    Handler handler_;
    mutable std::mutex mutex_;
    std::vector<HttpRequest> requests_;
};

/// A client wired to a MockTransport.
inline std::pair<Client, std::shared_ptr<MockTransport>> mock_client(MockTransport::Handler handler,
                                                                     std::shared_ptr<Authenticator> auth = nullptr) {
    auto transport = std::make_shared<MockTransport>(std::move(handler));
    ClientOptions options;
    options.transport = transport;
    options.authenticator = std::move(auth);
    return {Client(options), transport};
}

}  // namespace lws::test
