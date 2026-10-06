// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors

#include "lws/errors.hpp"

#include <algorithm>

namespace lws {

std::optional<ProblemDetails> ProblemDetails::from_response(const HttpResponse& response) {
    const auto content_type = response.headers.get("content-type").value_or("");
    std::string media = content_type.substr(0, content_type.find(';'));
    std::transform(media.begin(), media.end(), media.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    if (!(media.ends_with("+json") || media.ends_with("/json")) || response.body.empty()) return std::nullopt;
    auto json = nlohmann::json::parse(response.body, nullptr, false);
    if (json.is_discarded() || !json.is_object()) return std::nullopt;
    ProblemDetails p;
    bool any = false;
    auto str = [&](const char* key, std::optional<std::string>& field) {
        if (auto it = json.find(key); it != json.end() && it->is_string()) {
            field = it->get<std::string>();
            any = true;
        }
    };
    str("type", p.type);
    str("title", p.title);
    str("detail", p.detail);
    str("instance", p.instance);
    if (auto it = json.find("status"); it != json.end() && it->is_number_integer()) {
        p.status = it->get<int>();
        any = true;
    }
    if (!any) return std::nullopt;
    for (auto it = json.begin(); it != json.end(); ++it) {
        const auto& k = it.key();
        if (k != "type" && k != "title" && k != "status" && k != "detail" && k != "instance")
            p.extensions[k] = it.value();
    }
    p.raw = std::move(json);
    return p;
}

HttpError::HttpError(std::string message, int status, std::string method, std::string url, HttpHeaders headers,
                     std::optional<ProblemDetails> problem, std::string body)
    : Error(message),
      status_(status),
      method_(std::move(method)),
      url_(std::move(url)),
      headers_(std::move(headers)),
      problem_(std::move(problem)),
      body_(std::move(body)) {}

std::vector<AuthChallenge> UnauthorizedError::challenges() const {
    return parse_www_authenticate(headers().get_all("www-authenticate"));
}

std::vector<std::string> MethodNotAllowedError::allow() const { return headers().get_list("allow"); }

std::vector<std::string> UnsupportedMediaTypeError::accept_patch() const {
    return headers().get_list("accept-patch");
}

std::vector<std::string> UnsupportedMediaTypeError::accept_query() const {
    return headers().get_list("accept-query");
}

void throw_http_error(const HttpRequest& request, const HttpResponse& response) {
    auto problem = ProblemDetails::from_response(response);
    std::string body = response.body.substr(0, 2048);
    std::string message = request.method + " " + request.url + " failed with HTTP " + std::to_string(response.status);
    if (problem && (problem->title || problem->detail))
        message += ": " + problem->title.value_or("") + (problem->title && problem->detail ? " — " : "") +
                   problem->detail.value_or("");
    auto make = [&]<typename E>() {
        return E(message, response.status, request.method, response.url.empty() ? request.url : response.url,
                 response.headers, problem, body);
    };
    switch (response.status) {
        case 400: throw make.template operator()<BadRequestError>();
        case 401: throw make.template operator()<UnauthorizedError>();
        case 403: throw make.template operator()<ForbiddenError>();
        case 404: throw make.template operator()<NotFoundError>();
        case 405: throw make.template operator()<MethodNotAllowedError>();
        case 406: throw make.template operator()<NotAcceptableError>();
        case 409: throw make.template operator()<ConflictError>();
        case 410: throw make.template operator()<GoneError>();
        case 412: throw make.template operator()<PreconditionFailedError>();
        case 415: throw make.template operator()<UnsupportedMediaTypeError>();
        case 422: throw make.template operator()<UnprocessableContentError>();
        case 501: throw make.template operator()<NotImplementedError>();
        case 507: throw make.template operator()<InsufficientStorageError>();
        default: throw make.template operator()<HttpError>();
    }
}

void raise_for_status(const HttpRequest& request, const HttpResponse& response, bool allow_not_modified) {
    if (response.ok()) return;
    if (allow_not_modified && response.status == 304) return;
    throw_http_error(request, response);
}

}  // namespace lws
