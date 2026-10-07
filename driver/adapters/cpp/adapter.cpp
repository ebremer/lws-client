// SPDX-License-Identifier: MIT
// The C++ adapter of the lws-client driver: runs the operations of driver/PROTOCOL.md with the
// lws-client of ../../../cpp. Build it with the CMakeLists.txt next to this file.
//
// stdout carries protocol messages only (one JSON object per line); logs go to stderr.

#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <typeinfo>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "lws/lws.hpp"

namespace {

using json = nlohmann::json;           // the library's JSON type
using ojson = nlohmann::ordered_json;  // protocol messages, which keep their member order

constexpr std::string_view kLibrary = "lws-client-cpp/" LWS_CLIENT_VERSION;

/// An error the adapter raises itself (bad arguments, an unavailable option).
class AdapterError : public std::runtime_error {
public:
    AdapterError(std::string kind, const std::string& message) : std::runtime_error(message), kind_(std::move(kind)) {}
    const std::string& kind() const noexcept { return kind_; }

private:
    std::string kind_;
};

AdapterError invalid(const std::string& message) { return AdapterError("InvalidArguments", message); }
[[maybe_unused]] AdapterError unsupported(const std::string& message) { return AdapterError("Unsupported", message); }

json to_library(const ojson& value) { return json(value); }
ojson from_library(const json& value) { return ojson(value); }

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n')) s.remove_suffix(1);
    return s;
}

// ---------------------------------------------------------------------------------------------
// Arguments

/// The member `name` of `args`, or nullptr when it is absent or null.
const ojson* member(const ojson& args, const char* name) {
    const auto it = args.find(name);
    if (it == args.end() || it->is_null()) return nullptr;
    return &*it;
}

std::string quoted(const char* name) { return std::string("'") + name + "'"; }

const ojson& required(const ojson& args, const char* name) {
    const ojson* value = member(args, name);
    if (!value) throw invalid("missing argument " + quoted(name));
    return *value;
}

std::string required_string(const ojson& args, const char* name) {
    const ojson& value = required(args, name);
    if (!value.is_string()) throw invalid("argument " + quoted(name) + " must be a string");
    return value.get<std::string>();
}

/// A URL argument where a request target is expected (url, container, parent, linksetUrl,
/// serviceUrl): it must be absolute.
std::string required_target(const ojson& args, const char* name) {
    std::string url = required_string(args, name);
    if (!lws::is_absolute_iri(url)) throw invalid("argument " + quoted(name) + " must be an absolute URL, not '" + url + "'");
    return url;
}

std::optional<std::string> optional_string(const ojson& args, const char* name) {
    const ojson* value = member(args, name);
    if (!value) return std::nullopt;
    if (!value->is_string()) throw invalid("argument " + quoted(name) + " must be a string");
    return value->get<std::string>();
}

std::optional<bool> optional_bool(const ojson& args, const char* name) {
    const ojson* value = member(args, name);
    if (!value) return std::nullopt;
    if (!value->is_boolean()) throw invalid("argument " + quoted(name) + " must be a boolean");
    return value->get<bool>();
}

const ojson& required_object(const ojson& args, const char* name) {
    const ojson& value = required(args, name);
    if (!value.is_object()) throw invalid("argument " + quoted(name) + " must be an object");
    return value;
}

const ojson* optional_object(const ojson& args, const char* name) {
    const ojson* value = member(args, name);
    if (value && !value->is_object()) throw invalid("argument " + quoted(name) + " must be an object");
    return value;
}

const ojson& required_array(const ojson& args, const char* name) {
    const ojson& value = required(args, name);
    if (!value.is_array()) throw invalid("argument " + quoted(name) + " must be an array");
    return value;
}

const ojson* optional_array(const ojson& args, const char* name) {
    const ojson* value = member(args, name);
    if (value && !value->is_array()) throw invalid("argument " + quoted(name) + " must be an array");
    return value;
}

/// A non-negative integer argument (a JSON integer, or a float with an integral value).
std::optional<std::uint64_t> optional_count(const ojson& args, const char* name) {
    const ojson* value = member(args, name);
    if (!value) return std::nullopt;
    if (value->is_number_unsigned()) return value->get<std::uint64_t>();
    if (value->is_number_integer()) {
        if (const auto i = value->get<std::int64_t>(); i >= 0) return static_cast<std::uint64_t>(i);
    } else if (value->is_number_float()) {
        const double d = value->get<double>();
        if (std::isfinite(d) && d >= 0 && std::floor(d) == d && d <= 9007199254740992.0) return static_cast<std::uint64_t>(d);
    }
    throw invalid("argument " + quoted(name) + " must be a non-negative integer");
}

std::vector<std::string> strings_of(const ojson& array, const char* name) {
    std::vector<std::string> out;
    for (const auto& v : array) {
        if (!v.is_string()) throw invalid("argument " + quoted(name) + " must be a list of strings");
        out.push_back(v.get<std::string>());
    }
    return out;
}

std::string base64_argument(const std::string& text, const char* name) {
    try {
        return lws::base64_decode(text);
    } catch (const lws::Error&) {
        throw invalid("argument " + quoted(name) + " is not valid base64");
    }
}

std::uint64_t limit_of(const ojson& args) { return optional_count(args, "limit").value_or(1000); }

/// A `body` argument as bytes, with the content type it implies.
struct Body {
    std::string bytes;
    std::string content_type;
};

Body body_of(const ojson* body, const std::optional<std::string>& content_type) {
    if (!body) return {std::string(), content_type.value_or("application/octet-stream")};
    if (!body->is_object()) throw invalid("argument 'body' must be an object");
    if (const auto it = body->find("text"); it != body->end() && it->is_string())
        return {it->get<std::string>(), content_type.value_or("text/plain")};
    if (const auto it = body->find("base64"); it != body->end() && it->is_string())
        return {base64_argument(it->get<std::string>(), "body.base64"), content_type.value_or("application/octet-stream")};
    if (const auto it = body->find("json"); it != body->end()) return {it->dump(), content_type.value_or("application/json")};
    throw invalid("argument 'body' must have text, base64 or json");
}

lws::JsonPatch patch_of(const ojson* operations) {
    if (!operations || !operations->is_array()) throw invalid("argument 'patch' must be an array of operations");
    lws::JsonPatch patch;
    for (const auto& op : *operations) {
        const auto name_it = op.is_object() ? op.find("op") : op.end();
        if (!op.is_object() || name_it == op.end() || !name_it->is_string())
            throw invalid("a patch operation must be an object with an op");
        const std::string name = name_it->get<std::string>();
        const auto pointer = [&](const char* key) {
            const auto it = op.find(key);
            if (it == op.end() || !it->is_string())
                throw invalid("patch operation '" + name + "' needs a string " + quoted(key));
            return it->get<std::string>();
        };
        // "value" may be null, which is a value; only its absence is malformed.
        const auto value = [&]() {
            const auto it = op.find("value");
            if (it == op.end()) throw invalid("patch operation '" + name + "' needs a 'value'");
            return to_library(*it);
        };
        if (name == "add") patch.add(pointer("path"), value());
        else if (name == "remove") patch.remove(pointer("path"));
        else if (name == "replace") patch.replace(pointer("path"), value());
        else if (name == "move") patch.move(pointer("from"), pointer("path"));
        else if (name == "copy") patch.copy(pointer("from"), pointer("path"));
        else if (name == "test") patch.test(pointer("path"), value());
        else throw invalid("unknown patch operation '" + name + "'");
    }
    return patch;
}

lws::TypeQuery query_of(const ojson* query) {
    if (!query || !query->is_object()) throw invalid("argument 'query' must be an object");
    lws::TypeQuery q;
    for (auto it = query->begin(); it != query->end(); ++it) {
        const std::string& key = it.key();
        if (!it->is_array()) throw invalid("query member '" + key + "' must be a list of groups");
        for (const auto& group : *it) {
            if (group.is_string()) {
                const std::vector<std::string> iris{group.get<std::string>()};
                if (key == "type") q.all_of(iris);
                else q.relation_all_of(key, iris);
            } else if (group.is_array()) {
                std::vector<std::string> iris;
                for (const auto& iri : group) {
                    if (!iri.is_string()) throw invalid("a group of query member '" + key + "' must be an IRI or a list of IRIs");
                    iris.push_back(iri.get<std::string>());
                }
                if (key == "type") q.any_of(iris);
                else q.relation_any_of(key, iris);
            } else {
                throw invalid("a group of query member '" + key + "' must be an IRI or a list of IRIs");
            }
        }
    }
    return q;
}

// ---------------------------------------------------------------------------------------------
// Results

template <typename T>
void put(ojson& target, const char* key, const std::optional<T>& value) {
    if (value) target[key] = *value;
}

/// text/*, application/json, application/xml, or any type with a +json or +xml suffix.
bool is_textual(std::string_view content_type) {
    std::string media(trim(content_type.substr(0, content_type.find(';'))));
    for (char& c : media) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return media.starts_with("text/") || media == "application/json" || media == "application/xml" ||
           media.ends_with("+json") || media.ends_with("+xml");
}

ojson body_result(const std::string& bytes, const std::optional<std::string>& content_type) {
    ojson body = ojson::object();
    // The library keeps the body as bytes and decodes no charset: text is UTF-8, and invalid
    // sequences are replaced by U+FFFD when the line is written.
    if (content_type && is_textual(*content_type))
        body["text"] = bytes;
    else
        body["base64"] = lws::base64_encode(bytes);
    return body;
}

ojson metadata_result(const lws::ResourceMetadata& m) {
    ojson r = ojson::object();
    r["url"] = m.url;
    r["status"] = m.status;
    put(r, "etag", m.etag);
    put(r, "lastModified", m.last_modified);
    put(r, "contentType", m.content_type);
    put(r, "contentLength", m.content_length);
    ojson links = ojson::array();
    for (const auto& l : m.links) {
        ojson link = ojson::object();
        link["href"] = l.href;
        link["rel"] = l.rel;
        ojson params = ojson::object();
        for (const auto& [name, value] : l.params) params[name] = value;
        link["params"] = std::move(params);
        links.push_back(std::move(link));
    }
    r["links"] = std::move(links);
    put(r, "linkset", m.linkset);
    put(r, "parent", m.parent);
    put(r, "storage", m.storage);
    r["types"] = m.types;
    r["allow"] = m.allow;
    r["acceptPatch"] = m.accept_patch;
    return r;
}

ojson item_result(const lws::ContainedResource& i) {
    ojson r = ojson::object();
    r["id"] = i.id;
    r["types"] = i.types;
    put(r, "format", i.format);
    put(r, "size", i.size);
    put(r, "modified", i.modified_raw);
    return r;
}

ojson page_result(const lws::ContainerPage& p) {
    ojson r = ojson::object();
    if (!p.id.empty()) r["id"] = p.id;  // the library leaves it empty for a search page without one
    r["types"] = p.types;
    put(r, "totalItems", p.total_items);
    ojson items = ojson::array();
    for (const auto& i : p.items) items.push_back(item_result(i));
    r["items"] = std::move(items);
    put(r, "first", p.first);
    put(r, "next", p.next);
    put(r, "prev", p.prev);
    put(r, "last", p.last);
    r["metadata"] = metadata_result(p.metadata);
    return r;
}

ojson update_result(const lws::UpdateResult& u) {
    ojson r = ojson::object();
    r["status"] = u.status;
    put(r, "etag", u.etag);
    r["metadata"] = metadata_result(u.metadata);
    return r;
}

ojson created_result(const lws::CreateResult& c) {
    ojson r = ojson::object();
    r["location"] = c.location;
    r["metadata"] = metadata_result(c.metadata);
    return r;
}

ojson storage_result(const lws::StorageDescription& s) {
    ojson r = ojson::object();
    r["id"] = s.id;
    r["types"] = s.types;
    try {
        r["storageRoot"] = s.storage_root();
    } catch (const lws::ProtocolError&) {
        // no StorageRoot service: storageRoot is omitted
    }
    ojson services = ojson::array();
    for (const auto& svc : s.services) {
        ojson o = ojson::object();
        put(o, "id", svc.id);
        o["types"] = svc.types;
        o["serviceEndpoint"] = svc.service_endpoint;
        if (svc.raw.is_object() && svc.raw.contains("subscriptionType")) o["subscriptionType"] = svc.strings("subscriptionType");
        services.push_back(std::move(o));
    }
    r["services"] = std::move(services);
    ojson methods = ojson::array();
    for (const auto& vm : s.verification_methods) {
        ojson o = ojson::object();
        o["id"] = vm.id;
        o["type"] = vm.type;
        put(o, "controller", vm.controller);
        methods.push_back(std::move(o));
    }
    r["verificationMethods"] = std::move(methods);
    r["raw"] = from_library(s.raw);
    return r;
}

ojson subscription_result(const lws::Subscription& s) {
    ojson r = ojson::object();
    r["subscription"] = s.subscription;
    r["types"] = ojson::array({s.type});
    put(r, "expires", s.expires);
    r["raw"] = from_library(s.raw);
    return r;
}

/// Pulls at most `limit + 1` items from a lazy sequence; returns the first `limit` under `key`
/// and whether there was one more.
template <typename T, typename Convert>
ojson take(const lws::PagedRange<T>& range, std::uint64_t limit, const char* key, Convert convert) {
    ojson items = ojson::array();
    bool truncated = false;
    for (auto it = range.begin(); it != range.end(); ++it) {
        if (items.size() == limit) {
            truncated = true;
            break;
        }
        items.push_back(convert(*it));
    }
    ojson r = ojson::object();
    r[key] = std::move(items);
    r["truncated"] = truncated;
    return r;
}

ojson items_of(const lws::ContainerRange& range, std::uint64_t limit) { return take(range, limit, "items", item_result); }

ojson empty() { return ojson::object(); }

ojson location_result(const std::string& location) {
    ojson r = ojson::object();
    r["location"] = location;
    return r;
}

/// `{"document"}` for an access request or grant the library read. The C++ models keep no raw
/// document, so this is the library's re-serialization, to_json(). That validates more than
/// from_json() does, so a server document the library accepted may fail to serialize: the bad
/// document came from the server, so that is a ProtocolError.
template <typename Doc>
ojson document_result(const Doc& doc) {
    json document;
    try {
        document = doc.to_json();
    } catch (const std::invalid_argument& e) {
        throw lws::ProtocolError(std::string("the server's access document is incomplete: ") + e.what());
    }
    ojson r = ojson::object();
    r["document"] = from_library(document);
    return r;
}

// ---------------------------------------------------------------------------------------------
// Errors

template <typename E>
bool is(const lws::HttpError& e) {
    return dynamic_cast<const E*>(&e) != nullptr;
}

/// The API contract's name of the library's HttpError subclass.
std::string http_kind(const lws::HttpError& e) {
    if (is<lws::BadRequestError>(e)) return "BadRequestError";
    if (is<lws::UnauthorizedError>(e)) return "UnauthorizedError";
    if (is<lws::ForbiddenError>(e)) return "ForbiddenError";
    if (is<lws::NotFoundError>(e)) return "NotFoundError";
    if (is<lws::MethodNotAllowedError>(e)) return "MethodNotAllowedError";
    if (is<lws::NotAcceptableError>(e)) return "NotAcceptableError";
    if (is<lws::ConflictError>(e)) return "ConflictError";
    if (is<lws::GoneError>(e)) return "GoneError";
    if (is<lws::PreconditionFailedError>(e)) return "PreconditionFailedError";
    if (is<lws::UnsupportedMediaTypeError>(e)) return "UnsupportedMediaTypeError";
    if (is<lws::UnprocessableContentError>(e)) return "UnprocessableContentError";
    if (is<lws::NotImplementedError>(e)) return "NotImplementedError";
    if (is<lws::InsufficientStorageError>(e)) return "InsufficientStorageError";
    return "HttpError";
}

ojson simple_error(std::string_view kind, std::string_view message) {
    ojson error = ojson::object();
    error["kind"] = kind;
    error["message"] = message;
    return error;
}

/// The protocol's error object for the exception being handled.
ojson error_result(const std::string& op) {
    try {
        throw;
    } catch (const AdapterError& e) {
        return simple_error(e.kind(), e.what());
    } catch (const lws::HttpError& e) {
        ojson error = ojson::object();
        error["kind"] = http_kind(e);
        error["status"] = e.status();
        error["message"] = e.what();
        if (e.problem()) error["problem"] = from_library(e.problem()->raw);
        if (const auto* m = dynamic_cast<const lws::MethodNotAllowedError*>(&e)) error["allow"] = m->allow();
        if (const auto* u = dynamic_cast<const lws::UnsupportedMediaTypeError*>(&e)) error["acceptPatch"] = u->accept_patch();
        return error;
    } catch (const lws::AuthenticationError& e) {
        ojson error = simple_error("AuthenticationError", e.what());
        put(error, "oauthError", e.oauth_error());
        put(error, "oauthErrorDescription", e.error_description());
        return error;
    } catch (const lws::SignatureVerificationError& e) {
        return simple_error("SignatureVerificationError", e.what());
    } catch (const lws::ProtocolError& e) {  // ParseError included
        return simple_error("ProtocolError", e.what());
    } catch (const lws::TransportError& e) {
        return simple_error("TransportError", e.what());
    } catch (const lws::Error& e) {
        std::cerr << op << ": lws::Error: " << e.what() << std::endl;
        return simple_error("InternalError", std::string("lws::Error: ") + e.what());
    } catch (const std::invalid_argument& e) {
        // The library's own argument validation (a relative IRI in a type query, an unusable JWK,
        // an access document without a policy, ...).
        return simple_error("InvalidArguments", e.what());
    } catch (const std::exception& e) {
        std::cerr << op << ": " << typeid(e).name() << ": " << e.what() << std::endl;
        return simple_error("InternalError", e.what());
    } catch (...) {
        std::cerr << op << ": unknown exception" << std::endl;
        return simple_error("InternalError", "unknown exception");
    }
}

// ---------------------------------------------------------------------------------------------
// The operations

class Adapter {
public:
    using Handler = ojson (Adapter::*)(const ojson&);
    struct Operation {
        const char* name;
        Handler handler;
        bool available;  ///< announced in the hello
    };

    static const std::vector<Operation>& operations() {
        static const std::vector<Operation> table = {
            {"configure", &Adapter::configure, true},
            {"discover_storage", &Adapter::discover_storage, true},
            {"get_storage_description", &Adapter::get_storage_description, true},
            {"head", &Adapter::head, true},
            {"read", &Adapter::read, true},
            {"read_container", &Adapter::read_container, true},
            {"list_container", &Adapter::list_container, true},
            {"create", &Adapter::create, true},
            {"create_container", &Adapter::create_container, true},
            {"update", &Adapter::update, true},
            {"patch", &Adapter::patch, true},
            {"delete", &Adapter::remove, true},
            {"linkset_url", &Adapter::linkset_url, true},
            {"read_linkset", &Adapter::read_linkset, true},
            {"update_linkset", &Adapter::update_linkset, true},
            {"patch_linkset", &Adapter::patch_linkset, true},
            {"subscribe", &Adapter::subscribe, true},
            {"list_subscriptions", &Adapter::list_subscriptions, true},
            {"get_subscription", &Adapter::get_subscription, true},
            {"unsubscribe", &Adapter::unsubscribe, true},
            {"verify_notification", &Adapter::verify_notification, LWS_WITH_OPENSSL != 0},
            {"request_access", &Adapter::request_access, true},
            {"get_access_request", &Adapter::get_access_request, true},
            {"list_access_requests", &Adapter::list_access_requests, true},
            {"cancel_access_request", &Adapter::cancel_access_request, true},
            {"grant_access", &Adapter::grant_access, true},
            {"get_access_grant", &Adapter::get_access_grant, true},
            {"list_access_grants", &Adapter::list_access_grants, true},
            {"revoke_access_grant", &Adapter::revoke_access_grant, true},
            {"read_type_index", &Adapter::read_type_index, true},
            {"list_types", &Adapter::list_types, true},
            {"search_types", &Adapter::search_types, true},
            {"search_all", &Adapter::search_all, true},
            {"accepted_query_formats", &Adapter::accepted_query_formats, true},
            {"shutdown", &Adapter::shutdown, true},
        };
        return table;
    }

    ojson run(Handler handler, const ojson& args) { return (this->*handler)(args); }

private:
    // Until the first configure: a client with no authenticator.
    lws::Client client_{};

    // ---- configure ----------------------------------------------------------------------

    ojson configure(const ojson& args) {
        static const ojson anonymous = {{"type", "none"}};
        const ojson* auth_arg = member(args, "auth");
        const ojson& auth = auth_arg ? *auth_arg : anonymous;
        if (!auth.is_object()) throw invalid("argument 'auth' must be an object");
        lws::TokenExchangeOptions exchange;
        if (const auto allow = optional_bool(args, "allowInsecureHttp")) exchange.allow_insecure_http = *allow;

        ojson result = ojson::object();
        result["library"] = kLibrary;
        std::shared_ptr<lws::Authenticator> authenticator;
        const ojson* type_arg = member(auth, "type");
        const std::string type = type_arg && type_arg->is_string() ? type_arg->get<std::string>() : std::string();
        if (type == "none") {
            // anonymous requests
        } else if (type == "bearer") {
            authenticator = std::make_shared<lws::BearerTokenAuthenticator>(required_string(auth, "token"),
                                                                            optional_string(auth, "realm"));
        } else if (type == "openid") {
            authenticator = std::make_shared<lws::TokenExchangeAuthenticator>(
                std::make_shared<lws::OpenIdCredentials>(required_string(auth, "idToken")), exchange);
        } else if (type == "selfSigned") {
#if LWS_WITH_OPENSSL
            const std::string agent = required_string(auth, "agent");
            const ojson& jwk = required_object(auth, "privateJwk");
            std::optional<std::string> kid = optional_string(auth, "kid");
            if (!kid) {
                if (const auto it = jwk.find("kid"); it != jwk.end() && it->is_string()) kid = it->get<std::string>();
            }
            if (!kid) throw invalid("selfSigned needs 'kid', or a 'kid' in the private JWK");
            auto key = lws::PrivateKey::from_jwk(to_library(jwk));
            authenticator = std::make_shared<lws::TokenExchangeAuthenticator>(
                lws::SelfSignedCredentials::for_agent(agent, std::move(key), *kid), exchange);
            result["agent"] = agent;
            result["kid"] = *kid;
#else
            throw unsupported("selfSigned credentials need a library built with OpenSSL (LWS_WITH_OPENSSL)");
#endif
        } else if (type == "didKey") {
#if LWS_WITH_OPENSSL
            const std::string algorithm = optional_string(auth, "algorithm").value_or("ES256");
            lws::KeyAlgorithm alg = lws::KeyAlgorithm::ES256;
            if (algorithm == "ES256") alg = lws::KeyAlgorithm::ES256;
            else if (algorithm == "EdDSA") alg = lws::KeyAlgorithm::EdDSA;
            else throw invalid("unknown algorithm '" + algorithm + "'");
            auto credentials = lws::SelfSignedCredentials::did_key(lws::PrivateKey::generate(alg));
            result["agent"] = credentials->agent_id();
            result["kid"] = credentials->kid();
            authenticator = std::make_shared<lws::TokenExchangeAuthenticator>(credentials, exchange);
#else
            throw unsupported("did:key credentials need a library built with OpenSSL (LWS_WITH_OPENSSL)");
#endif
        } else {
            throw invalid("unknown auth type '" + (type_arg ? (type_arg->is_string() ? type : type_arg->dump()) : "") + "'");
        }

        lws::ClientOptions options;
        options.authenticator = std::move(authenticator);
        if (const auto user_agent = optional_string(args, "userAgent")) options.user_agent = *user_agent;
        if (const auto seconds = optional_count(args, "timeoutSeconds")) {
            if (*seconds == 0 || *seconds > 1000000000) throw invalid("argument 'timeoutSeconds' must be a positive integer");
            options.timeout = std::chrono::seconds(*seconds);
        }
        if (const ojson* headers = optional_object(args, "headers")) {
            for (auto it = headers->begin(); it != headers->end(); ++it) {
                if (!it->is_string()) throw invalid("header '" + it.key() + "' must be a string");
                options.default_headers.add(it.key(), it->get<std::string>());
            }
        }
        client_ = lws::Client(std::move(options));
        return result;
    }

    // ---- discovery and reading ----------------------------------------------------------

    ojson discover_storage(const ojson& args) { return storage_result(client_.discover_storage(required_target(args, "url"))); }

    ojson get_storage_description(const ojson& args) {
        return storage_result(client_.get_storage_description(required_target(args, "url")));
    }

    ojson head(const ojson& args) { return metadata_result(client_.head(required_target(args, "url"))); }

    ojson read(const ojson& args) {
        const std::string url = required_target(args, "url");
        lws::ReadOptions options;
        options.accept = optional_string(args, "accept");
        const auto start = optional_count(args, "rangeStart");
        const auto end = optional_count(args, "rangeEnd");
        if (start) options.range = lws::byte_range(*start, end);
        else if (end) throw invalid("rangeEnd needs rangeStart");
        options.if_none_match = optional_string(args, "ifNoneMatch");
        options.prefer = optional_string(args, "prefer");
        const lws::Resource resource = client_.read(url, options);
        ojson r = ojson::object();
        r["metadata"] = metadata_result(resource);
        r["notModified"] = resource.not_modified;
        put(r, "contentRange", resource.content_range);
        r["body"] = body_result(resource.not_modified ? std::string() : resource.body, resource.content_type);
        return r;
    }

    ojson read_container(const ojson& args) { return page_result(client_.read_container(required_target(args, "url"))); }

    ojson list_container(const ojson& args) {
        const std::string url = required_target(args, "url");
        return items_of(client_.list_container(url), limit_of(args));
    }

    // ---- writing --------------------------------------------------------------------------

    ojson create(const ojson& args) {
        const std::string container = required_target(args, "container");
        const Body body = body_of(member(args, "body"), optional_string(args, "contentType"));
        lws::CreateOptions options;
        options.slug = optional_string(args, "slug");
        if (const ojson* types = optional_array(args, "types")) options.types = strings_of(*types, "types");
        if (const ojson* links = optional_array(args, "links")) {
            for (const auto& l : *links) {
                const auto href = l.is_object() ? l.find("href") : l.end();
                const auto rel = l.is_object() ? l.find("rel") : l.end();
                if (!l.is_object() || href == l.end() || !href->is_string() || rel == l.end() || !rel->is_string())
                    throw invalid("argument 'links' must be a list of {href, rel} objects");
                options.links.push_back(lws::Link{href->get<std::string>(), rel->get<std::string>(), {}});
            }
        }
        return created_result(client_.create(container, body.bytes, body.content_type, options));
    }

    ojson create_container(const ojson& args) {
        const std::string parent = required_target(args, "parent");
        lws::CreateOptions options;
        options.slug = optional_string(args, "slug");
        return created_result(client_.create_container(parent, options));
    }

    ojson update(const ojson& args) {
        const std::string url = required_target(args, "url");
        const Body body = body_of(&required(args, "body"), optional_string(args, "contentType"));
        lws::UpdateOptions options;
        options.if_match = optional_string(args, "ifMatch");
        options.if_none_match = optional_string(args, "ifNoneMatch");
        return update_result(client_.update(url, body.bytes, body.content_type, options));
    }

    ojson patch(const ojson& args) {
        const std::string url = required_target(args, "url");
        const lws::JsonPatch patch = patch_of(member(args, "patch"));
        lws::UpdateOptions options;
        options.if_match = optional_string(args, "ifMatch");
        return update_result(client_.patch(url, patch, options));
    }

    ojson remove(const ojson& args) {
        const std::string url = required_target(args, "url");
        lws::DeleteOptions options;
        options.if_match = optional_string(args, "ifMatch");
        options.recursive = optional_bool(args, "recursive").value_or(false);
        client_.remove(url, options);
        return empty();
    }

    // ---- linksets -------------------------------------------------------------------------

    ojson linkset_url(const ojson& args) {
        ojson r = ojson::object();
        r["linkset"] = client_.linkset_url(required_target(args, "url"));
        return r;
    }

    ojson read_linkset(const ojson& args) {
        const lws::LinksetDocument doc = client_.read_linkset(required_target(args, "url"));
        ojson r = ojson::object();
        r["url"] = doc.url;
        put(r, "etag", doc.etag);
        r["linkset"] = from_library(doc.linkset.to_json());
        r["allow"] = doc.allow;
        r["acceptPatch"] = doc.accept_patch;
        return r;
    }

    ojson update_linkset(const ojson& args) {
        const std::string url = required_target(args, "linksetUrl");
        lws::Linkset linkset;
        try {
            linkset = lws::Linkset::from_json(to_library(required_object(args, "linkset")));
        } catch (const lws::ProtocolError& e) {
            throw invalid(std::string("argument 'linkset': ") + e.what());
        }
        lws::UpdateOptions options;
        options.if_match = optional_string(args, "ifMatch");
        return update_result(client_.update_linkset(url, linkset, options));
    }

    ojson patch_linkset(const ojson& args) {
        const std::string url = required_target(args, "linksetUrl");
        const lws::JsonPatch patch = patch_of(member(args, "patch"));
        lws::UpdateOptions options;
        options.if_match = optional_string(args, "ifMatch");
        return update_result(client_.patch_linkset(url, patch, options));
    }

    // ---- notifications --------------------------------------------------------------------

    ojson subscribe(const ojson& args) {
        const std::string service = required_target(args, "serviceUrl");
        lws::WebhookSubscriptionRequest request;
        request.topics = strings_of(required_array(args, "topics"), "topics");
        request.inbox = required_string(args, "inbox");
        request.expires = optional_string(args, "expires");
        return subscription_result(client_.subscribe(service, request));
    }

    ojson list_subscriptions(const ojson& args) {
        const std::string service = required_target(args, "serviceUrl");
        return items_of(client_.list_subscriptions(service), limit_of(args));
    }

    ojson get_subscription(const ojson& args) { return subscription_result(client_.get_subscription(required_target(args, "url"))); }

    ojson unsubscribe(const ojson& args) {
        client_.unsubscribe(required_target(args, "url"));
        return empty();
    }

    ojson verify_notification([[maybe_unused]] const ojson& args) {
#if LWS_WITH_OPENSSL
        const std::string method = required_string(args, "method");
        const std::string url = required_string(args, "url");
        lws::HttpHeaders headers;
        const ojson& fields = required_object(args, "headers");
        for (auto it = fields.begin(); it != fields.end(); ++it) {
            if (it->is_string()) {
                headers.add(it.key(), it->get<std::string>());
            } else if (it->is_array()) {
                for (const auto& value : *it) {
                    if (!value.is_string()) throw invalid("header '" + it.key() + "' must be a list of strings");
                    headers.add(it.key(), value.get<std::string>());
                }
            } else {
                throw invalid("header '" + it.key() + "' must be a list of strings");
            }
        }
        const std::string body = base64_argument(required_string(args, "bodyBase64"), "bodyBase64");
        lws::WebhookVerifierOptions options;
        if (const ojson* trusted = optional_array(args, "trustedStorages"))
            options.trusted_storages = strings_of(*trusted, "trustedStorages");
        // The verifier fetches storage descriptions through the configured client.
        lws::WebhookVerifier verifier(client_, options);
        const lws::VerifiedNotification verified = verifier.verify(method, url, headers, body);
        ojson activities = ojson::array();
        for (const auto& a : verified.notification.activities) {
            ojson o = ojson::object();
            if (!a.id.empty()) o["id"] = a.id;
            o["types"] = a.types;
            o["object"] = a.object.id;
            o["objectTypes"] = a.object.types;
            activities.push_back(std::move(o));
        }
        ojson r = ojson::object();
        r["storage"] = verified.storage;
        r["keyid"] = verified.keyid;
        r["activities"] = std::move(activities);
        r["raw"] = from_library(verified.notification.raw);
        return r;
#else
        throw unsupported("webhook verification needs a library built with OpenSSL (LWS_WITH_OPENSSL)");
#endif
    }

    // ---- access requests and grants -------------------------------------------------------

    template <typename Doc>
    static Doc access_document(const ojson& args, const char* name) {
        const json document = to_library(required_object(args, name));
        try {
            return Doc::from_json(document);
        } catch (const lws::ProtocolError& e) {
            throw invalid(std::string("argument '") + name + "': " + e.what());
        }
    }

    ojson request_access(const ojson& args) {
        const std::string service = required_target(args, "serviceUrl");
        const auto request = access_document<lws::AccessRequest>(args, "request");
        return location_result(client_.request_access(service, request));
    }

    ojson get_access_request(const ojson& args) {
        return document_result(client_.get_access_request(required_target(args, "url")));
    }

    ojson list_access_requests(const ojson& args) {
        const std::string service = required_target(args, "serviceUrl");
        return items_of(client_.list_access_requests(service), limit_of(args));
    }

    ojson cancel_access_request(const ojson& args) {
        client_.cancel_access_request(required_target(args, "url"));
        return empty();
    }

    ojson grant_access(const ojson& args) {
        const std::string service = required_target(args, "serviceUrl");
        const auto grant = access_document<lws::AccessGrant>(args, "grant");
        return location_result(client_.grant_access(service, grant));
    }

    ojson get_access_grant(const ojson& args) {
        return document_result(client_.get_access_grant(required_target(args, "url")));
    }

    ojson list_access_grants(const ojson& args) {
        const std::string service = required_target(args, "serviceUrl");
        return items_of(client_.list_access_grants(service), limit_of(args));
    }

    ojson revoke_access_grant(const ojson& args) {
        client_.revoke_access_grant(required_target(args, "url"));
        return empty();
    }

    // ---- type index and search ------------------------------------------------------------

    ojson read_type_index(const ojson& args) {
        const lws::TypeIndexPage page = client_.read_type_index(required_target(args, "url"));
        ojson r = ojson::object();
        put(r, "totalItems", page.total_items);
        r["types"] = page.types;
        put(r, "first", page.first);
        put(r, "next", page.next);
        put(r, "prev", page.prev);
        put(r, "last", page.last);
        return r;
    }

    ojson list_types(const ojson& args) {
        const std::string service = required_target(args, "serviceUrl");
        return take(client_.list_types(service), limit_of(args), "types", [](const std::string& t) { return ojson(t); });
    }

    ojson search_types(const ojson& args) {
        const std::string service = required_target(args, "serviceUrl");
        return page_result(client_.search_types(service, query_of(&required_object(args, "query"))));
    }

    ojson search_all(const ojson& args) {
        const std::string service = required_target(args, "serviceUrl");
        const lws::TypeQuery query = query_of(&required_object(args, "query"));
        return items_of(client_.search_all(service, query), limit_of(args));
    }

    ojson accepted_query_formats(const ojson& args) {
        ojson r = ojson::object();
        r["formats"] = client_.accepted_query_formats(required_target(args, "serviceUrl"));
        return r;
    }

    ojson shutdown(const ojson&) { return empty(); }
};

// ---------------------------------------------------------------------------------------------
// The protocol loop

void write(const ojson& message) {
    std::cout << message.dump(-1, ' ', false, ojson::error_handler_t::replace) << '\n' << std::flush;
}

void write_error(const ojson& id, const ojson& error) {
    ojson response = ojson::object();
    response["id"] = id;
    response["ok"] = false;
    response["error"] = error;
    write(response);
}

}  // namespace

int main() {
    std::ios::sync_with_stdio(false);
    Adapter adapter;

    ojson hello = ojson::object();
    hello["protocol"] = "lws-driver/1";
    hello["language"] = "cpp";
    hello["library"] = kLibrary;
    ojson names = ojson::array();
    for (const auto& op : Adapter::operations())
        if (op.available) names.push_back(op.name);
    hello["operations"] = std::move(names);
    ojson announcement = ojson::object();
    announcement["hello"] = std::move(hello);
    write(announcement);

    std::string line;
    while (std::getline(std::cin, line)) {
        if (trim(line).empty()) continue;
        const ojson request = ojson::parse(line, nullptr, false);
        if (request.is_discarded() || !request.is_object()) {
            write_error(nullptr, simple_error("InvalidArguments", request.is_discarded() ? "the request is not JSON"
                                                                                         : "the request is not a JSON object"));
            continue;
        }
        const ojson id = request.contains("id") ? request["id"] : ojson(nullptr);
        const std::string op = request.contains("op") && request["op"].is_string() ? request["op"].get<std::string>() : std::string();
        const Adapter::Operation* operation = nullptr;
        for (const auto& candidate : Adapter::operations())
            if (op == candidate.name) operation = &candidate;
        if (!operation) {
            write_error(id, simple_error("Unsupported", "unknown operation '" + (op.empty() && request.contains("op") ? request["op"].dump() : op) + "'"));
            continue;
        }
        try {
            static const ojson no_args = ojson::object();
            const ojson* args = member(request, "args");
            if (args && !args->is_object()) throw invalid("args must be an object");
            ojson response = ojson::object();
            response["id"] = id;
            response["ok"] = true;
            response["result"] = adapter.run(operation->handler, args ? *args : no_args);
            write(response);
        } catch (...) {
            write_error(id, error_result(op));
        }
        if (op == "shutdown") break;
    }
    return 0;
}
