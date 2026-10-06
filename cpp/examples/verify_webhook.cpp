// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Verifying a signed webhook delivery (RFC 9421 + RFC 9530) inside your own HTTP server.
// Plug the body of `on_webhook` into whatever server framework receives the POST.
//
// Run without arguments to verify one of the shared conformance vectors offline:
//   lws-verify-webhook <path-to>/conformance/fixtures/webhook/p256-valid.json \
//                      <path-to>/conformance/fixtures/webhook/storage-description.json

#include <fstream>
#include <iostream>
#include <sstream>

#include <lws/lws.hpp>

namespace {

std::string slurp(const char* path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// What an inbox handler looks like in production.
int on_webhook(lws::WebhookVerifier& verifier, const lws::HttpRequest& delivery) {
    try {
        const lws::VerifiedNotification verified = verifier.verify(delivery);
        for (const lws::Activity& activity : verified.notification.activities)
            std::cout << activity.types.at(0) << " " << activity.object.id << " (storage " << verified.storage << ")\n";
        return 202;
    } catch (const lws::SignatureVerificationError& e) {
        std::cerr << "rejected: " << e.what() << "\n";
        return 401;
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: " << argv[0] << " <webhook-vector.json> <storage-description.json>\n";
        return 2;
    }
    const auto vector = nlohmann::json::parse(slurp(argv[1]));
    const auto description = nlohmann::json::parse(slurp(argv[2]));

    lws::WebhookVerifierOptions options;
    options.trusted_storages = {description["id"].get<std::string>()};
    // The vectors carry a fixed "now"; production code uses the system clock (the default).
    const auto now = vector["now"].get<std::int64_t>();
    options.clock = [now] { return std::chrono::system_clock::time_point(std::chrono::seconds(now)); };

    // In production: lws::WebhookVerifier verifier(lws::Client{}, options); — the client
    // dereferences the storage identifier taken from the signature's keyid.
    lws::WebhookVerifier verifier(
        [&](const std::string& storage_id) { return lws::StorageDescription::from_json(description, storage_id); },
        options);

    lws::HttpRequest delivery;
    delivery.method = vector["method"].get<std::string>();
    delivery.url = vector["url"].get<std::string>();  // the inbox URL you registered
    delivery.body = vector["body"].get<std::string>();
    for (auto it = vector["headers"].begin(); it != vector["headers"].end(); ++it)
        delivery.headers.add(it.key(), it.value().get<std::string>());

    const int status = on_webhook(verifier, delivery);
    std::cout << "HTTP " << status << "\n";
    return status == 202 ? 0 : 1;
}
