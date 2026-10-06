// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Self-signed did:key authentication (lws10-authn-ssi-cid): the client signs its own
// credential, exchanges it at the storage's authorization server (OAuth 2.0 token exchange)
// and retries — all automatically on the first 401.
//
//   lws-did-key-auth <resource-url> [private-jwk-file]
//
//   node testing/mock-server/server.mjs
//   lws-did-key-auth http://localhost:8787/root/

#include <fstream>
#include <iostream>
#include <sstream>

#include <lws/lws.hpp>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <resource-url> [private-jwk-file]\n";
        return 2;
    }
    try {
        // Load a persistent key, or generate a fresh P-256 key (a new identity per run).
        lws::PrivateKey key = lws::PrivateKey::generate(lws::KeyAlgorithm::ES256);
        if (argc > 2) {
            std::ifstream in(argv[2]);
            std::stringstream ss;
            ss << in.rdbuf();
            key = lws::PrivateKey::from_jwk(nlohmann::json::parse(ss.str()));
        }
        auto credentials = lws::SelfSignedCredentials::did_key(key);
        std::cout << "agent " << credentials->agent_id() << "\n";

        lws::TokenExchangeOptions auth_options;
        // Only send credentials to authorization servers you trust (optional policy).
        auth_options.authorization_server_filter = [](std::string_view as_uri, std::string_view realm) {
            std::cout << "token exchange with " << as_uri << " for realm " << realm << "\n";
            return true;
        };
        auto authenticator = std::make_shared<lws::TokenExchangeAuthenticator>(credentials, auth_options);

        lws::ClientOptions options;
        options.authenticator = authenticator;
        lws::Client client(options);

        const auto page = client.read_container(argv[1]);
        std::cout << "container " << page.id << " has " << page.total_items.value_or(0) << " member(s)\n";
        for (const auto& token : authenticator->cached_tokens())
            std::cout << "cached access token for " << token.realm << " (issuer " << token.issuer << ")\n";

        // An HTTPS agent instead publishes this controlled identifier document at its URI and uses
        // SelfSignedCredentials::for_agent("https://id.example/bot", key, "key-1").
        std::cout << lws::controlled_identifier_document("https://id.example/bot", key.public_jwk(), "key-1").dump(2)
                  << "\n";
    } catch (const lws::Error& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
