// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Erich Bremer and the lws-client contributors
//
// Quickstart: discover a storage, create / read / update / list / delete resources.
//
//   lws-quickstart <resource-or-storage-url> [bearer-token]
//
// Against the mock server (authentication disabled):
//   node testing/mock-server/server.mjs --no-auth
//   lws-quickstart http://localhost:8787/root/

#include <iostream>

#include <lws/lws.hpp>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <resource-url> [bearer-token]\n";
        return 2;
    }
    try {
        lws::ClientOptions options;
        if (argc > 2) options.authenticator = std::make_shared<lws::BearerTokenAuthenticator>(argv[2]);
        lws::Client client(options);

        // Discovery: follow rel="https://www.w3.org/ns/lws#storage" to the storage description.
        const lws::StorageDescription storage = client.discover_storage(argv[1]);
        const std::string root = storage.storage_root();
        std::cout << "storage " << storage.id << "\nroot    " << root << "\n";

        // Create a container and a text resource inside it.
        const auto folder = client.create_container(root, {.slug = "quickstart"});
        const auto note = client.create(folder.location, "milk\neggs\nbread\n", "text/plain", {.slug = "shopping.txt"});
        std::cout << "created " << note.location << "\n";

        // Read it back (ETag kept for optimistic concurrency).
        const lws::Resource resource = client.read(note.location);
        std::cout << "read    " << resource.body.size() << " bytes, etag " << resource.etag.value_or("-") << "\n";

        // Conditional update: only succeeds if nobody changed it meanwhile.
        client.update(note.location, "milk\neggs\nbread\nbutter\n", "text/plain", {.if_match = resource.etag});

        // JSON resources and JSON Patch (the LWS baseline patch format).
        const auto profile = client.create_json(folder.location, {{"name", "Alice"}, {"age", 30}}, {.slug = "profile.json"});
        client.patch(profile.location, lws::JsonPatch{}.replace("/age", 31).add("/city", "Boston"));
        std::cout << "profile " << client.read(profile.location).json().dump() << "\n";

        // List the container lazily — pages are fetched on demand.
        for (const lws::ContainedResource& item : client.list_container(folder.location))
            std::cout << "  - " << item.id << (item.is_container() ? " (container)" : "") << " "
                      << item.format.value_or("") << "\n";

        // Clean up recursively (Depth: infinity).
        client.remove(folder.location, {.recursive = true});
        std::cout << "deleted " << folder.location << "\n";
    } catch (const lws::HttpError& e) {
        std::cerr << "HTTP error " << e.status() << ": " << e.what() << "\n";
        return 1;
    } catch (const lws::Error& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
