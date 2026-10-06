// SPDX-License-Identifier: MIT
package com.ebremer.lws.examples;

import com.ebremer.lws.Body;
import com.ebremer.lws.ContainedResource;
import com.ebremer.lws.CreateOptions;
import com.ebremer.lws.CreateResult;
import com.ebremer.lws.DeleteOptions;
import com.ebremer.lws.LwsClient;
import com.ebremer.lws.PreconditionFailedException;
import com.ebremer.lws.Resource;
import com.ebremer.lws.StorageDescription;
import com.ebremer.lws.UpdateOptions;
import com.ebremer.lws.auth.KeyPairs;
import com.ebremer.lws.auth.SelfSignedCredentials;
import com.ebremer.lws.auth.TokenExchangeAuthenticator;
import com.ebremer.lws.patch.JsonPatch;
import java.net.URI;
import java.util.Map;

/**
 * Discover a storage, then create, read, update, patch, list and delete resources.
 *
 * <pre>
 * java ... com.ebremer.lws.examples.Quickstart http://localhost:8787/root/
 * </pre>
 */
public final class Quickstart {
    public static void main(String[] args) {
        URI start = URI.create(args.length > 0 ? args[0] : "http://localhost:8787/root/");

        // A did:key agent signs its own credential; the client exchanges it for access tokens on demand.
        SelfSignedCredentials me = SelfSignedCredentials.didKey(KeyPairs.generateP256());
        LwsClient client = LwsClient.builder()
                .authenticator(TokenExchangeAuthenticator.of(me))
                .build();
        System.out.println("Agent: " + me.agent());

        StorageDescription storage = client.discoverStorage(start);
        URI root = storage.storageRoot();
        System.out.println("Storage " + storage.id() + ", root " + root);

        CreateResult folder = client.createContainer(root, CreateOptions.slug("quickstart"));
        CreateResult note = client.create(folder.location(), Body.of("Hello, LWS!"), "text/plain", CreateOptions.slug("hello.txt"));
        System.out.println("Created " + note.location());

        Resource r = client.read(note.location());
        System.out.println("Read: " + r.text() + " (ETag " + r.etag().orElse("-") + ")");

        // Optimistic concurrency: only replace if nobody changed it since we read it.
        client.update(note.location(), Body.of("Hello again"), "text/plain", UpdateOptions.ifMatch(r.etag().orElseThrow()));
        try {
            client.update(note.location(), Body.of("lost update"), "text/plain", UpdateOptions.ifMatch(r.etag().orElseThrow()));
        } catch (PreconditionFailedException e) {
            System.out.println("Stale update rejected with HTTP " + e.status());
        }

        URI profile = client.createJson(folder.location(), Map.of("name", "Alice", "age", 30), CreateOptions.slug("profile.json")).location();
        client.patch(profile, JsonPatch.builder().replace("/age", 31).add("/city", "Boston").build());
        System.out.println("Patched: " + client.read(profile).json());

        System.out.println("Members of " + folder.location() + ":");
        client.listContainer(folder.location())
                .map(ContainedResource::id)
                .forEach(id -> System.out.println("  " + id));

        client.delete(folder.location(), DeleteOptions.recursive());
        System.out.println("Deleted " + folder.location());
    }
}
