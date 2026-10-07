// SPDX-License-Identifier: MIT
// The basics against the mock server (node testing/mock-server/server.mjs --port 8787):
//
//   ./gradlew -q quickstart --args=http://localhost:8787/root/
package com.ebremer.lws.kotlin.examples

import com.ebremer.lws.kotlin.LwsClient
import com.ebremer.lws.kotlin.PreconditionFailedException
import com.ebremer.lws.kotlin.auth.SelfSignedCredentials
import com.ebremer.lws.kotlin.auth.SigningKey
import com.ebremer.lws.kotlin.auth.TokenExchangeAuthenticator
import com.ebremer.lws.kotlin.json.jsonPatch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.net.URI

fun main(args: Array<String>) = runBlocking {
    val start = URI(args.firstOrNull() ?: "http://localhost:8787/root/")

    // A did:key agent signs its own credential; the client exchanges it for access tokens on demand.
    val me = SelfSignedCredentials.didKey(SigningKey.generateP256())
    val client = LwsClient(authenticator = TokenExchangeAuthenticator(me))
    println("Agent: ${me.agent}")

    val storage = client.discoverStorage(start)
    val root = storage.storageRoot()
    println("Storage ${storage.id}, root $root")

    val folder = client.createContainer(root, slug = "quickstart").location
    val note = client.createText(folder, "Hello, LWS!", slug = "hello.txt").location
    println("Created $note")

    val r = client.read(note)
    println("Read: ${r.text()} (ETag ${r.etag})")

    // Optimistic concurrency: only replace it if nobody changed it since we read it.
    client.updateText(note, "Hello again", ifMatch = r.etag)
    try {
        client.updateText(note, "lost update", ifMatch = r.etag)
    } catch (e: PreconditionFailedException) {
        println("Stale update rejected with HTTP ${e.status}")
    }

    val alice = buildJsonObject {
        put("name", "Alice")
        put("age", 30)
    }
    val profile = client.createJson(folder, alice, slug = "profile.json").location
    client.patch(profile, jsonPatch { replace("/age", 31); add("/city", "Boston") })
    println("Patched: ${client.read(profile).text()}")

    println("Members of $folder:")
    client.listContainer(folder).collect { item -> // follows rel="next" pages lazily
        println("  ${item.id} ${item.format}")
    }

    client.delete(folder, recursive = true) // Depth: infinity
    println("Deleted $folder")
}
