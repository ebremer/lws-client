// SPDX-License-Identifier: MIT
// Discover a storage, then create, read, update, patch, list and delete resources.
//
//   dotnet run --project examples/Quickstart -- http://localhost:8787/root/
using System.Text.Json.Nodes;
using Ebremer.Lws;
using Ebremer.Lws.Auth;

var start = new Uri(args.Length > 0 ? args[0] : "http://localhost:8787/root/");

// A did:key agent signs its own credential; the client exchanges it for access tokens on demand.
SelfSignedCredentials me = SelfSignedCredentials.DidKey(SigningKey.GenerateP256());
using var authenticator = new TokenExchangeAuthenticator(me);
using var client = new LwsClient(new LwsClientOptions { Authenticator = authenticator });
Console.WriteLine($"Agent: {me.Agent}");

StorageDescription storage = await client.DiscoverStorageAsync(start);
Uri root = storage.GetStorageRoot();
Console.WriteLine($"Storage {storage.Id}, root {root}");

CreateResult folder = await client.CreateContainerAsync(root, new CreateOptions { Slug = "quickstart" });
CreateResult note = await client.CreateTextAsync(folder.Location, "Hello, LWS!", options: new CreateOptions { Slug = "hello.txt" });
Console.WriteLine($"Created {note.Location}");

Resource r = await client.ReadAsync(note.Location);
Console.WriteLine($"Read: {r.GetText()} (ETag {r.ETag})");

// Optimistic concurrency: only replace it if nobody changed it since we read it.
await client.UpdateAsync(note.Location, "Hello again"u8.ToArray(), "text/plain", new UpdateOptions { IfMatch = r.ETag });
try
{
    await client.UpdateAsync(note.Location, "lost update"u8.ToArray(), "text/plain", new UpdateOptions { IfMatch = r.ETag });
}
catch (PreconditionFailedException e)
{
    Console.WriteLine($"Stale update rejected with HTTP {e.Status}");
}

Uri profile = (await client.CreateJsonAsync(folder.Location, new JsonObject { ["name"] = "Alice", ["age"] = 30 },
    new CreateOptions { Slug = "profile.json" })).Location;
await client.PatchAsync(profile, new JsonPatch().Replace("/age", 31).Add("/city", "Boston"));
Console.WriteLine($"Patched: {(await client.ReadAsync(profile)).GetText()}");

Console.WriteLine($"Members of {folder.Location}:");
await foreach (ContainedResource item in client.ListContainerAsync(folder.Location))   // follows rel="next" pages lazily
{
    Console.WriteLine($"  {item.Id} {item.Format}");
}

await client.DeleteAsync(folder.Location, new DeleteOptions { Recursive = true });       // Depth: infinity
Console.WriteLine($"Deleted {folder.Location}");
