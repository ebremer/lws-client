// SPDX-License-Identifier: MIT
// The C# adapter of the lws-client driver: runs the operations of driver/PROTOCOL.md (lws-driver/1) with lws-client
// for C#. It reads one JSON request per line on stdin and writes one JSON response per line on stdout; everything
// else (logs, stack traces) goes to stderr.
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ebremer.Lws.Driver.Adapter;

// stdout carries protocol messages only: keep it for them, and send every other write to stderr.
var protocol = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { NewLine = "\n", AutoFlush = false };
Console.SetOut(Console.Error);
using var input = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
using var adapter = new Adapter();

async Task WriteAsync(JsonObject message)
{
    await protocol.WriteAsync(message.ToJsonString(Results.Json));
    await protocol.WriteAsync('\n');
    await protocol.FlushAsync();
}

static JsonObject Failure(JsonNode? id, JsonObject error) => new() { ["id"] = id, ["ok"] = false, ["error"] = error };

await WriteAsync(new JsonObject
{
    ["hello"] = new JsonObject
    {
        ["protocol"] = Adapter.Protocol,
        ["language"] = Adapter.Language,
        ["library"] = Adapter.Library,
        ["operations"] = Results.Strings(adapter.Operations),
    },
});

while (await input.ReadLineAsync() is { } line)
{
    if (string.IsNullOrWhiteSpace(line)) continue;
    JsonNode? request;
    try
    {
        request = JsonNode.Parse(line);
    }
    catch (JsonException)
    {
        await WriteAsync(Failure(null, Errors.Error(Errors.InvalidArguments, "the request is not JSON")));
        continue;
    }
    if (request is not JsonObject message)
    {
        await WriteAsync(Failure(null, Errors.Error(Errors.InvalidArguments, "the request is not a JSON object")));
        continue;
    }
    JsonNode? id = message["id"]?.DeepClone();
    string? op = message["op"] is JsonValue o && o.GetValueKind() == JsonValueKind.String ? o.GetValue<string>() : null;
    if (op is null || !adapter.TryGet(op, out Func<JsonObject, Task<JsonObject>>? operation))
    {
        await WriteAsync(Failure(id, Errors.Error(Errors.Unsupported, $"unknown operation '{op}'")));
        continue;
    }
    JsonObject response;
    try
    {
        JsonNode? argsNode = message["args"];
        if (argsNode is not null and not JsonObject) throw AdapterException.Invalid("args must be an object");
        JsonObject arguments = argsNode is JsonObject a ? a : [];
        JsonObject result = await operation(arguments);
        response = new JsonObject { ["id"] = id, ["ok"] = true, ["result"] = result };
    }
    catch (Exception e)
    {
        response = Failure(id, Errors.Of(e));
    }
    await WriteAsync(response);
    if (op == "shutdown") break;
}

await protocol.FlushAsync();
return 0;
