// SPDX-License-Identifier: MIT
import { callout, code, table } from "../../lib.mjs";
import { sample } from "../../samples.mjs";

const s = (topic) => code(sample("csharp", topic).lang, sample("csharp", topic).code);

export default {
  path: "languages/csharp.html",
  title: "C#",
  description: "The LWS client for C# and .NET 10: installation, configuration, async/await with CancellationToken, IAsyncEnumerable pagination, exceptions and build instructions.",
  body: `
<h1><span class="lang-badge lang-csharp">C#</span> C#</h1>
<div class="badges">
  <span class="badge accent">Ebremer.Lws.Client 0.1.0</span>
  <span class="badge">.NET 10</span>
  <span class="badge">namespace Ebremer.Lws</span>
  <span class="badge">1 dependency: BouncyCastle (Ed25519)</span>
</div>
<p class="lead">A .NET client built on <code>HttpClient</code> and <code>System.Text.Json</code>. Every operation is
<code>async</code> and takes a <code>CancellationToken</code>, listings are lazy <code>IAsyncEnumerable&lt;T&gt;</code>s for
<code>await foreach</code>, options are <code>init</code>-only records, and nullable reference types mark every value
that may be absent.</p>
<div id="toc" class="toc"></div>

<h2 id="install">Install</h2>
${s("install")}

<h2 id="first">First program</h2>
${s("first-program")}
<p>This is a complete <code>Program.cs</code> with top-level statements: create a console project
(<code>dotnet new console</code>), add the package or project reference, and run it with <code>dotnet run</code>.</p>

<h2 id="configure">Configure the client</h2>
${s("client-config")}
<p><code>LwsClient</code> is immutable and thread-safe: create one, share it, and dispose it when you are done. It owns its
<code>HttpClient</code> unless you pass one in. <code>WithAuthenticator(a)</code> returns a client with a different
authenticator that shares the same connections. The client follows redirects itself and re-checks credentials on
each hop, so an <code>HttpClient</code> or <code>HttpMessageHandler</code> you supply must not follow redirects
(<code>AllowAutoRedirect = false</code>). One that does bypasses that protection.</p>

<h2 id="idioms">C# idioms</h2>
${table(
  ["Aspect", "How the C# client does it"],
  [
    ["Calls", "Every operation is an <code>…Async</code> method returning a <code>Task</code>, with an optional trailing <code>CancellationToken</code>. Cancelling throws <code>OperationCanceledException</code>; a timeout throws <code>LwsTransportException</code>"],
    ["Pagination", "<code>ListContainerAsync</code>, <code>ListTypesAsync</code>, <code>SearchAllAsync</code>, <code>ListSubscriptionsAsync</code>… return lazy <code>IAsyncEnumerable&lt;T&gt;</code>s: <code>await foreach</code>, or .NET 10's <code>System.Linq.AsyncEnumerable</code> operators (<code>Where</code>, <code>Select</code>, <code>ToListAsync</code>)"],
    ["Options", "Records with <code>init</code> properties, set with object initializers: <code>new CreateOptions { Slug = … }</code>, <code>new UpdateOptions { IfMatch = etag }</code>, <code>new DeleteOptions { Recursive = true }</code>, <code>new ReadOptions { Range = new RangeHeaderValue(0, 1023) }</code>. Every one also has <code>Headers</code> and <code>Timeout</code>"],
    ["Bodies", "<code>ReadOnlyMemory&lt;byte&gt;</code> (replayable) or a <code>Stream</code> (sent once, after a <code>HEAD</code> obtains a token); <code>CreateTextAsync</code> and <code>CreateJsonAsync</code>; <code>ReadStreamAsync</code> for unbuffered reads"],
    ["Models", "Immutable classes and records. Absent values are <code>null</code> under nullable reference types; JSON is <code>JsonElement</code> / <code>JsonObject</code>; <code>GetJson&lt;T&gt;()</code> binds with <code>System.Text.Json</code>"],
    ["Errors", "<code>LwsException</code> → <code>HttpException</code> (<code>Status</code>, <code>Problem</code>, <code>Headers</code>, <code>Body</code>) → <code>NotFoundException</code>, <code>ConflictException</code>, …; narrow them with <code>catch … when</code>"],
    ["Disposal", "<code>LwsClient</code>, <code>TokenExchangeAuthenticator</code>, <code>WebhookVerifier</code> and <code>ResourceStream</code> are disposable: <code>using var</code> / <code>await using</code>"],
    ["Crypto", "The BCL's <code>ECDsa</code> (P-256, and P-384 for imported keys and webhook signatures) and <code>SHA256</code>/<code>SHA512</code>. Ed25519 comes from BouncyCastle.Cryptography, because .NET 10 has none"],
  ],
)}

<h2 id="namespaces">Namespaces</h2>
${table(
  ["Namespace", "Contents"],
  [
    ["<code>Ebremer.Lws</code>", "<code>LwsClient</code>, options, models (<code>Resource</code>, <code>ResourceMetadata</code>, <code>ContainerPage</code>, <code>StorageDescription</code>, <code>Linkset</code>…), <code>JsonPatch</code>, <code>JsonPointer</code>, <code>TypeQuery</code>, exceptions, <code>Lws</code> constants"],
    ["<code>Ebremer.Lws.Auth</code>", "<code>IAuthenticator</code>, <code>TokenExchangeAuthenticator</code>, <code>BearerTokenAuthenticator</code>, credentials, <code>SigningKey</code>, <code>VerificationKey</code>, <code>Jwk</code>, <code>Jwt</code>, <code>DidKey</code>, <code>ControlledIdentifierDocument</code>"],
    ["<code>Ebremer.Lws.Notifications</code>", "<code>WebhookSubscriptionRequest</code>, <code>Subscription</code>, <code>Notification</code>, <code>Activity</code>, <code>WebhookVerifier</code>"],
    ["<code>Ebremer.Lws.Access</code>", "<code>AccessRequest</code>, <code>AccessGrant</code>, <code>AccessPolicy</code>, <code>AccessTarget</code>, <code>Constraint</code>"],
    ["<code>Ebremer.Lws.Http</code>", "<code>Link</code>, <code>LinkHeader</code>, <code>WwwAuthenticate</code>, <code>AuthChallenge</code>, <code>StructuredFields</code>, <code>ProblemDetails</code>, <code>HeaderMap</code>, <code>Slug</code>"],
  ],
)}

<h2 id="notes">Notes and deviations</h2>
<ul>
  <li>The 501 exception is <code>HttpNotImplementedException</code>, so that <code>using Ebremer.Lws;</code> never clashes with
  <code>System.NotImplementedException</code>. The contract's <em>HttpError</em> is <code>HttpException</code>, <em>ProtocolError</em> is
  <code>ProtocolException</code>, and transport failures are <code>LwsTransportException</code> (its <code>InnerException</code> is the
  <code>HttpRequestException</code>, <code>IOException</code> or <code>TimeoutException</code>). An argument that is not an absolute
  http(s) URL throws <code>ArgumentException</code>.</li>
  <li>A subscription's URL is <code>Subscription.Url</code>. <code>SubscribeAsync(Service, …)</code> checks the service's
  <code>subscriptionType</code>; <code>SubscribeAsync(Uri, …)</code> takes a raw endpoint.</li>
  <li><code>StorageDescription.GetStorageRoot()</code> is a method because it throws <code>ProtocolException</code> when there is no
  <code>StorageRoot</code> service. The other well-known services are nullable properties (<code>NotificationService</code>,
  <code>TypeSearchService</code>…).</li>
  <li><code>ContainerPage.Id</code> is never null: a search page without an <code>id</code> takes the page URL.</li>
  <li><code>Linkset</code>, <code>JsonPatch</code> and <code>TypeQuery</code> are immutable, so <code>Add</code>, <code>Remove</code>,
  <code>Replace</code>, <code>AllOf</code>… return new instances. Start a query from <code>new TypeQuery()</code>.</li>
  <li><code>ReadLinksetResourceAsync(linksetUrl)</code> complements <code>ReadLinksetAsync(resourceUrl)</code> when you already know the linkset URL.</li>
  <li><code>WebhookVerifier.VerifyAsync(HttpListenerRequest, inbox)</code> serves <code>System.Net.HttpListener</code>. ASP.NET Core and other
  frameworks pass the method, the registered inbox URL, <code>HeaderMap.From(…)</code> and the body bytes.</li>
  <li><code>CreateJsonAsync&lt;T&gt;</code> and <code>GetJson&lt;T&gt;</code> use reflection-based serialization. For trimming and native AOT,
  <code>CreateJsonAsync</code> has a <code>JsonTypeInfo&lt;T&gt;</code> overload.</li>
  <li>Extras: <code>RequestAsync(method, url, …)</code> sends any request through the authentication and redirect pipeline;
  <code>ReadStreamAsync</code>, <code>SigningKey.FromECDsa</code> (P-256 or P-384) and <code>Jwt</code> helpers.</li>
</ul>

<h2 id="build">Build, test and examples</h2>
${code("bash", `
cd csharp
dotnet build                                        # library, tests and examples (warnings are errors)
dotnet test                                         # unit, fixture and HTTP tests
node ../testing/mock-server/server.mjs --port 8787 &
LWS_TEST_SERVER=http://localhost:8787 dotnet test   # adds the cross-language interop scenario
dotnet pack src/Ebremer.Lws.Client -c Release       # the NuGet package

# Examples (examples/): Quickstart, SelfSignedAuth, WebhookReceiver
dotnet run --project examples/Quickstart -- http://localhost:8787/root/`)}
${callout("note", "Source", ' <a href="https://github.com/ebremer/lws-client/tree/main/csharp">csharp/</a> in the repository, with its own <a href="https://github.com/ebremer/lws-client/blob/main/csharp/README.md">README</a>.')}
`,
};
