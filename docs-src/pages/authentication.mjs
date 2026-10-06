// SPDX-License-Identifier: MIT
import { callout, code, table, tabs } from "../lib.mjs";
import { S } from "../samples.mjs";

export default {
  path: "authentication.html",
  title: "Authentication",
  description: "Configure LWS authentication: the automatic 401 → OAuth 2.0 token exchange flow, OpenID Connect, SAML 2.0, self-signed did:key and controlled-identifier agents, bearer tokens and custom authenticators.",
  body: `
<h1>Authentication</h1>
<p class="lead">LWS separates identity from authorization. Your <em>credential provider</em> proves who you are.
The storage's authorization server exchanges that proof for a short-lived access token. The clients run
that exchange automatically whenever a storage answers <code>401</code>.</p>
<div id="toc" class="toc"></div>

<h2 id="model">The pieces</h2>
${table(
  ["Concept", "What it is", "Provided as"],
  [
    ["Authenticator", "Pluggable hook: adds credentials before a request, reacts to a 401", "<code>TokenExchangeAuthenticator</code>, <code>BearerTokenAuthenticator</code>, or your own"],
    ["Credential provider", "Produces an authentication credential (subject token) for an authorization server", "<code>OpenIdCredentials</code>, <code>SamlCredentials</code>, <code>SelfSignedCredentials</code>"],
    ["Authorization server (AS)", "Issues access tokens; metadata at <code>/.well-known/lws-configuration</code>", "Named by the storage's <code>WWW-Authenticate</code> challenge"],
    ["Access token", "RFC 9068 JWT with <code>aud</code> = the challenge's realm, valid for minutes", "Cached and reused by the authenticator"],
  ],
)}

<h2 id="flow">What happens on a 401</h2>
<p>See the <a href="concepts.html#auth">sequence diagram</a>. With a <code>TokenExchangeAuthenticator</code> configured, each client:</p>
<ol class="steps">
  <li>Parses <code>WWW-Authenticate: Bearer as_uri="…", realm="…"</code>. Without such a challenge, the
  <code>401</code> surfaces as an <em>unauthorized</em> error that carries the parsed challenges.</li>
  <li><strong>Checks the realm.</strong> The request URL must have the same scheme, host and port, and its path must equal the
  realm's path or sit below it at a <code>/</code> boundary. Otherwise it raises an authentication error and sends nothing.</li>
  <li><strong>Checks transport security.</strong> The AS and its token endpoint must use HTTPS unless they are on loopback
  (or <code>allowInsecureHttp</code> is set for testing). It also applies your optional <code>authorizationServerFilter</code>.</li>
  <li>Fetches the AS metadata (RFC 8414 path insertion) and checks that <code>issuer</code> equals <code>as_uri</code>, and that
  <code>subject_token_types_supported</code> (if present) accepts your credential type.</li>
  <li>Posts an RFC 8693 token exchange with <code>resource</code> = realm, <code>subject_token</code> and
  <code>subject_token_type</code>. OAuth errors become authentication errors carrying <code>error</code> and
  <code>error_description</code>.</li>
  <li>Caches the access token per (issuer, realm) until 30 s before it expires. Expiry comes from
  <code>expires_in</code>, else the JWT's <code>exp</code>, else 300 s. It then retries the original request once.</li>
</ol>
<p>Later requests inside the realm send the cached token straight away. A <code>401</code> with a cached token
discards it and runs the exchange once more. Concurrent requests share a single in-flight exchange.
Tokens are never sent to URLs outside their realm, including across redirects.</p>

<h2 id="self-signed">Self-signed identities</h2>
<p>Bots, server-side jobs and command-line tools usually hold their own key pair. With the self-signed
suite (<code>lws10-authn-ssi-cid</code>), the agent signs a short-lived JWT in which
<code>sub = iss = client_id = agent URI</code> and <code>aud</code> is the authorization server. The clients support
ES256 (P-256) and EdDSA (Ed25519). Signatures use the JOSE raw <code>r‖s</code> encoding, and each JWT carries a
<code>kid</code> and a random <code>jti</code>.</p>

<h3 id="did-key">did:key agents</h3>
<p>A <code>did:key</code> identifier is derived from the public key itself, so there is nothing to host. This is the
quickest way to get an identity. The trade-off is that you cannot rotate the key without changing the identity.</p>
${tabs(S["auth-didkey"])}

<h3 id="cid">HTTPS agents with a controlled identifier document</h3>
<p>To keep a stable identity across key rotations, give the agent an HTTPS URI and publish a
<a href="https://www.w3.org/TR/cid-1.0/">controlled identifier document</a> there. The authorization server
dereferences the agent URI and finds the verification key by the JWT's <code>kid</code>.</p>
${tabs(S["auth-cid"])}
${code("json", `
{
  "@context": ["https://www.w3.org/ns/cid/v1"],
  "id": "https://bot.example/agent",
  "authentication": [{
    "id": "https://bot.example/agent#key-1",
    "type": "JsonWebKey",
    "controller": "https://bot.example/agent",
    "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "kid": "key-1", "alg": "ES256" }
  }]
}`, { title: "https://bot.example/agent" })}

<h3 id="keys">Generating, persisting and importing keys</h3>
${tabs(S.keys)}
${callout("warn", "Protect private keys", " A private JWK or PEM is a long-lived credential. Keep it in a secret store, never in a repository. JavaScript keys are non-extractable unless you ask otherwise.")}

<h2 id="openid">OpenID Connect</h2>
<p>For people signing in through an OpenID provider, use any OIDC library for the login and hand the
<strong>ID token</strong> to <code>OpenIdCredentials</code>. It is sent as
<code>urn:ietf:params:oauth:token-type:id_token</code>. Pass a callback instead of a string to supply a fresh
token each time one is needed. For verifiers to trust the provider, the user's agent URI must resolve to a
controlled identifier document listing it:</p>
${code("json", `
{
  "@context": ["https://www.w3.org/ns/cid/v1"],
  "id": "https://id.example/alice",
  "service": [{ "type": "https://www.w3.org/ns/lws#OpenIdProvider", "serviceEndpoint": "https://openid.example" }]
}`)}
${tabs(S["auth-openid"])}

<h2 id="saml">SAML 2.0</h2>
<p><code>SamlCredentials</code> sends a signed assertion as <code>urn:ietf:params:oauth:token-type:saml2</code>,
base64url-encoded as RFC 8693 requires. Raw XML is encoded for you. Trust in SAML identity providers is
established out of band by the authorization server.</p>
${tabs(S["auth-saml"])}

<h2 id="bearer">Existing access tokens</h2>
<p>If you obtain access tokens yourself, <code>BearerTokenAuthenticator</code> sends them as
<code>Authorization: Bearer</code>. Give it the realm so the token never leaves that storage.</p>
${tabs(S["auth-bearer"])}

<h2 id="options">Options</h2>
${tabs(S["auth-options"])}
${table(
  ["Option", "Default", "Purpose"],
  [
    ["<code>allowInsecureHttp</code>", "<code>false</code>", "Permit <code>http://</code> authorization servers on non-loopback hosts (testing only)"],
    ["<code>authorizationServerFilter(asUri, realm)</code>", "allow all", "Refuse to send credentials to authorization servers you don't trust"],
    ["refresh skew / margin", "30 s", "How long before expiry a cached access token is replaced"],
    ["self-signed lifetime", "300 s", "Lifetime of each self-signed JWT credential"],
  ],
)}

<h2 id="custom">Custom authenticators</h2>
<p>Any scheme fits the two-method <code>Authenticator</code> interface: API keys, cookies, DPoP or mutual TLS
headers. <code>authorize</code> runs before every request, including redirected ones. <code>handleChallenge</code> runs
on a <code>401</code> and returns whether to retry once.</p>
${tabs(S["custom-authenticator"])}

<h2 id="security">Security considerations</h2>
<ul>
  <li><strong>A storage chooses the authorization server.</strong> Self-signed credentials are audience-bound
  to that server, so a malicious storage gains nothing from them. Static OpenID or SAML tokens may not be
  audience-restricted, so restrict them with <code>authorizationServerFilter</code> or obtain audience-restricted tokens.</li>
  <li><strong>Realm checks are not optional.</strong> They stop a server from collecting a token whose audience
  covers resources outside its own space.</li>
  <li><strong>Short lifetimes.</strong> Access tokens should live five minutes or less. Self-signed credentials
  default to five minutes and are cached per audience until shortly before expiry.</li>
  <li><strong>TLS everywhere.</strong> Bearer tokens and ID tokens grant access to whoever holds them.</li>
</ul>
`,
};
