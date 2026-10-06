// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import java.net.URI;

/**
 * Where a subject token will be presented.
 *
 * @param issuer the authorization server issuer ({@code as_uri}) — the audience for self-signed tokens
 * @param realm the protection realm the access token is requested for
 * @param metadata the authorization server metadata
 */
public record CredentialContext(URI issuer, URI realm, AuthorizationServerMetadata metadata) {}
