// SPDX-License-Identifier: MIT
package com.ebremer.lws.auth;

import java.net.URI;

/**
 * Where a subject token will be presented.
 *
 * @param issuer the authorization server issuer — the audience for self-signed tokens
 * @param storage the storage the access token is requested for (the token request's {@code resource}; the
 *     {@code realm} of a challenge of the drafts before 19 October 2026)
 * @param metadata the authorization server metadata
 */
public record CredentialContext(URI issuer, URI storage, AuthorizationServerMetadata metadata) {}
