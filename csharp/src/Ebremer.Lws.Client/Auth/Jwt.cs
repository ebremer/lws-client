// SPDX-License-Identifier: MIT
using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ebremer.Lws.Internal;

namespace Ebremer.Lws.Auth;

/// <summary>Compact JSON Web Signature helpers for JWT credentials (<c>ES256</c>, <c>ES384</c>, <c>EdDSA</c>).</summary>
public static class Jwt
{
    /// <summary>Signs <paramref name="claims"/>; the header's <c>alg</c> is set from the key.</summary>
    /// <param name="header">The JOSE header (copied).</param>
    /// <param name="claims">The claims.</param>
    /// <param name="key">The signing key.</param>
    /// <returns>The compact JWS.</returns>
    public static string Sign(JsonObject header, JsonObject claims, SigningKey key)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(key);
        var h = (JsonObject)header.DeepClone();
        h["alg"] = key.Algorithm;
        string input = Base64Url.EncodeToString(LwsJson.ToBytes(h)) + "." + Base64Url.EncodeToString(LwsJson.ToBytes(claims));
        byte[] signature = key.Sign(Encoding.ASCII.GetBytes(input));
        return input + "." + Base64Url.EncodeToString(signature);
    }

    /// <summary>
    /// Verifies the signature of a compact JWS with <paramref name="key"/>. The header <c>alg</c> must be the key's
    /// algorithm (never <c>none</c>).
    /// </summary>
    /// <param name="jwt">The token.</param>
    /// <param name="key">The public key.</param>
    /// <returns>Whether the signature verifies.</returns>
    public static bool Verify(string jwt, VerificationKey key)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(key);
        string[] parts = jwt.Split('.');
        if (parts.Length != 3) return false;
        try
        {
            if (LwsJson.GetString(DecodeHeader(jwt), "alg") != key.Algorithm) return false;
            byte[] signature = Base64Url.DecodeFromChars(parts[2]);
            return key.Verify(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), signature);
        }
        catch (Exception e) when (e is FormatException or ArgumentException or LwsException)
        {
            return false;
        }
    }

    /// <summary>Decodes the header without verifying.</summary>
    /// <param name="jwt">The token.</param>
    /// <returns>The header.</returns>
    /// <exception cref="ArgumentException">The value is not a JWT.</exception>
    public static JsonElement DecodeHeader(string jwt) => Part(jwt, 0);

    /// <summary>Decodes the claims without verifying.</summary>
    /// <param name="jwt">The token.</param>
    /// <returns>The claims.</returns>
    /// <exception cref="ArgumentException">The value is not a JWT.</exception>
    public static JsonElement DecodeClaims(string jwt) => Part(jwt, 1);

    /// <summary>The <c>exp</c> claim of a JWT, or null when the token is not a JWT or has none.</summary>
    /// <param name="token">The token.</param>
    /// <returns>The expiry.</returns>
    public static DateTimeOffset? Expiration(string token)
    {
        try
        {
            return LwsJson.GetLong(DecodeClaims(token), "exp") is { } exp ? DateTimeOffset.FromUnixTimeSeconds(exp) : null;
        }
        catch (Exception e) when (e is ArgumentException or FormatException)
        {
            return null;
        }
    }

    private static JsonElement Part(string jwt, int index)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        string[] parts = jwt.Split('.');
        if (parts.Length < 2) throw new ArgumentException("Not a JWT", nameof(jwt));
        byte[] bytes;
        try
        {
            bytes = Base64Url.DecodeFromChars(parts[index]);
        }
        catch (FormatException e)
        {
            throw new ArgumentException("Not a JWT: invalid base64url", nameof(jwt), e);
        }
        try
        {
            return LwsJson.RequireObject(LwsJson.Parse(bytes, "JWT part"), "JWT part");
        }
        catch (ProtocolException e)
        {
            throw new ArgumentException("Not a JWT: " + e.Message, nameof(jwt), e);
        }
    }
}
