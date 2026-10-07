// SPDX-License-Identifier: MIT
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Ebremer.Lws.Auth;

/// <summary>
/// <c>did:key</c> identifiers for P-256 and Ed25519 public keys: <c>did:key:</c> + multibase base58btc (<c>z</c>) of
/// the multicodec varint prefix and the public key (P-256 as a 33-byte compressed point). P-256 identifiers start
/// with <c>zDn</c>, Ed25519 identifiers with <c>z6Mk</c>.
/// </summary>
public static class DidKey
{
    private const string Prefix = "did:key:";
    private static readonly byte[] P256Prefix = [0x80, 0x24];
    private static readonly byte[] Ed25519Prefix = [0xed, 0x01];

    private static readonly BigInteger P256P = BigInteger.Parse("0ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);
    private static readonly BigInteger P256B = BigInteger.Parse("05ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>The <c>did:key</c> identifier of a P-256 or Ed25519 public key.</summary>
    /// <param name="key">The public key.</param>
    /// <returns>The DID.</returns>
    /// <exception cref="ArgumentException">The key is neither P-256 nor Ed25519.</exception>
    public static string FromPublicKey(VerificationKey key) => Prefix + Multibase(key);

    /// <summary>The <c>did:key</c> identifier of a public JWK.</summary>
    /// <param name="publicJwk">The JWK.</param>
    /// <returns>The DID.</returns>
    public static string FromJwk(JsonElement publicJwk) => FromPublicKey(VerificationKey.FromJwk(publicJwk));

    /// <summary>The verification method id (<c>did:key:z…#z…</c>) of a key, used as the JWT <c>kid</c>.</summary>
    /// <param name="key">The public key.</param>
    /// <returns>The key id.</returns>
    public static string KeyId(VerificationKey key)
    {
        string mb = Multibase(key);
        return Prefix + mb + "#" + mb;
    }

    /// <summary>The verification method id of an existing <c>did:key</c> identifier.</summary>
    /// <param name="did">The DID (a fragment is ignored).</param>
    /// <returns>The key id.</returns>
    /// <exception cref="ArgumentException">The value is not a did:key.</exception>
    public static string KeyId(string did)
    {
        string mb = MultibaseOf(did);
        return Prefix + mb + "#" + mb;
    }

    /// <summary>Decodes a <c>did:key</c> (or its key id) into the public key.</summary>
    /// <param name="did">The DID.</param>
    /// <returns>The public key.</returns>
    /// <exception cref="ArgumentException">The value is not a supported did:key.</exception>
    public static VerificationKey ToPublicKey(string did)
    {
        string mb = MultibaseOf(did);
        if (!mb.StartsWith('z')) throw new ArgumentException($"Not a base58btc did:key: {did}", nameof(did));
        byte[] bytes = Base58.Decode(mb[1..]);
        if (bytes.AsSpan().StartsWith(Ed25519Prefix) && bytes.Length == 34) return new Ed25519VerificationKey(bytes[2..]);
        if (bytes.AsSpan().StartsWith(P256Prefix) && bytes.Length == 35 && bytes[2] is 0x02 or 0x03)
        {
            byte[] xBytes = bytes[3..];
            var x = new BigInteger(xBytes, isUnsigned: true, isBigEndian: true);
            BigInteger rhs = Mod(BigInteger.Pow(x, 3) - (3 * x) + P256B, P256P);
            BigInteger y = BigInteger.ModPow(rhs, (P256P + 1) / 4, P256P);
            if (Mod(y * y, P256P) != rhs) throw new ArgumentException("Invalid P-256 point in did:key", nameof(did));
            bool odd = bytes[2] == 0x03;
            if (!y.IsEven != odd) y = P256P - y;
            var q = new ECPoint { X = xBytes, Y = Fixed(y, 32) };
            return new EcVerificationKey(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = q }, "P-256");
        }
        throw new ArgumentException($"Unsupported did:key key type: {did}", nameof(did));
    }

    private static string MultibaseOf(string did)
    {
        ArgumentNullException.ThrowIfNull(did);
        if (!did.StartsWith(Prefix, StringComparison.Ordinal)) throw new ArgumentException($"Not a did:key: {did}", nameof(did));
        string mb = did[Prefix.Length..];
        int hash = mb.IndexOf('#', StringComparison.Ordinal);
        return hash >= 0 ? mb[..hash] : mb;
    }

    private static string Multibase(VerificationKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        byte[] data = key switch
        {
            EcVerificationKey ec when ec.Curve == "P-256" =>
                [.. P256Prefix, (byte)((ec.Y[^1] & 1) == 1 ? 0x03 : 0x02), .. ec.X],
            Ed25519VerificationKey ed => [.. Ed25519Prefix, .. ed.RawBytes],
            _ => throw new ArgumentException($"did:key supports P-256 and Ed25519 keys, not {key.Curve}", nameof(key)),
        };
        return "z" + Base58.Encode(data);
    }

    private static BigInteger Mod(BigInteger a, BigInteger m)
    {
        BigInteger r = a % m;
        return r.Sign < 0 ? r + m : r;
    }

    private static byte[] Fixed(BigInteger v, int size)
    {
        byte[] b = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (b.Length == size) return b;
        byte[] output = new byte[size];
        b.CopyTo(output, size - b.Length);
        return output;
    }
}

/// <summary>Base58 with the Bitcoin alphabet (used by multibase <c>z</c>).</summary>
internal static class Base58
{
    private const string Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        var n = new BigInteger(data, isUnsigned: true, isBigEndian: true);
        var sb = new StringBuilder();
        while (n.Sign > 0)
        {
            n = BigInteger.DivRem(n, 58, out BigInteger rem);
            sb.Append(Alphabet[(int)rem]);
        }
        foreach (byte b in data)
        {
            if (b != 0) break;
            sb.Append('1');
        }
        char[] chars = sb.ToString().ToCharArray();
        Array.Reverse(chars);
        return new string(chars);
    }

    public static byte[] Decode(string s)
    {
        BigInteger n = BigInteger.Zero;
        foreach (char c in s)
        {
            int d = Alphabet.IndexOf(c, StringComparison.Ordinal);
            if (d < 0) throw new ArgumentException("Invalid base58 character", nameof(s));
            n = (n * 58) + d;
        }
        byte[] raw = n.Sign == 0 ? [] : n.ToByteArray(isUnsigned: true, isBigEndian: true);
        int zeros = 0;
        while (zeros < s.Length && s[zeros] == '1') zeros++;
        byte[] output = new byte[zeros + raw.Length];
        raw.CopyTo(output, zeros);
        return output;
    }
}

/// <summary>
/// Builds the W3C Controlled Identifier (CID) document an agent publishes at its identifier URL, so that
/// authorization servers can validate its self-signed credentials (<c>lws10-authn-ssi-cid</c>).
/// </summary>
public static class ControlledIdentifierDocument
{
    /// <summary>
    /// A CID document with one <c>JsonWebKey</c> verification method in the <c>authentication</c> relationship. The
    /// method id is <c>agent#kid</c>, or <paramref name="kid"/> itself when it already is a URI.
    /// </summary>
    /// <param name="agent">The agent identifier (the document's <c>id</c>).</param>
    /// <param name="key">The agent's public key.</param>
    /// <param name="kid">The key id.</param>
    /// <returns>The document.</returns>
    public static JsonObject Create(string agent, VerificationKey key, string kid) =>
        Create(agent, Internal.LwsJson.ToElement((key ?? throw new ArgumentNullException(nameof(key))).ToJwk()), kid);

    /// <summary>Like <see cref="Create(string, VerificationKey, string)"/> for a public JWK.</summary>
    /// <param name="agent">The agent identifier.</param>
    /// <param name="publicJwk">The public JWK (a <c>d</c> member is dropped).</param>
    /// <param name="kid">The key id.</param>
    /// <returns>The document.</returns>
    public static JsonObject Create(string agent, JsonElement publicJwk, string kid)
    {
        ArgumentNullException.ThrowIfNull(agent);
        ArgumentNullException.ThrowIfNull(kid);
        if (publicJwk.ValueKind != JsonValueKind.Object) throw new ArgumentException("The JWK must be an object", nameof(publicJwk));
        var jwk = (JsonObject)Internal.LwsJson.ToNode(publicJwk)!;
        jwk.Remove("d");
        jwk["kid"] = kid;
        if (!jwk.ContainsKey("alg"))
        {
            string kty = Internal.LwsJson.GetString(publicJwk, "kty") ?? "";
            string crv = Internal.LwsJson.GetString(publicJwk, "crv") ?? "";
            jwk["alg"] = kty == "OKP" ? "EdDSA" : crv == "P-384" ? "ES384" : "ES256";
        }
        string methodId = kid.Contains(':', StringComparison.Ordinal) ? kid : agent + "#" + kid;
        return new JsonObject
        {
            ["@context"] = new JsonArray(Lws.CidContext),
            ["id"] = agent,
            ["authentication"] = new JsonArray(new JsonObject
            {
                ["id"] = methodId,
                ["type"] = "JsonWebKey",
                ["controller"] = agent,
                ["publicKeyJwk"] = jwk,
            }),
        };
    }

    /// <summary>Like <see cref="Create(string, VerificationKey, string)"/> for a URL agent.</summary>
    /// <param name="agent">The agent identifier.</param>
    /// <param name="key">The agent's public key.</param>
    /// <param name="kid">The key id.</param>
    /// <returns>The document.</returns>
    public static JsonObject Create(Uri agent, VerificationKey key, string kid) =>
        Create(Internal.Uris.ToText(agent ?? throw new ArgumentNullException(nameof(agent))), key, kid);
}
