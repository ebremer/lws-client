// SPDX-License-Identifier: MIT
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ebremer.Lws.Internal;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Ebremer.Lws.Auth;

/// <summary>
/// A public key that verifies signatures: ECDSA on P-256 (<c>ES256</c>) or P-384 (<c>ES384</c>), or Ed25519
/// (<c>EdDSA</c>). ECDSA signatures are the raw <c>r‖s</c> concatenation (JOSE and RFC 9421), never DER.
/// </summary>
public abstract class VerificationKey
{
    private protected VerificationKey()
    {
    }

    /// <summary>The JOSE algorithm: <c>ES256</c>, <c>ES384</c> or <c>EdDSA</c>.</summary>
    public abstract string Algorithm { get; }

    /// <summary>The JWK key type: <c>EC</c> or <c>OKP</c>.</summary>
    public abstract string KeyType { get; }

    /// <summary>The JWK curve: <c>P-256</c>, <c>P-384</c> or <c>Ed25519</c>.</summary>
    public abstract string Curve { get; }

    /// <summary>Verifies a signature over <paramref name="data"/>.</summary>
    /// <param name="data">The signed bytes.</param>
    /// <param name="signature">The signature (raw <c>r‖s</c> for ECDSA).</param>
    /// <returns>Whether it verifies.</returns>
    public abstract bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

    /// <summary>The public JWK (a new, mutable object).</summary>
    /// <returns>The JWK.</returns>
    public abstract JsonObject ToJwk();

    /// <summary>Imports a public JWK (<c>EC</c> P-256 / P-384, <c>OKP</c> Ed25519); private members are ignored.</summary>
    /// <param name="jwk">The JWK.</param>
    /// <returns>The key.</returns>
    /// <exception cref="ArgumentException">The JWK is malformed or of an unsupported type.</exception>
    public static VerificationKey FromJwk(JsonElement jwk)
    {
        if (jwk.ValueKind != JsonValueKind.Object) throw new ArgumentException("A JWK must be a JSON object", nameof(jwk));
        string kty = LwsJson.GetString(jwk, "kty") ?? throw new ArgumentException("JWK member 'kty' is missing", nameof(jwk));
        string crv = LwsJson.GetString(jwk, "crv") ?? throw new ArgumentException("JWK member 'crv' is missing", nameof(jwk));
        return kty switch
        {
            "EC" => new EcVerificationKey(Jwk.EcParameters(jwk, crv, includePrivate: false), crv),
            "OKP" when crv == "Ed25519" => new Ed25519VerificationKey(Jwk.Member(jwk, "x", 32)),
            "OKP" => throw new ArgumentException($"Unsupported OKP curve: {crv}", nameof(jwk)),
            _ => throw new ArgumentException($"Unsupported JWK kty: {kty}", nameof(jwk)),
        };
    }

    /// <summary>Imports a public JWK.</summary>
    /// <param name="jwk">The JWK.</param>
    /// <returns>The key.</returns>
    /// <exception cref="ArgumentException">The JWK is malformed or of an unsupported type.</exception>
    public static VerificationKey FromJwk(JsonNode jwk) => FromJwk(LwsJson.ToElement(jwk ?? throw new ArgumentNullException(nameof(jwk))));

    /// <inheritdoc/>
    public override string ToString() => $"{Algorithm} public key";
}

/// <summary>
/// A private key that signs JWT credentials: ECDSA P-256 (<c>ES256</c>) with the BCL, or Ed25519 (<c>EdDSA</c>)
/// with BouncyCastle. Generate one with <see cref="GenerateP256"/> / <see cref="GenerateEd25519"/>, or import a JWK.
/// </summary>
public abstract class SigningKey
{
    private protected SigningKey()
    {
    }

    /// <summary>The JOSE algorithm: <c>ES256</c>, <c>ES384</c> or <c>EdDSA</c>.</summary>
    public abstract string Algorithm { get; }

    /// <summary>The matching public key.</summary>
    public abstract VerificationKey PublicKey { get; }

    /// <summary>Signs <paramref name="data"/> (ECDSA signatures are raw <c>r‖s</c>).</summary>
    /// <param name="data">The bytes to sign.</param>
    /// <returns>The signature.</returns>
    public abstract byte[] Sign(ReadOnlySpan<byte> data);

    /// <summary>The private JWK, including <c>d</c> (a new, mutable object). Keep it secret.</summary>
    /// <returns>The JWK.</returns>
    public abstract JsonObject ToJwk();

    /// <summary>Generates a P-256 key (<c>ES256</c>).</summary>
    /// <returns>The key.</returns>
    public static SigningKey GenerateP256()
    {
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new EcSigningKey(ec.ExportParameters(true), "P-256");
    }

    /// <summary>Generates an Ed25519 key (<c>EdDSA</c>).</summary>
    /// <returns>The key.</returns>
    public static SigningKey GenerateEd25519() => new Ed25519SigningKey(RandomNumberGenerator.GetBytes(32));

    /// <summary>Generates a key for a JOSE algorithm: <c>ES256</c> or <c>EdDSA</c>.</summary>
    /// <param name="algorithm">The algorithm.</param>
    /// <returns>The key.</returns>
    /// <exception cref="ArgumentException">The algorithm is not supported.</exception>
    public static SigningKey Generate(string algorithm) => algorithm switch
    {
        "ES256" => GenerateP256(),
        "EdDSA" or "Ed25519" => GenerateEd25519(),
        _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}", nameof(algorithm)),
    };

    /// <summary>Wraps a BCL ECDSA key (P-256 or P-384) with its private part.</summary>
    /// <param name="key">The key.</param>
    /// <returns>The signing key.</returns>
    public static SigningKey FromECDsa(ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        ECParameters p = key.ExportParameters(true);
        string crv = Jwk.CurveName(p.Curve, key.KeySize);
        return new EcSigningKey(p, crv);
    }

    /// <summary>Imports a private JWK (<c>EC</c> P-256 / P-384 or <c>OKP</c> Ed25519, with <c>d</c>).</summary>
    /// <param name="jwk">The JWK.</param>
    /// <returns>The key.</returns>
    /// <exception cref="ArgumentException">The JWK is malformed, public only, or of an unsupported type.</exception>
    public static SigningKey FromJwk(JsonElement jwk)
    {
        if (jwk.ValueKind != JsonValueKind.Object) throw new ArgumentException("A JWK must be a JSON object", nameof(jwk));
        if (LwsJson.GetString(jwk, "d") is null) throw new ArgumentException("The JWK has no private key member 'd'", nameof(jwk));
        string kty = LwsJson.GetString(jwk, "kty") ?? throw new ArgumentException("JWK member 'kty' is missing", nameof(jwk));
        string crv = LwsJson.GetString(jwk, "crv") ?? throw new ArgumentException("JWK member 'crv' is missing", nameof(jwk));
        switch (kty)
        {
            case "EC":
                return new EcSigningKey(Jwk.EcParameters(jwk, crv, includePrivate: true), crv);
            case "OKP" when crv == "Ed25519":
                {
                    var key = new Ed25519SigningKey(Jwk.Member(jwk, "d", 32));
                    if (LwsJson.GetString(jwk, "x") is not null
                        && !key.PublicBytes.AsSpan().SequenceEqual(Jwk.Member(jwk, "x", 32)))
                    {
                        throw new ArgumentException("The Ed25519 JWK's 'x' does not match its 'd'", nameof(jwk));
                    }
                    return key;
                }
            case "OKP":
                throw new ArgumentException($"Unsupported OKP curve: {crv}", nameof(jwk));
            default:
                throw new ArgumentException($"Unsupported private JWK kty: {kty}", nameof(jwk));
        }
    }

    /// <summary>Imports a private JWK.</summary>
    /// <param name="jwk">The JWK.</param>
    /// <returns>The key.</returns>
    /// <exception cref="ArgumentException">The JWK is malformed, public only, or of an unsupported type.</exception>
    public static SigningKey FromJwk(JsonNode jwk) => FromJwk(LwsJson.ToElement(jwk ?? throw new ArgumentNullException(nameof(jwk))));

    /// <inheritdoc/>
    public override string ToString() => $"{Algorithm} private key";
}

internal sealed class EcVerificationKey : VerificationKey
{
    private readonly ECParameters _parameters;

    public EcVerificationKey(ECParameters parameters, string curve)
    {
        _parameters = new ECParameters { Curve = parameters.Curve, Q = parameters.Q };
        Curve = curve;
        using ECDsa ec = Create();
    }

    public override string Algorithm => Curve == "P-384" ? "ES384" : "ES256";

    public override string KeyType => "EC";

    public override string Curve { get; }

    internal byte[] X => _parameters.Q.X!;

    internal byte[] Y => _parameters.Q.Y!;

    private ECDsa Create()
    {
        try
        {
            return ECDsa.Create(_parameters);
        }
        catch (CryptographicException e)
        {
            throw new ArgumentException($"Invalid {Curve} public key: {e.Message}", e);
        }
    }

    public override bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        using ECDsa ec = Create();
        HashAlgorithmName hash = Curve == "P-384" ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
        return ec.VerifyData(data, signature, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    public override JsonObject ToJwk() => new()
    {
        ["kty"] = "EC",
        ["crv"] = Curve,
        ["x"] = Base64Url.EncodeToString(X),
        ["y"] = Base64Url.EncodeToString(Y),
    };
}

internal sealed class EcSigningKey : SigningKey
{
    private readonly ECParameters _parameters;
    private readonly EcVerificationKey _public;
    private readonly string _curve;

    public EcSigningKey(ECParameters parameters, string curve)
    {
        if (curve is not ("P-256" or "P-384")) throw new ArgumentException($"Unsupported EC curve for signing: {curve}", nameof(curve));
        _curve = curve;
        try
        {
            using ECDsa ec = ECDsa.Create(parameters);
            _parameters = ec.ExportParameters(true);
        }
        catch (CryptographicException e)
        {
            throw new ArgumentException($"Invalid {curve} private key: {e.Message}", e);
        }
        _public = new EcVerificationKey(_parameters, curve);
    }

    public override string Algorithm => _curve == "P-384" ? "ES384" : "ES256";

    public override VerificationKey PublicKey => _public;

    public override byte[] Sign(ReadOnlySpan<byte> data)
    {
        using ECDsa ec = ECDsa.Create(_parameters);
        HashAlgorithmName hash = _curve == "P-384" ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
        return ec.SignData(data, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    public override JsonObject ToJwk()
    {
        JsonObject jwk = _public.ToJwk();
        jwk["d"] = Base64Url.EncodeToString(_parameters.D!);
        return jwk;
    }
}

internal sealed class Ed25519VerificationKey : VerificationKey
{
    private readonly Ed25519PublicKeyParameters _key;

    public Ed25519VerificationKey(byte[] publicKey)
    {
        if (publicKey.Length != 32) throw new ArgumentException("An Ed25519 public key is 32 bytes", nameof(publicKey));
        RawBytes = (byte[])publicKey.Clone();
        _key = new Ed25519PublicKeyParameters(RawBytes, 0);
    }

    internal byte[] RawBytes { get; }

    public override string Algorithm => "EdDSA";

    public override string KeyType => "OKP";

    public override string Curve => "Ed25519";

    public override bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        if (signature.Length != 64) return false;
        var verifier = new Ed25519Signer();
        verifier.Init(false, _key);
        byte[] message = data.ToArray();
        verifier.BlockUpdate(message, 0, message.Length);
        return verifier.VerifySignature(signature.ToArray());
    }

    public override JsonObject ToJwk() => new()
    {
        ["kty"] = "OKP",
        ["crv"] = "Ed25519",
        ["x"] = Base64Url.EncodeToString(RawBytes),
    };
}

internal sealed class Ed25519SigningKey : SigningKey
{
    private readonly Ed25519PrivateKeyParameters _key;
    private readonly byte[] _seed;
    private readonly Ed25519VerificationKey _public;

    public Ed25519SigningKey(byte[] seed)
    {
        if (seed.Length != 32) throw new ArgumentException("An Ed25519 private key is 32 bytes", nameof(seed));
        _seed = (byte[])seed.Clone();
        _key = new Ed25519PrivateKeyParameters(_seed, 0);
        PublicBytes = _key.GeneratePublicKey().GetEncoded();
        _public = new Ed25519VerificationKey(PublicBytes);
    }

    internal byte[] PublicBytes { get; }

    public override string Algorithm => "EdDSA";

    public override VerificationKey PublicKey => _public;

    public override byte[] Sign(ReadOnlySpan<byte> data)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, _key);
        byte[] message = data.ToArray();
        signer.BlockUpdate(message, 0, message.Length);
        return signer.GenerateSignature();
    }

    public override JsonObject ToJwk()
    {
        JsonObject jwk = _public.ToJwk();
        jwk["d"] = Base64Url.EncodeToString(_seed);
        return jwk;
    }
}

/// <summary>JSON Web Key (RFC 7517) helpers for EC (P-256, P-384) and OKP (Ed25519) keys.</summary>
public static class Jwk
{
    /// <summary>Imports a public JWK; same as <see cref="VerificationKey.FromJwk(JsonElement)"/>.</summary>
    /// <param name="jwk">The JWK.</param>
    /// <returns>The key.</returns>
    public static VerificationKey ToPublicKey(JsonElement jwk) => VerificationKey.FromJwk(jwk);

    /// <summary>Imports a private JWK; same as <see cref="SigningKey.FromJwk(JsonElement)"/>.</summary>
    /// <param name="jwk">The JWK.</param>
    /// <returns>The key.</returns>
    public static SigningKey ToSigningKey(JsonElement jwk) => SigningKey.FromJwk(jwk);

    /// <summary>The public JWK of a key.</summary>
    /// <param name="key">The key.</param>
    /// <returns>The JWK.</returns>
    public static JsonObject FromPublicKey(VerificationKey key) => (key ?? throw new ArgumentNullException(nameof(key))).ToJwk();

    /// <summary>The private JWK of a key (including <c>d</c>).</summary>
    /// <param name="key">The key.</param>
    /// <returns>The JWK.</returns>
    public static JsonObject FromSigningKey(SigningKey key) => (key ?? throw new ArgumentNullException(nameof(key))).ToJwk();

    internal static byte[] Member(JsonElement jwk, string name, int size)
    {
        string v = LwsJson.GetString(jwk, name) ?? throw new ArgumentException($"JWK member '{name}' is missing");
        byte[] bytes;
        try
        {
            bytes = Base64Url.DecodeFromChars(v);
        }
        catch (FormatException e)
        {
            throw new ArgumentException($"JWK member '{name}' is not base64url", e);
        }
        if (bytes.Length == size) return bytes;
        if (bytes.Length > size || bytes.Length == 0) throw new ArgumentException($"JWK member '{name}' has the wrong length");
        byte[] padded = new byte[size];
        bytes.CopyTo(padded, size - bytes.Length);
        return padded;
    }

    internal static ECParameters EcParameters(JsonElement jwk, string crv, bool includePrivate)
    {
        (ECCurve curve, int size) = crv switch
        {
            "P-256" => (ECCurve.NamedCurves.nistP256, 32),
            "P-384" => (ECCurve.NamedCurves.nistP384, 48),
            _ => throw new ArgumentException($"Unsupported EC curve: {crv}"),
        };
        var p = new ECParameters
        {
            Curve = curve,
            Q = new ECPoint { X = Member(jwk, "x", size), Y = Member(jwk, "y", size) },
        };
        if (includePrivate) p.D = Member(jwk, "d", size);
        return p;
    }

    internal static string CurveName(ECCurve curve, int keySize) => keySize switch
    {
        256 => "P-256",
        384 => "P-384",
        _ => throw new ArgumentException($"Unsupported EC curve ({curve.Oid?.FriendlyName ?? keySize.ToString(System.Globalization.CultureInfo.InvariantCulture)})"),
    };
}
