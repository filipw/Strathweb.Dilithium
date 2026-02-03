using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Strathweb.Dilithium.IdentityModel;

public class MlDsaSecurityKey : AsymmetricSecurityKey
{
    private readonly string _keyId;

    /// <param name="algorithm">Supported algorithms: ML-DSA-44, ML-DSA-65 and ML-DSA-87</param>
    /// <param name="backend">PQC backend to use. Defaults to Maybe LibOQS.NET.</param>
    public MlDsaSecurityKey(string algorithm, IPqcBackend? backend = null)
    {
        if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
        if (algorithm != "ML-DSA-44" && algorithm != "ML-DSA-65" && algorithm != "ML-DSA-87")
        {
            throw new NotSupportedException(
                $"Algorithm {algorithm} is not supported. Supported algorithms: ML-DSA-44, ML-DSA-65 and ML-DSA-87.");
        }

        SupportedAlgorithm = algorithm;
        Backend = backend ?? new LibOqsPqcBackend();

        var (publicKey, privateKey) = Backend.GenerateKeyPair(algorithm);
        PublicKey = publicKey;
        PrivateKey = privateKey;

        _keyId = Guid.NewGuid().ToString("N");
        CryptoProviderFactory = new MlDsaCryptoProviderFactory();
    }

    /// <param name="jsonWebKey">Supported algorithms: ML-DSA-44, ML-DSA-65 and ML-DSA-87</param>
    /// <param name="backend">PQC backend to use. Defaults to Maybe LibOQS.NET.</param>
    public MlDsaSecurityKey(JsonWebKey jsonWebKey, IPqcBackend? backend = null)
    {
        if (jsonWebKey == null) throw new ArgumentNullException(nameof(jsonWebKey));
        if (jsonWebKey.X == null) throw new ArgumentException("X parameter (public key) is missing!");
        if (jsonWebKey.Alg == null) throw new ArgumentException("Alg parameter is missing!");
        if (jsonWebKey.Alg != "ML-DSA-44" && jsonWebKey.Alg != "ML-DSA-65" && jsonWebKey.Alg != "ML-DSA-87")
        {
            throw new NotSupportedException(
                $"Algorithm {jsonWebKey.Alg} is not supported. Supported algorithms: ML-DSA-44, ML-DSA-65 and ML-DSA-87.");
        }

        SupportedAlgorithm = jsonWebKey.Alg;
        Backend = backend ?? new LibOqsPqcBackend();

        PublicKey = Base64UrlEncoder.DecodeBytes(jsonWebKey.X);

        if (jsonWebKey.D != null)
        {
            PrivateKey = Base64UrlEncoder.DecodeBytes(jsonWebKey.D);
        }

        _keyId = jsonWebKey.KeyId;
        CryptoProviderFactory = new MlDsaCryptoProviderFactory();
    }

    /// <param name="algorithm">Supported algorithms: ML-DSA-44, ML-DSA-65 and ML-DSA-87</param>
    /// <param name="keyId"></param>
    /// <param name="publicKey">Byte encoded Dilithium public key.</param>
    /// <param name="privateKey">Byte encoded Dilithium private key (optional).</param>
    /// <param name="backend">PQC backend to use. Defaults to Maybe LibOQS.NET.</param>
    public MlDsaSecurityKey(string algorithm, string keyId, byte[] publicKey, byte[]? privateKey = null, IPqcBackend? backend = null)
    {
        if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
        if (keyId == null) throw new ArgumentNullException(nameof(keyId));
        if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
        if (algorithm != "ML-DSA-44" && algorithm != "ML-DSA-65" && algorithm != "ML-DSA-87")
        {
            throw new NotSupportedException(
                $"Algorithm {algorithm} is not supported. Supported algorithms: ML-DSA-44, ML-DSA-65 and ML-DSA-87.");
        }

        SupportedAlgorithm = algorithm;
        Backend = backend ?? new LibOqsPqcBackend();
        PublicKey = publicKey;

        if (privateKey != null)
        {
            PrivateKey = privateKey;
        }

        _keyId = keyId;
        CryptoProviderFactory = new MlDsaCryptoProviderFactory();
    }

    public byte[] PublicKey { get; set; }

    public byte[]? PrivateKey { get; set; }

    public IPqcBackend Backend { get; }

    public override int KeySize => PublicKey.Length * 8; // Approximation

    public string SupportedAlgorithm { get; }

    public override string KeyId => _keyId;

    public override bool IsSupportedAlgorithm(string algorithm) => SupportedAlgorithm == algorithm;

    [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus instead.")]
    public override bool HasPrivateKey => PrivateKey != null;

    public override PrivateKeyStatus PrivateKeyStatus =>
        PrivateKey == null ? PrivateKeyStatus.DoesNotExist : PrivateKeyStatus.Exists;

    public JsonWebKey ToJsonWebKey(bool includePrivateKey)
    {
        var jsonWebKey = new JsonWebKey
        {
            Kty = "AKP",
            Kid = KeyId,
            X = Base64UrlEncoder.Encode(PublicKey),
            Alg = SupportedAlgorithm,
            Use = "sig"
        };

        if (includePrivateKey && PrivateKey != null)
        {
            jsonWebKey.D = Base64UrlEncoder.Encode(PrivateKey);
        }

        return jsonWebKey;
    }
}