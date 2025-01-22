using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Security;

namespace Strathweb.Dilithium.IdentityModel;

public class DilithiumSecurityKey : AsymmetricSecurityKey
{
    private readonly string _keyId;

    /// <summary>
    /// Create a new Dilithium key pair in memory and init public and private keys
    /// </summary>
    /// <param name="algorithm">Supported algorithms: ML-DSA-44, ML-DSA-65 and ML-DSA-87</param>
    /// <exception cref="ArgumentNullException"></exception>
    public DilithiumSecurityKey(string algorithm)
    {
        if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
        if (algorithm != "ML-DSA-44" && algorithm != "ML-DSA-65" && algorithm != "ML-DSA-87")
        {
            throw new NotSupportedException(
                $"Algorithm {algorithm} is not supported. Supported algorithms: ML-DSA-44, ML-DSA-65 and ML-DSA-87.");
        }

        SupportedAlgorithm = algorithm;

        var dilithiumParameters = GetDilithiumParameters(algorithm);
        var random = new SecureRandom();
        var keyGenParameters = new MLDsaKeyGenerationParameters(random, dilithiumParameters);
        var dilithiumKeyPairGenerator = new MLDsaKeyPairGenerator();
        dilithiumKeyPairGenerator.Init(keyGenParameters);

        var keyPair = dilithiumKeyPairGenerator.GenerateKeyPair();

        PublicKey = (MLDsaPublicKeyParameters)keyPair.Public;
        PrivateKey = (MLDsaPrivateKeyParameters)keyPair.Private;
        _keyId = BitConverter.ToString(SecureRandom.GetNextBytes(random, 16)).Replace("-", "");
        CryptoProviderFactory = new DilithiumCryptoProviderFactory();
    }

    /// <summary>
    /// Create a key from JSON Web Key representation.
    /// X property is mandatory and will be used to init public key.
    /// If the key contains D property, it will be used to init private key.
    /// </summary>
    /// <param name="jsonWebKey">Supported algorithms: ML-DSA-44, ML-DSA-65 and ML-DSA-87</param>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public DilithiumSecurityKey(JsonWebKey jsonWebKey)
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

        var dilithiumParameters = GetDilithiumParameters(jsonWebKey.Alg);
        PublicKey = MLDsaPublicKeyParameters.FromEncoding(dilithiumParameters, Base64UrlEncoder.DecodeBytes(jsonWebKey.X));

        if (jsonWebKey.D != null)
        {
            PrivateKey = MLDsaPrivateKeyParameters.FromEncoding(dilithiumParameters, Base64UrlEncoder.DecodeBytes(jsonWebKey.D));
        }

        _keyId = jsonWebKey.KeyId;
        KeySize = jsonWebKey.KeySize;
        CryptoProviderFactory = new DilithiumCryptoProviderFactory();
    }

    /// <summary>
    /// Load a key from byte representation of public and an optional private key.
    /// </summary>
    /// <param name="algorithm">Supported algorithms: ML-DSA-44, ML-DSA-65 and ML-DSA-87</param>
    /// <param name="keyId"></param>
    /// <param name="publicKey">Byte encoded Dilithium public key.</param>
    /// <param name="privateKey">Byte encoded Dilithium private key (optional).</param>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="NotSupportedException"></exception>
    public DilithiumSecurityKey(string algorithm, string keyId, byte[] publicKey, byte[]? privateKey = null)
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

        var dilithiumParameters = GetDilithiumParameters(algorithm);
        PublicKey = MLDsaPublicKeyParameters.FromEncoding(dilithiumParameters, publicKey);

        if (privateKey != null)
        {
            PrivateKey = MLDsaPrivateKeyParameters.FromEncoding(dilithiumParameters, privateKey);
        }

        _keyId = keyId;
        CryptoProviderFactory = new DilithiumCryptoProviderFactory();
    }

    public MLDsaPublicKeyParameters PublicKey { get; set; }

    public MLDsaPrivateKeyParameters? PrivateKey { get; set; }

    public override int KeySize { get; }

    public string SupportedAlgorithm { get; }

    public override string KeyId => _keyId;

    public override bool IsSupportedAlgorithm(string algorithm) => SupportedAlgorithm == algorithm;

    private MLDsaParameters GetDilithiumParameters(string algorithm)
    {
        if (algorithm == "ML-DSA-44") return MLDsaParameters.ml_dsa_44;
        if (algorithm == "ML-DSA-65") return MLDsaParameters.ml_dsa_65;
        if (algorithm == "ML-DSA-87") return MLDsaParameters.ml_dsa_87;

        throw new NotSupportedException($"Unsupported algorithm type: '{algorithm}'");
    }

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
            X = Base64UrlEncoder.Encode(PublicKey.GetEncoded()),
            Alg = SupportedAlgorithm,
            Use = "sig"
        };

        if (includePrivateKey && PrivateKey != null)
        {
            jsonWebKey.D = Base64UrlEncoder.Encode(PrivateKey.GetEncoded());
        }

        return jsonWebKey;
    }
}