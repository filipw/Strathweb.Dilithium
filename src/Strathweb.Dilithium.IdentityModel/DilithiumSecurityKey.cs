using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Security;

namespace Strathweb.Dilithium.IdentityModel;

public class DilithiumSecurityKey : AsymmetricSecurityKey
{
    private readonly string _keyId;

    /// <summary>
    /// Create a new Dilithium key pair in memory and init public and private keys
    /// </summary>
    /// <param name="algorithm">Supported algorithms: CRYDI2, CRYDI3 and CRYDI5</param>
    /// <exception cref="ArgumentNullException"></exception>
    public DilithiumSecurityKey(string algorithm)
    {
        if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
        if (algorithm != "CRYDI2" && algorithm != "CRYDI3" && algorithm != "CRYDI5")
        {
            throw new NotSupportedException(
                $"Algorithm {algorithm} is not supported. Supported algorithms: CRYDI2, CRYDI3 and CRYDI5.");
        }

        SupportedAlgorithm = algorithm;

        var dilithiumParameters = GetDilithiumParameters(algorithm);
        var random = new SecureRandom();
        var keyGenParameters = new DilithiumKeyGenerationParameters(random, dilithiumParameters);
        var dilithiumKeyPairGenerator = new DilithiumKeyPairGenerator();
        dilithiumKeyPairGenerator.Init(keyGenParameters);

        var keyPair = dilithiumKeyPairGenerator.GenerateKeyPair();

        PublicKey = (DilithiumPublicKeyParameters)keyPair.Public;
        PrivateKey = (DilithiumPrivateKeyParameters)keyPair.Private;
        _keyId = BitConverter.ToString(SecureRandom.GetNextBytes(random, 16)).Replace("-", "");
        CryptoProviderFactory = new DilithiumCryptoProviderFactory();
    }

    /// <summary>
    /// Create a key from JSON Web Key representation.
    /// X property is mandatory and will be used to init public key.
    /// If the key contains D property, it will be used to init private key.
    /// </summary>
    /// <param name="jsonWebKey">Supported algorithms: CRYDI2, CRYDI3 and CRYDI5</param>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public DilithiumSecurityKey(JsonWebKey jsonWebKey)
    {
        if (jsonWebKey == null) throw new ArgumentNullException(nameof(jsonWebKey));
        if (jsonWebKey.X == null) throw new ArgumentException("X parameter (public key) is missing!");
        if (jsonWebKey.Alg == null) throw new ArgumentException("Alg parameter is missing!");
        if (jsonWebKey.Alg != "CRYDI2" && jsonWebKey.Alg != "CRYDI3" && jsonWebKey.Alg != "CRYDI5")
        {
            throw new NotSupportedException(
                $"Algorithm {jsonWebKey.Alg} is not supported. Supported algorithms: CRYDI2, CRYDI3 and CRYDI5.");
        }

        SupportedAlgorithm = jsonWebKey.Alg;

        var dilithiumParameters = GetDilithiumParameters(jsonWebKey.Alg);
        PublicKey = new DilithiumPublicKeyParameters(dilithiumParameters, Base64UrlEncoder.DecodeBytes(jsonWebKey.X));

        if (jsonWebKey.D != null)
        {
            PrivateKey =
                GetPrivateKeyParametersFromEncodedKey(dilithiumParameters, Base64UrlEncoder.DecodeBytes(jsonWebKey.D));
        }

        _keyId = jsonWebKey.KeyId;
        KeySize = jsonWebKey.KeySize;
        CryptoProviderFactory = new DilithiumCryptoProviderFactory();
    }

    /// <summary>
    /// Load a key from byte representation of public and an optional private key.
    /// </summary>
    /// <param name="algorithm">Supported algorithms: CRYDI2, CRYDI3 and CRYDI5</param>
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
        if (algorithm != "CRYDI2" && algorithm != "CRYDI3" && algorithm != "CRYDI5")
        {
            throw new NotSupportedException(
                $"Algorithm {algorithm} is not supported. Supported algorithms: CRYDI2, CRYDI3 and CRYDI5.");
        }

        SupportedAlgorithm = algorithm;

        var dilithiumParameters = GetDilithiumParameters(algorithm);
        PublicKey = new DilithiumPublicKeyParameters(dilithiumParameters, publicKey);

        if (privateKey != null)
        {
            PrivateKey = GetPrivateKeyParametersFromEncodedKey(dilithiumParameters, privateKey);
        }

        _keyId = keyId;
        CryptoProviderFactory = new DilithiumCryptoProviderFactory();
    }

    public DilithiumPublicKeyParameters PublicKey { get; set; }

    public DilithiumPrivateKeyParameters? PrivateKey { get; set; }

    public override int KeySize { get; }

    public string SupportedAlgorithm { get; }

    public override string KeyId => _keyId;

    public override bool IsSupportedAlgorithm(string algorithm) => SupportedAlgorithm == algorithm;

    private DilithiumParameters GetDilithiumParameters(string algorithm)
    {
        if (algorithm == "CRYDI2") return DilithiumParameters.Dilithium2;
        if (algorithm == "CRYDI3") return DilithiumParameters.Dilithium3;
        if (algorithm == "CRYDI5") return DilithiumParameters.Dilithium5;

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
            Kty = "MLWE",
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

    // based on https://github.com/bcgit/bc-csharp/blob/release-2.4.0/crypto/src/pqc/crypto/crystals/dilithium/DilithiumPrivateKeyParameters.cs
    private DilithiumPrivateKeyParameters GetPrivateKeyParametersFromEncodedKey(DilithiumParameters dilithiumParameters,
        byte[] encodedPrivateKey)
    {
        const int SeedBytes = 32;
        const int TrBytes = 64;
        //const int PolyT1PackedBytes = 320; // not used here but listed for completeness
        const int PolyT0PackedBytes = 416;

        int K, L, PolyEtaPackedBytes;

        // Set parameters based on the Dilithium mode
        if (dilithiumParameters == DilithiumParameters.Dilithium2)
        {
            K = 4;
            L = 4;
            PolyEtaPackedBytes = 96;
        }
        else if (dilithiumParameters == DilithiumParameters.Dilithium3)
        {
            K = 6;
            L = 5;
            PolyEtaPackedBytes = 128;
        }
        else if (dilithiumParameters == DilithiumParameters.Dilithium5)
        {
            K = 8;
            L = 7;
            PolyEtaPackedBytes = 96;
        }
        else
        {
            throw new NotSupportedException("Unsupported mode");
        }

        // calculate the lengths based on the parameters
        var s1Length = L * PolyEtaPackedBytes;
        var s2Length = K * PolyEtaPackedBytes;
        var t0Length = K * PolyT0PackedBytes;

        var rho = new byte[SeedBytes];
        var k = new byte[SeedBytes];
        var tr = new byte[TrBytes];
        var s1 = new byte[s1Length];
        var s2 = new byte[s2Length];
        var t0 = new byte[t0Length];

        // copy the respective parts of the encoded private key
        var offset = 0;
        Array.Copy(encodedPrivateKey, offset, rho, 0, SeedBytes);
        offset += SeedBytes;
        Array.Copy(encodedPrivateKey, offset, k, 0, SeedBytes);
        offset += SeedBytes;
        Array.Copy(encodedPrivateKey, offset, tr, 0, TrBytes);
        offset += TrBytes;
        Array.Copy(encodedPrivateKey, offset, s1, 0, s1Length);
        offset += s1Length;
        Array.Copy(encodedPrivateKey, offset, s2, 0, s2Length);
        offset += s2Length;
        Array.Copy(encodedPrivateKey, offset, t0, 0, t0Length);
        offset += t0Length;

        // handle t1 with the remaining bytes
        var remainingLength = encodedPrivateKey.Length - offset;
        var t1 = new byte[remainingLength];
        Array.Copy(encodedPrivateKey, offset, t1, 0, remainingLength);

        return new DilithiumPrivateKeyParameters(dilithiumParameters, rho, k, tr, s1, s2, t0, t1);
    }
}