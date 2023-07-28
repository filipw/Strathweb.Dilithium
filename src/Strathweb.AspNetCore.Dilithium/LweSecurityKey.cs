using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Security;

namespace Strathweb.AspNetCore.Dilithium;

public class LweSecurityKey : AsymmetricSecurityKey
{
    private readonly string _supportedAlgorithm;
    private readonly string _keyId;

    public LweSecurityKey(string algorithm)
    {
        _supportedAlgorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            
        var dilithiumParameters = GetDilithiumParameters(algorithm);
        var random = new SecureRandom();
        var keyGenParameters = new DilithiumKeyGenerationParameters(random, dilithiumParameters);
        var dilithiumKeyPairGenerator = new DilithiumKeyPairGenerator();
        dilithiumKeyPairGenerator.Init(keyGenParameters);

        var keyPair = dilithiumKeyPairGenerator.GenerateKeyPair();

        PublicKey = (DilithiumPublicKeyParameters)keyPair.Public;
        PrivateKey = (DilithiumPrivateKeyParameters)keyPair.Private;
        _keyId = BitConverter.ToString(SecureRandom.GetNextBytes(random, 16)).Replace("-", "");
        CryptoProviderFactory = new LweCryptoProviderFactory();
    }

    internal LweSecurityKey(JsonWebKey jsonWebKey)
    {
        if (jsonWebKey == null) throw new ArgumentNullException(nameof(jsonWebKey));
        if (jsonWebKey.X == null) throw new ArgumentException("X parameter (public key) is missing!");
        _supportedAlgorithm = jsonWebKey.Alg ?? throw new ArgumentException("jsonWebKey.Alg cannot be null!");
        
        var dilithiumParameters = GetDilithiumParameters(jsonWebKey.Alg);
        PublicKey = new DilithiumPublicKeyParameters(dilithiumParameters, Base64Url.Decode(jsonWebKey.X));

        if (jsonWebKey.D != null)
        {
            PrivateKey = GetPrivateKeyParametersFromEncodedKey(dilithiumParameters, Base64Url.Decode(jsonWebKey.D));
        }

        _keyId = jsonWebKey.KeyId;
        KeySize = jsonWebKey.KeySize;
    }
    
    public DilithiumPublicKeyParameters PublicKey { get; set; }
    
    public DilithiumPrivateKeyParameters? PrivateKey { get; set; }
    
    public override int KeySize { get; }

    public override string KeyId => _keyId;

    public override bool IsSupportedAlgorithm(string algorithm) => _supportedAlgorithm == algorithm;

    private DilithiumParameters GetDilithiumParameters(string algorithm)
    {
        if (_supportedAlgorithm == algorithm) return DilithiumParameters.Dilithium2;
        if (_supportedAlgorithm == algorithm) return DilithiumParameters.Dilithium3;
        if (_supportedAlgorithm == algorithm) return DilithiumParameters.Dilithium5;

        throw new NotSupportedException($"Unsupported algorithm type: '{algorithm}'");
    }

    [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus instead.")] 
    public override bool HasPrivateKey => PrivateKey != null;

    public override PrivateKeyStatus PrivateKeyStatus =>
        PrivateKey == null ? PrivateKeyStatus.Unknown : PrivateKeyStatus.Exists;

    public JsonWebKey ToJsonWebKey()
    {
        var jsonWebKey = new JsonWebKey
        {
            Kty = "LWE",
            Kid = KeyId,
            X = Base64Url.Encode(PublicKey.GetEncoded()),
            Alg = _supportedAlgorithm,
            Use = "sig"
        };

        if (PrivateKey != null)
        {
            jsonWebKey.D = Base64Url.Encode(PrivateKey.GetEncoded());
        }

        return jsonWebKey;
    }

    private DilithiumPrivateKeyParameters GetPrivateKeyParametersFromEncodedKey(DilithiumParameters dilithiumParameters, byte[] encodedPrivateKey)
    {
        const int seedBytes = 32;
        int s1Length;
        int s2Length;
        int t0Length;

        if (dilithiumParameters == DilithiumParameters.Dilithium2)
        {
            s1Length = 4 * 96; 
            s2Length = 4 * 96;
            t0Length = 4 * 416;
        } 
        else if (dilithiumParameters == DilithiumParameters.Dilithium3)
        {
            s1Length = 5 * 128;
            s2Length = 6 * 128;
            t0Length = 6 * 416;
        } 
        else if (dilithiumParameters == DilithiumParameters.Dilithium5)
        {
            s1Length = 7 * 96;
            s2Length = 8 * 96;
            t0Length = 8 * 416;
        }
        else
        {
            throw new NotSupportedException("Unsupported mode");
        }
    
        var rho = new byte[seedBytes]; // SeedBytes length
        var k = new byte[seedBytes]; // SeedBytes length
        var tr = new byte[seedBytes]; // SeedBytes length
        var s1 = new byte[s1Length]; // L * PolyEtaPackedBytes
        var s2 = new byte[s2Length]; // K * PolyEtaPackedBytes
        var t0 = new byte[t0Length]; // K * PolyT0PackedBytes

        var offset = 0;
        Array.Copy(encodedPrivateKey, offset, rho, 0, seedBytes);
        offset += seedBytes;
        Array.Copy(encodedPrivateKey, offset, k, 0, seedBytes);
        offset += seedBytes;
        Array.Copy(encodedPrivateKey, offset, tr, 0, seedBytes);
        offset += seedBytes;
        Array.Copy(encodedPrivateKey, offset, s1, 0, s1Length);
        offset += s1Length;
        Array.Copy(encodedPrivateKey, offset, s2, 0, s2Length);
        offset += s2Length;
        Array.Copy(encodedPrivateKey, offset, t0, 0, t0Length);
        offset += t0Length;
    
        // Take all remaining bytes as t1
        var remainingLength = encodedPrivateKey.Length - offset;
        var t1 = new byte[remainingLength];
        Array.Copy(encodedPrivateKey, offset, t1, 0, remainingLength);

        return new DilithiumPrivateKeyParameters(dilithiumParameters, rho, k, tr, s1, s2, t0, t1);
    }
}