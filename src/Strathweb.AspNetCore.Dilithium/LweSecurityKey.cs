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

    /// <summary>
    /// Used only for validation (initialize from JSON Web Key obtained from IDP). Cannot be used for signing.
    /// </summary>
    /// <param name="jsonWebKey"></param>
    internal LweSecurityKey(JsonWebKey jsonWebKey)
    {
        if (jsonWebKey == null) throw new ArgumentNullException(nameof(jsonWebKey));
        if (jsonWebKey.X == null) throw new ArgumentException("X parameter (public key) is missing!");
        _supportedAlgorithm = jsonWebKey.Alg ?? throw new ArgumentException("jsonWebKey.Alg cannot be null!");
        
        var dilithiumParameters = GetDilithiumParameters(jsonWebKey.Alg);
        PublicKey = new DilithiumPublicKeyParameters(dilithiumParameters, Base64Url.Decode(jsonWebKey.X));
        
        // todo: decide if we allow loading private key from jsonWebKey.D

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
}