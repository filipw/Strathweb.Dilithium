using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

namespace Strathweb.AspNetCore.Dilithium;

public class LweSecurityKey : SecurityKey
{
    private readonly LweAlgorithm[] _supportedAlgorithms;
    private readonly string _keyId;
    private readonly byte[] _x;

    public LweSecurityKey(JsonWebKey jsonWebKey, LweAlgorithm[] supportedAlgorithms)
    {
        _supportedAlgorithms = supportedAlgorithms;
        _x = Base64Url.Decode(jsonWebKey.X);
        _keyId = jsonWebKey.KeyId;
        KeySize = jsonWebKey.KeySize;
    }
    
    public override int KeySize { get; }

    public override string KeyId => _keyId;

    public DilithiumPublicKeyParameters GetPublicKeyParameters(string algorithm) =>
        new(GetDilithiumParameters(algorithm), _x);

    public override bool IsSupportedAlgorithm(string algorithm) =>
        Enum.TryParse<LweAlgorithm>(algorithm, true, out var parsedAlg) &&
        _supportedAlgorithms.Contains(parsedAlg);

    private DilithiumParameters GetDilithiumParameters(string algorithm)
    {
        if (Enum.TryParse<LweAlgorithm>(algorithm, true, out var parsedAlg) &&
            _supportedAlgorithms.Contains(parsedAlg))
        {
            if (parsedAlg == LweAlgorithm.CRYDI2) return DilithiumParameters.Dilithium2;
            if (parsedAlg == LweAlgorithm.CRYDI3) return DilithiumParameters.Dilithium3;
            if (parsedAlg == LweAlgorithm.CRYDI5) return DilithiumParameters.Dilithium5;
        }

        throw new Exception("Unsupported algorithm type");
    }
}