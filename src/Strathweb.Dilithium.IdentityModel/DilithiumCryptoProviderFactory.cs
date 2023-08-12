using System.Collections.Concurrent;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

namespace Strathweb.Dilithium.IdentityModel;

public class DilithiumCryptoProviderFactory : CryptoProviderFactory
{
    private readonly ConcurrentDictionary<string, DilithiumSigner> _dilithiumVerifiers = new();

    public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm) =>
        GetOrCreate(key, algorithm, forSigning: true);

    public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm) =>
        GetOrCreate(key, algorithm, forSigning: false);

    private SignatureProvider GetOrCreate(SecurityKey key, string algorithm, bool forSigning)
    {
        if (key is not DilithiumSecurityKey lweKey)
            throw new NotSupportedException(
                $"Key {key.GetType()} is not compatible with {nameof(DilithiumCryptoProviderFactory)}. Key must be of type {nameof(DilithiumSecurityKey)}");
            
        var cacheKey = lweKey.KeyId;
        if (forSigning)
        {
            cacheKey += "-S";
        }
        if (_dilithiumVerifiers.TryGetValue(cacheKey, out var signer))
        {
            return new DilithiumSignatureProvider(lweKey, algorithm, signer, forSigning);
        }

        var newSigner = new DilithiumSigner();
        ICipherParameters? publicOrPrivateKey = forSigning ? lweKey.PrivateKey : lweKey.PublicKey;
        
        if (publicOrPrivateKey == null)
        {
            throw new NotSupportedException("Security key cannot be used as the necessary cipher parameters are missing for the required operation");
        }
        
        newSigner.Init(forSigning, publicOrPrivateKey);
        _dilithiumVerifiers[cacheKey] = newSigner;
        return new DilithiumSignatureProvider(lweKey, algorithm, newSigner, forSigning);
    }

    public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key) => 
        key is DilithiumSecurityKey lweKey && lweKey.IsSupportedAlgorithm(algorithm);

    public override bool IsSupportedAlgorithm(string algorithm) => 
        algorithm == "CRYDI2" || algorithm == "CRYDI3" || algorithm == "CRYDI5";
}