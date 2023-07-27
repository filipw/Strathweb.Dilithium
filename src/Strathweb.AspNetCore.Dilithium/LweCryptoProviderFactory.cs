using System.Collections.Concurrent;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

namespace Strathweb.AspNetCore.Dilithium;

public class LweCryptoProviderFactory : CryptoProviderFactory
{
    private readonly ConcurrentDictionary<string, DilithiumSigner> _dilithiumVerifiers = new ConcurrentDictionary<string, DilithiumSigner>();

    public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm) =>
        GetOrCreate(key, algorithm, forSigning: true);

    public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm) =>
        GetOrCreate(key, algorithm, forSigning: false);

    private SignatureProvider GetOrCreate(SecurityKey key, string algorithm, bool forSigning)
    {
        if (key is not LweSecurityKey lweKey)
            return key.CryptoProviderFactory.CreateForVerifying(key, algorithm);
            
        var cacheKey = lweKey.KeyId;
        if (forSigning)
        {
            cacheKey += "-S";
        }
        if (_dilithiumVerifiers.TryGetValue(cacheKey, out var signer))
        {
            return new LweSignatureProvider(lweKey, algorithm, signer);
        }

        var newSigner = new DilithiumSigner();
        var publicKey = lweKey.GetPublicKeyParameters(algorithm);

        newSigner.Init(forSigning, publicKey);

        _dilithiumVerifiers[cacheKey] = newSigner;
        return new LweSignatureProvider(lweKey, algorithm, newSigner);
    }

    public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key) => 
        key is LweSecurityKey lweKey && lweKey.IsSupportedAlgorithm(algorithm);
}