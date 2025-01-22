using System.Collections.Concurrent;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

namespace Strathweb.Dilithium.IdentityModel;

public class DilithiumCryptoProviderFactory : CryptoProviderFactory
{
    public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm) =>
        Create(key, algorithm, forSigning: true);

    public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm) =>
        Create(key, algorithm, forSigning: false);

    private SignatureProvider Create(SecurityKey key, string algorithm, bool forSigning)
    {
        if (key is not DilithiumSecurityKey lweKey)
            throw new NotSupportedException(
                $"Key {key.GetType()} is not compatible with {nameof(DilithiumCryptoProviderFactory)}. Key must be of type {nameof(DilithiumSecurityKey)}");

        return new DilithiumSignatureProvider(lweKey, algorithm, forSigning);
    }

    public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key) => 
        key is DilithiumSecurityKey lweKey && lweKey.IsSupportedAlgorithm(algorithm);

    public override bool IsSupportedAlgorithm(string algorithm) => 
        algorithm == "ML-DSA-44" || algorithm == "ML-DSA-65" || algorithm == "ML-DSA-87";
}