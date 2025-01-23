using Microsoft.IdentityModel.Tokens;

namespace Strathweb.Dilithium.IdentityModel;

public class MlDsaCryptoProviderFactory : CryptoProviderFactory
{
    public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm) =>
        Create(key, algorithm, forSigning: true);

    public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm) =>
        Create(key, algorithm, forSigning: false);

    private SignatureProvider Create(SecurityKey key, string algorithm, bool forSigning)
    {
        if (key is not MlDsaSecurityKey lweKey)
            throw new NotSupportedException(
                $"Key {key.GetType()} is not compatible with {nameof(MlDsaCryptoProviderFactory)}. Key must be of type {nameof(MlDsaSecurityKey)}");

        return new MlDsaSignatureProvider(lweKey, algorithm, forSigning);
    }

    public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key) => 
        key is MlDsaSecurityKey lweKey && lweKey.IsSupportedAlgorithm(algorithm);

    public override bool IsSupportedAlgorithm(string algorithm) => 
        algorithm == "ML-DSA-44" || algorithm == "ML-DSA-65" || algorithm == "ML-DSA-87";
}