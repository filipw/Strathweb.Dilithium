using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Signers;

namespace Strathweb.Dilithium.IdentityModel;

public class BouncyCastlePqcBackend : IPqcBackend
{
    public string Name => "BouncyCastle";

    public (byte[] publicKey, byte[] privateKey) GenerateKeyPair(string algorithm)
    {
        var mlDsaParameters = GetMlDsaParameters(algorithm);
        var random = new SecureRandom();
        var keyGenParameters = new MLDsaKeyGenerationParameters(random, mlDsaParameters);
        var mlDsaKeyPairGenerator = new MLDsaKeyPairGenerator();
        mlDsaKeyPairGenerator.Init(keyGenParameters);

        var keyPair = mlDsaKeyPairGenerator.GenerateKeyPair();
        var publicKey = ((MLDsaPublicKeyParameters)keyPair.Public).GetEncoded();
        var privateKey = ((MLDsaPrivateKeyParameters)keyPair.Private).GetEncoded();

        return (publicKey, privateKey);
    }

    public byte[] Sign(string algorithm, byte[] data, byte[] privateKey)
    {
        var mlDsaParameters = GetMlDsaParameters(algorithm);
        var privateKeyParameters = MLDsaPrivateKeyParameters.FromEncoding(mlDsaParameters, privateKey);
        var signer = new MLDsaSigner(mlDsaParameters, deterministic: true);
        signer.Init(true, privateKeyParameters);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    public bool Verify(string algorithm, byte[] data, byte[] signature, byte[] publicKey)
    {
        var mlDsaParameters = GetMlDsaParameters(algorithm);
        var publicKeyParameters = MLDsaPublicKeyParameters.FromEncoding(mlDsaParameters, publicKey);
        var signer = new MLDsaSigner(mlDsaParameters, deterministic: true);
        signer.Init(false, publicKeyParameters);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.VerifySignature(signature);
    }

    private MLDsaParameters GetMlDsaParameters(string algorithm)
    {
        if (algorithm == "ML-DSA-44") return MLDsaParameters.ml_dsa_44;
        if (algorithm == "ML-DSA-65") return MLDsaParameters.ml_dsa_65;
        if (algorithm == "ML-DSA-87") return MLDsaParameters.ml_dsa_87;

        throw new NotSupportedException($"Unsupported algorithm type: '{algorithm}'");
    }
}
