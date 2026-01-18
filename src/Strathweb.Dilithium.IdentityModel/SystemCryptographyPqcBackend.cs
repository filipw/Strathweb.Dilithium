#pragma warning disable SYSLIB5006
using System.Security.Cryptography;

namespace Strathweb.Dilithium.IdentityModel;

public class SystemCryptographyPqcBackend : IPqcBackend
{
    public string Name => "System.Security.Cryptography";

    public static bool IsSupported => MLDsa.IsSupported;

    public (byte[] publicKey, byte[] privateKey) GenerateKeyPair(string algorithm)
    {
        if (!IsSupported) throw new NotSupportedException("ML-DSA is not supported on this platform.");

        var alg = GetMLDsaAlgorithm(algorithm);
        using var mldsaKey = MLDsa.GenerateKey(alg);
        
        return (mldsaKey.ExportSubjectPublicKeyInfo(), mldsaKey.ExportPkcs8PrivateKey());
    }

    public byte[] Sign(string algorithm, byte[] data, byte[] privateKey)
    {
        if (!IsSupported) throw new NotSupportedException("ML-DSA is not supported on this platform.");

        using var mldsaKey = MLDsa.ImportPkcs8PrivateKey(privateKey);
        return mldsaKey.SignData(data);
    }

    public bool Verify(string algorithm, byte[] data, byte[] signature, byte[] publicKey)
    {
        if (!IsSupported) throw new NotSupportedException("ML-DSA is not supported on this platform.");

        using var mldsaKey = MLDsa.ImportSubjectPublicKeyInfo(publicKey);
        return mldsaKey.VerifyData(data, signature);
    }

    private MLDsaAlgorithm GetMLDsaAlgorithm(string algorithm)
    {
        return algorithm switch
        {
            "ML-DSA-44" => MLDsaAlgorithm.MLDsa44,
            "ML-DSA-65" => MLDsaAlgorithm.MLDsa65,
            "ML-DSA-87" => MLDsaAlgorithm.MLDsa87,
            _ => throw new NotSupportedException($"Unsupported algorithm type: '{algorithm}'")
        };
    }
}
