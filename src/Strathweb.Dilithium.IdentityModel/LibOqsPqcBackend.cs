using LibOQS.NET;

namespace Strathweb.Dilithium.IdentityModel;

public class LibOqsPqcBackend : IPqcBackend
{
    public string Name => "LibOQS";

    public (byte[] publicKey, byte[] privateKey) GenerateKeyPair(string algorithm)
    {
        var alg = GetSigAlgorithm(algorithm);
        using var sig = new SigInstance(alg);
        var (publicKey, privateKey) = sig.GenerateKeypair();
        return (publicKey, privateKey);
    }

    public byte[] Sign(string algorithm, byte[] data, byte[] privateKey)
    {
        var alg = GetSigAlgorithm(algorithm);
        using var sig = new SigInstance(alg);
        return sig.Sign(data, privateKey);
    }

    public bool Verify(string algorithm, byte[] data, byte[] signature, byte[] publicKey)
    {
        var alg = GetSigAlgorithm(algorithm);
        using var sig = new SigInstance(alg);
        return sig.Verify(data, signature, publicKey);
    }

    private SigAlgorithm GetSigAlgorithm(string algorithm)
    {
        if (algorithm == "ML-DSA-44") return SigAlgorithm.MlDsa44;
        if (algorithm == "ML-DSA-65") return SigAlgorithm.MlDsa65;
        if (algorithm == "ML-DSA-87") return SigAlgorithm.MlDsa87;

        throw new NotSupportedException($"Unsupported algorithm type: '{algorithm}'");
    }
}
