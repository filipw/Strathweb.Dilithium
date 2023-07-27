using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

namespace Strathweb.AspNetCore.Dilithium;

public class LweSignatureProvider : SignatureProvider
{
    private readonly DilithiumSigner _signer;

    public LweSignatureProvider(LweSecurityKey key, string algorithm, DilithiumSigner signer)
        : base(key, algorithm)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
        Console.WriteLine($"ALGO: {algorithm}");
    }

    public override byte[] Sign(byte[] input)
    {
        return _signer.GenerateSignature(input);
    }

    public override bool Verify(byte[] input, byte[] signature)
    {
        var verified = _signer.VerifySignature(input, signature);
        Console.WriteLine($"VERIFIED: {verified}");
        return verified;
    }

    protected override void Dispose(bool disposing)
    {
    }
}