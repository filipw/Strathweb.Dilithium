using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

namespace Strathweb.AspNetCore.Dilithium;

public class DilithiumSignatureProvider : SignatureProvider
{
    private readonly DilithiumSigner _signer;

    public DilithiumSignatureProvider(DilithiumSecurityKey key, string algorithm, DilithiumSigner signer)
        : base(key, algorithm)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
    }

    public override byte[] Sign(byte[] input) => 
        _signer.GenerateSignature(input);

    public override bool Verify(byte[] input, byte[] signature) => 
        _signer.VerifySignature(input, signature);

    protected override void Dispose(bool disposing)
    {
    }
}