using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

namespace Strathweb.Dilithium.IdentityModel;

public class DilithiumSignatureProvider : SignatureProvider
{
    private readonly DilithiumSigner _signer;
    private readonly bool _canSign;

    public DilithiumSignatureProvider(DilithiumSecurityKey key, string algorithm, DilithiumSigner signer, bool canSign)
        : base(key, algorithm)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
        _canSign = canSign;
    }

    public override byte[] Sign(byte[] input)
    {
        if (!_canSign)
        {
            throw new NotSupportedException("This instance is not configured for signing!");
        }
        return _signer.GenerateSignature(input);
    }

    public override bool Verify(byte[] input, byte[] signature) => 
        _signer.VerifySignature(input, signature);

    // todo: it would be good to avoid copying here
    public override bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength)
    {
        var actualInput = new byte[inputLength];
        Array.Copy(input, inputOffset, actualInput, 0, inputLength);

        var actualSignature = new byte[signatureLength];
        Array.Copy(signature, signatureOffset, actualSignature, 0, signatureLength);

        return _signer.VerifySignature(actualInput, actualSignature);
    }

    protected override void Dispose(bool disposing)
    {
    }
}