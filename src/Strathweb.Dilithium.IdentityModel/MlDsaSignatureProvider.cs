using Microsoft.IdentityModel.Tokens;

namespace Strathweb.Dilithium.IdentityModel;

public class MlDsaSignatureProvider : SignatureProvider
{
    private readonly MlDsaSecurityKey _key;
    private readonly bool _canSign;

    public MlDsaSignatureProvider(MlDsaSecurityKey key, string algorithm, bool canSign)
        : base(key, algorithm)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
        _key = key;
        _canSign = canSign;
    }

    public override byte[] Sign(byte[] input)
    {
        if (!_canSign || _key.PrivateKey == null)
        {
            throw new NotSupportedException("This instance is not configured for signing, or private key is missing!");
        }

        return _key.Backend.Sign(Algorithm, input, _key.PrivateKey);
    }

    public override bool Verify(byte[] input, byte[] signature)
    {
        return _key.Backend.Verify(Algorithm, input, signature, _key.PublicKey);
    }

    public override bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength)
    {
        var actualInput = new byte[inputLength];
        Array.Copy(input, inputOffset, actualInput, 0, inputLength);

        var actualSignature = new byte[signatureLength];
        Array.Copy(signature, signatureOffset, actualSignature, 0, signatureLength);

        return Verify(actualInput, actualSignature);
    }

    protected override void Dispose(bool disposing)
    {
    }
}