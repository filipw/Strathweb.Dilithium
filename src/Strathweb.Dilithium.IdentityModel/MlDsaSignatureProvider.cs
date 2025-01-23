using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Strathweb.Dilithium.IdentityModel;

public class MlDsaSignatureProvider : SignatureProvider
{
    private readonly MlDsaSecurityKey _key;
    private readonly bool _canSign;
    private readonly MLDsaParameters _publicOrPrivateKey;

    public MlDsaSignatureProvider(MlDsaSecurityKey key, string algorithm, bool canSign)
        : base(key, algorithm)
    {
        
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
        _key = key;
        _canSign = canSign;
        
        var publicOrPrivateKey = _canSign ? key.PrivateKey?.Parameters : key.PublicKey.Parameters;
        
        if (publicOrPrivateKey == null)
        {
            throw new NotSupportedException("Security key cannot be used as the necessary cipher parameters are missing for the required operation");
        }

        _publicOrPrivateKey = publicOrPrivateKey;
    }

    private MLDsaSigner CreateSigner()
    {
        var signer = new MLDsaSigner(_publicOrPrivateKey, deterministic: true);
        if (_canSign)
        {
            signer.Init(true, _key.PrivateKey);
        }
        else
        {
            signer.Init(false, _key.PublicKey);
        }
        
        return signer;
    }

    public override byte[] Sign(byte[] input)
    {
        if (!_canSign)
        {
            throw new NotSupportedException("This instance is not configured for signing!");
        }

        var signer = CreateSigner();
        signer.BlockUpdate(input, 0, input.Length);
        return signer.GenerateSignature();
    }

    public override bool Verify(byte[] input, byte[] signature)
    {
        var signer = CreateSigner();
        signer.BlockUpdate(input, 0, input.Length);
        return signer.VerifySignature(signature);
    }

    public override bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength)
    {
        var actualInput = new byte[inputLength];
        Array.Copy(input, inputOffset, actualInput, 0, inputLength);

        var actualSignature = new byte[signatureLength];
        Array.Copy(signature, signatureOffset, actualSignature, 0, signatureLength);

        var signer = CreateSigner();
        signer.BlockUpdate(actualInput, 0, actualInput.Length);
        return signer.VerifySignature(actualSignature);
    }

    protected override void Dispose(bool disposing)
    {
    }
}