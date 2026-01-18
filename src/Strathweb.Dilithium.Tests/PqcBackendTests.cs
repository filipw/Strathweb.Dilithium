using System.Text;
using Microsoft.IdentityModel.Tokens;
using Strathweb.Dilithium.IdentityModel;
using Xunit;

namespace Strathweb.Dilithium.Tests;

public class PqcBackendTests
{
    private const string TestTokenHeader = "{\"alg\": \"ML-DSA-65\",\"typ\": \"at+jwt\",\"kid\": \"DA9348183FA12769546010E260082E98\"}";
    private const string TestTokenPayload = "{\"iss\": \"https://localhost:5001\",\"aud\": [\"api1\"]}";

    public static IEnumerable<object[]> GetBackends()
    {
        yield return new object[] { new BouncyCastlePqcBackend() };
        yield return new object[] { new LibOqsPqcBackend() };
        if (SystemCryptographyPqcBackend.IsSupported)
        {
            yield return new object[] { new SystemCryptographyPqcBackend() };
        }
    }

    [Theory]
    [MemberData(nameof(GetBackends))]
    public void SignAndVerify_SameBackend(IPqcBackend backend)
    {
        var algorithm = "ML-DSA-65";
        var content = Encoding.UTF8.GetBytes($"{TestTokenHeader}.{TestTokenPayload}");
        var key = new MlDsaSecurityKey(algorithm, backend);
        
        var signatureProvider = key.CryptoProviderFactory.CreateForSigning(key, algorithm);
        var signed = signatureProvider.Sign(content);
        
        var verificationProvider = key.CryptoProviderFactory.CreateForVerifying(key, algorithm);
        Assert.True(verificationProvider.Verify(content, signed));
    }

    [Theory]
    [MemberData(nameof(GetBackends))]
    public void CrossBackendVerification_BouncyCastleSign(IPqcBackend verifierBackend)
    {
        var algorithm = "ML-DSA-65";
        var content = Encoding.UTF8.GetBytes($"{TestTokenHeader}.{TestTokenPayload}");
        
        // Sign with BouncyCastle
        var signerKey = new MlDsaSecurityKey(algorithm, new BouncyCastlePqcBackend());
        var signatureProvider = signerKey.CryptoProviderFactory.CreateForSigning(signerKey, algorithm);
        var signed = signatureProvider.Sign(content);
        
        // Verify with another backend
        var jwk = signerKey.ToJsonWebKey(includePrivateKey: false);
        var verificationKey = new MlDsaSecurityKey(jwk, verifierBackend);
        var verificationProvider = verificationKey.CryptoProviderFactory.CreateForVerifying(verificationKey, algorithm);
        
        Assert.True(verificationProvider.Verify(content, signed));
    }

    [Fact]
    public void BouncyCastle_To_LibOqs_Verify()
    {
        var algorithm = "ML-DSA-65";
        var content = Encoding.UTF8.GetBytes("Hello PQC");
        
        var bcBackend = new BouncyCastlePqcBackend();
        var oqsBackend = new LibOqsPqcBackend();
        
        var (pub, priv) = bcBackend.GenerateKeyPair(algorithm);
        var sig = bcBackend.Sign(algorithm, content, priv);
        
        var verified = oqsBackend.Verify(algorithm, content, sig, pub);
        Assert.True(verified);
    }
}
