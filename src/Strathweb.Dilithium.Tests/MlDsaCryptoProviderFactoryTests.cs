using System.Text;
using Microsoft.IdentityModel.Tokens;
using Strathweb.Dilithium.IdentityModel;

namespace Strathweb.Dilithium.Tests;

public class MlDsaCryptoProviderFactoryTests
{
    [Fact]
    public void IsSupportedAlgorithm_ReturnsFalseForNonMlDsaKey()
    {
        var testKey = new TestSecurityKey();
        var factory = new MlDsaCryptoProviderFactory();
        Assert.False(factory.IsSupportedAlgorithm("ML-DSA-65", testKey));
    }
    
    [Fact]
    public void IsSupportedAlgorithm_ReturnsFalseForNonMlDsaAlgo()
    {
        var factory = new MlDsaCryptoProviderFactory();
        Assert.False(factory.IsSupportedAlgorithm("Foo"));
    }
    
    [Fact]
    public void IsSupportedAlgorithm_ReturnsFalseForNonMlDsaAlgo2()
    {
        var testKey = new MlDsaSecurityKey("ML-DSA-65");
        var factory = new MlDsaCryptoProviderFactory();
        Assert.False(factory.IsSupportedAlgorithm("Foo", testKey));
    }
    
    [Fact]
    public void CreateForSigning_ThrowsForNonMlDsaKeys()
    {
        var testKey = new TestSecurityKey();
        var factory = new MlDsaCryptoProviderFactory();
        Assert.Throws<NotSupportedException>(() => factory.CreateForSigning(testKey, "ML-DSA-65"));
    }
    
    [Fact]
    public void CreateForVerifying_ThrowsForNonMlDsaKeys()
    {
        var testKey = new TestSecurityKey();
        var factory = new MlDsaCryptoProviderFactory();
        Assert.Throws<NotSupportedException>(() => factory.CreateForVerifying(testKey, "ML-DSA-65"));
    }
    
    [Fact]
    public void CreateForSigning_ReturnsMlDsaSignatureProvider()
    {
        var testKey = new MlDsaSecurityKey("ML-DSA-65");
        var factory = new MlDsaCryptoProviderFactory();
        var signatureProvider = factory.CreateForSigning(testKey, "ML-DSA-65");
        Assert.IsType<MlDsaSignatureProvider>(signatureProvider);
    }
    
    [Fact]
    public void CreateForVerifying_ReturnsMlDsaSignatureProvider()
    {
        var testKey = new MlDsaSecurityKey("ML-DSA-65");
        var factory = new MlDsaCryptoProviderFactory();
        var signatureProvider = factory.CreateForVerifying(testKey, "ML-DSA-65");
        Assert.IsType<MlDsaSignatureProvider>(signatureProvider);
    }

    [Theory]
    [InlineData("ML-DSA-44")]
    [InlineData("ML-DSA-65")]
    [InlineData("ML-DSA-87")]
    public void SignAndVerify(string algorithm)
    {
        var content = Encoding.UTF8.GetBytes($"{TestTokenHeader}.{TestTokenPayload}");
        var key = new MlDsaSecurityKey(algorithm);
        var signatureProvider = key.CryptoProviderFactory.CreateForSigning(key, algorithm);
        var signed = signatureProvider.Sign(content);
        
        var verificationProvider = key.CryptoProviderFactory.CreateForVerifying(key, algorithm);
        Assert.True(verificationProvider.Verify(content, signed));
    }
    
    [Theory]
    [InlineData("ML-DSA-44")]
    [InlineData("ML-DSA-65")]
    [InlineData("ML-DSA-87")]
    public void CreateForVerifying_SigningThrows(string algorithm)
    {
        var content = Encoding.UTF8.GetBytes($"{TestTokenHeader}.{TestTokenPayload}");
        var key = new MlDsaSecurityKey(algorithm);
        var signatureProvider = key.CryptoProviderFactory.CreateForVerifying(key, algorithm);
        Assert.Throws<NotSupportedException>(() => signatureProvider.Sign(content));
    }

    [Theory]
    [InlineData("ML-DSA-44")]
    [InlineData("ML-DSA-65")]
    [InlineData("ML-DSA-87")]
    public void SignAndVerify_RoundTripFromJWK(string algorithm)
    {
        var content = Encoding.UTF8.GetBytes($"{TestTokenHeader}.{TestTokenPayload}");
        var key = new MlDsaSecurityKey(algorithm);
        var signatureProvider = key.CryptoProviderFactory.CreateForSigning(key, algorithm);
        var signed = signatureProvider.Sign(content);

        var jwk = key.ToJsonWebKey(includePrivateKey: false);
        var verificationKey = new MlDsaSecurityKey(jwk);
        var verificationProvider = verificationKey.CryptoProviderFactory.CreateForVerifying(key, algorithm);
        Assert.True(verificationProvider.Verify(content, signed));
    }

    private const string TestTokenHeader = """
    {
      "alg": "ML-DSA-65",
      "typ": "at+jwt",
      "kid": "DA9348183FA12769546010E260082E98"
    }
    """;
    
    private const string TestTokenPayload = """
    {
      "iss": "https://localhost:5001",
      "nbf": 1690484180,
      "iat": 1690484180,
      "exp": 1690487780,
      "aud": [
        "api1",
        "https://localhost:5001/resources"
      ],
      "scope": [
        "scope1"
      ],
      "client_id": "client",
      "jti": "E7B10BF1B09E573FAB697E42CBFFC8D9"
    }
    """;
}

class TestSecurityKey : SecurityKey
{
    public override int KeySize { get; } = 1;
}