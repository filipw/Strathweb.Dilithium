using System.Text;
using Microsoft.IdentityModel.Tokens;
using Strathweb.Dilithium.IdentityModel;

namespace Strathweb.AspNetCore.Dilithium.Tests;

public class DilithiumCryptoProviderFactoryTests
{
    [Fact]
    public void CreateForSigning_ThrowsForNonDilithiumKeys()
    {
        var testKey = new TestSecurityKey();
        var factory = new DilithiumCryptoProviderFactory();
        Assert.Throws<NotSupportedException>(() => factory.CreateForSigning(testKey, "CRYDI3"));
    }
    
    [Fact]
    public void CreateForVerifying_ThrowsForNonDilithiumKeys()
    {
        var testKey = new TestSecurityKey();
        var factory = new DilithiumCryptoProviderFactory();
        Assert.Throws<NotSupportedException>(() => factory.CreateForVerifying(testKey, "CRYDI3"));
    }
    
    [Fact]
    public void CreateForSigning_ReturnsDilithiumSignatureProvider()
    {
        var testKey = new DilithiumSecurityKey("CRYDI3");
        var factory = new DilithiumCryptoProviderFactory();
        var signatureProvider = factory.CreateForSigning(testKey, "CRYDI3");
        Assert.IsType<DilithiumSignatureProvider>(signatureProvider);
    }
    
    [Fact]
    public void CreateForVerifying_ReturnsDilithiumSignatureProvider()
    {
        var testKey = new DilithiumSecurityKey("CRYDI3");
        var factory = new DilithiumCryptoProviderFactory();
        var signatureProvider = factory.CreateForVerifying(testKey, "CRYDI3");
        Assert.IsType<DilithiumSignatureProvider>(signatureProvider);
    }

    [Theory]
    [InlineData("CRYDI2")]
    [InlineData("CRYDI3")]
    [InlineData("CRYDI5")]
    public void SignatureValidation(string algorithm)
    {
        var content = "test me content"u8.ToArray();
        var key = new DilithiumSecurityKey(algorithm);
        var signatureProvider = key.CryptoProviderFactory.CreateForSigning(key, algorithm);
        var signed = signatureProvider.Sign(content);
        
        var verificationProvider = key.CryptoProviderFactory.CreateForVerifying(key, algorithm);
        Assert.True(verificationProvider.Verify(content, signed));
    }
    
    [Theory]
    [InlineData("CRYDI2")]
    [InlineData("CRYDI3")]
    [InlineData("CRYDI5")]
    public void SignatureValidation_RoundTripFromJWK(string algorithm)
    {
        var content = "test me content"u8.ToArray();
        var key = new DilithiumSecurityKey(algorithm);
        var signatureProvider = key.CryptoProviderFactory.CreateForSigning(key, algorithm);
        var signed = signatureProvider.Sign(content);

        var jwk = key.ToJsonWebKey(includePrivateKey: false);
        var verificationKey = new DilithiumSecurityKey(jwk);
        var verificationProvider = verificationKey.CryptoProviderFactory.CreateForVerifying(key, algorithm);
        Assert.True(verificationProvider.Verify(content, signed));
    }
}

class TestSecurityKey : SecurityKey
{
    public override int KeySize { get; } = 1;
}