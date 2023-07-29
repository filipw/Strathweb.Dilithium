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
}

class TestSecurityKey : SecurityKey
{
    public override int KeySize { get; } = 1;
}