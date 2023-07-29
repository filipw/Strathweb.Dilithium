using Microsoft.IdentityModel.Tokens;
using Strathweb.Dilithium.IdentityModel;

namespace Strathweb.AspNetCore.Dilithium.Tests;

public class DilithiumSecurityKeyTests
{
    [Theory]
    [InlineData("CRYDI2")]
    [InlineData("CRYDI3")]
    [InlineData("CRYDI5")]
    public void CanInit(string algorithm)
    {
        var securityKey = new DilithiumSecurityKey(algorithm);
        
        Assert.NotNull(securityKey.KeyId);
        Assert.NotNull(securityKey.PublicKey);
        Assert.NotNull(securityKey.PrivateKey);
        Assert.True(securityKey.IsSupportedAlgorithm(algorithm));
        Assert.NotNull(securityKey.CryptoProviderFactory);
        Assert.Equal(typeof(DilithiumCryptoProviderFactory), securityKey.CryptoProviderFactory.GetType());
        Assert.Equal(PrivateKeyStatus.Exists, securityKey.PrivateKeyStatus);
    }
    
    [Theory]
    [InlineData("CRYDI2")]
    [InlineData("CRYDI3")]
    [InlineData("CRYDI5")]
    public void CanExportToJWK(string algorithm)
    {
        var securityKey = new DilithiumSecurityKey(algorithm);
        var jwk = securityKey.ToJsonWebKey(includePrivateKey: true);
        
        Assert.Equal("MLWE", jwk.Kty);
        Assert.Equal(securityKey.KeyId, jwk.KeyId);
        Assert.Equal(algorithm, jwk.Alg);
        Assert.Equal(securityKey.PublicKey.GetEncoded(), Base64UrlEncoder.DecodeBytes(jwk.X));
        Assert.Equal(securityKey.PrivateKey.GetEncoded(), Base64UrlEncoder.DecodeBytes(jwk.D));
        Assert.True(securityKey.HasPrivateKey);
        Assert.Equal(PrivateKeyStatus.Exists, securityKey.PrivateKeyStatus);
    }
    
    [Fact]
    public void CanExportToJWK_WithoutPrivateKey()
    {
        var securityKey = new DilithiumSecurityKey("CRYDI2");
        var jwk = securityKey.ToJsonWebKey(includePrivateKey: false);
        
        Assert.Equal("MLWE", jwk.Kty);
        Assert.Equal(securityKey.KeyId, jwk.KeyId);
        Assert.Equal("CRYDI2", jwk.Alg);
        Assert.Equal(securityKey.PublicKey.GetEncoded(), Base64UrlEncoder.DecodeBytes(jwk.X));
        Assert.Null(jwk.D);
    }
    
    [Theory]
    [InlineData("CRYDI2")]
    [InlineData("CRYDI3")]
    [InlineData("CRYDI5")]
    public void CanImportFromJWK(string algorithm)
    {
        var securityKey = new DilithiumSecurityKey(algorithm);
        var jwk = securityKey.ToJsonWebKey(includePrivateKey: true);

        var importedKey = new DilithiumSecurityKey(jwk);
        
        Assert.Equal(securityKey.KeyId, importedKey.KeyId);
        Assert.Equal(securityKey.PublicKey.GetEncoded(), importedKey.PublicKey.GetEncoded());
        Assert.NotNull(importedKey.PrivateKey);
        Assert.Equal(securityKey.PrivateKey.GetEncoded(), importedKey.PrivateKey.GetEncoded());
        Assert.Equal(PrivateKeyStatus.Exists, importedKey.PrivateKeyStatus);
        Assert.True(importedKey.IsSupportedAlgorithm(algorithm));
        Assert.NotNull(importedKey.CryptoProviderFactory);
        Assert.Equal(typeof(DilithiumCryptoProviderFactory), importedKey.CryptoProviderFactory.GetType());

    }
    
    [Fact]
    public void CanImportFromJWK_WithoutPrivateKey()
    {
        var securityKey = new DilithiumSecurityKey("CRYDI2");
        var jwk = securityKey.ToJsonWebKey(includePrivateKey: false);

        var importedKey = new DilithiumSecurityKey(jwk);
        
        Assert.Equal(securityKey.KeyId, importedKey.KeyId);
        Assert.Equal(securityKey.PublicKey.GetEncoded(), importedKey.PublicKey.GetEncoded());
        Assert.True(importedKey.IsSupportedAlgorithm("CRYDI2"));
        Assert.NotNull(importedKey.CryptoProviderFactory);
        Assert.Equal(typeof(DilithiumCryptoProviderFactory), importedKey.CryptoProviderFactory.GetType());
        Assert.Null(importedKey.PrivateKey);
        Assert.False(importedKey.HasPrivateKey);
        Assert.Equal(PrivateKeyStatus.Unknown, importedKey.PrivateKeyStatus);
    }
}