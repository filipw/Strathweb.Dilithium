using Microsoft.IdentityModel.Tokens;
using Strathweb.Dilithium.IdentityModel;

namespace Strathweb.Dilithium.Tests;

public class MlDsaSecurityKeyTests
{
    public static IEnumerable<object?[]> Backends
    {
        get
        {
            yield return new object?[] { null };
            yield return new object?[] { new LibOqsPqcBackend() };
            yield return new object?[] { new BouncyCastlePqcBackend() };
            if (SystemCryptographyPqcBackend.IsSupported)
            {
                yield return new object?[] { new SystemCryptographyPqcBackend() };
            }
        }
    }

    public static IEnumerable<object[]> BackendAndAlgorithmData
    {
        get
        {
            var algorithms = new[] { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };
            var backends = new List<IPqcBackend?> { null, new LibOqsPqcBackend(), new BouncyCastlePqcBackend() };
            if (SystemCryptographyPqcBackend.IsSupported)
            {
                backends.Add(new SystemCryptographyPqcBackend());
            }

            foreach (var alg in algorithms)
            {
                foreach (var backend in backends)
                {
                    yield return new object[] { alg, backend };
                }
            }
        }
    }

    [Theory]
    [MemberData(nameof(BackendAndAlgorithmData))]
    public void CanInit(string algorithm, IPqcBackend? backend)
    {
        var securityKey = new MlDsaSecurityKey(algorithm, backend);
        
        Assert.NotNull(securityKey.KeyId);
        Assert.NotNull(securityKey.PublicKey);
        Assert.NotNull(securityKey.PrivateKey);
        Assert.True(securityKey.IsSupportedAlgorithm(algorithm));
        Assert.NotNull(securityKey.CryptoProviderFactory);
        Assert.Equal(typeof(MlDsaCryptoProviderFactory), securityKey.CryptoProviderFactory.GetType());
        Assert.Equal(PrivateKeyStatus.Exists, securityKey.PrivateKeyStatus);
        
        if (backend != null)
        {
            Assert.Equal(backend.Name, securityKey.Backend.Name);
        }
    }
    
    [Theory]
    [MemberData(nameof(BackendAndAlgorithmData))]
    public void CanExportToJWK(string algorithm, IPqcBackend? backend)
    {
        var securityKey = new MlDsaSecurityKey(algorithm, backend);
        var jwk = securityKey.ToJsonWebKey(includePrivateKey: true);
        
        Assert.Equal("AKP", jwk.Kty);
        Assert.Equal(securityKey.KeyId, jwk.KeyId);
        Assert.Equal(algorithm, jwk.Alg);
        Assert.Equal(securityKey.PublicKey, Base64UrlEncoder.DecodeBytes(jwk.X));
        Assert.Equal(securityKey.PrivateKey, Base64UrlEncoder.DecodeBytes(jwk.D));
        Assert.True(securityKey.HasPrivateKey);
        Assert.Equal(PrivateKeyStatus.Exists, securityKey.PrivateKeyStatus);
    }
    
    [Theory]
    [MemberData(nameof(Backends))]
    public void CanExportToJWK_WithoutPrivateKey(IPqcBackend? backend)
    {
        var securityKey = new MlDsaSecurityKey("ML-DSA-44", backend);
        var jwk = securityKey.ToJsonWebKey(includePrivateKey: false);
        
        Assert.Equal("AKP", jwk.Kty);
        Assert.Equal(securityKey.KeyId, jwk.KeyId);
        Assert.Equal("ML-DSA-44", jwk.Alg);
        Assert.Equal(securityKey.PublicKey, Base64UrlEncoder.DecodeBytes(jwk.X));
        Assert.Null(jwk.D);
    }
    
    [Theory]
    [MemberData(nameof(BackendAndAlgorithmData))]
    public void CanImportFromJWK(string algorithm, IPqcBackend? backend)
    {
        var securityKey = new MlDsaSecurityKey(algorithm, backend);
        var jwk = securityKey.ToJsonWebKey(includePrivateKey: true);

        var importedKey = new MlDsaSecurityKey(jwk, backend);
        
        Assert.Equal(securityKey.KeyId, importedKey.KeyId);
        Assert.Equal(securityKey.PublicKey, importedKey.PublicKey);
        Assert.NotNull(importedKey.PrivateKey);
        Assert.Equal(securityKey.PrivateKey, importedKey.PrivateKey);
        Assert.Equal(PrivateKeyStatus.Exists, importedKey.PrivateKeyStatus);
        Assert.True(importedKey.IsSupportedAlgorithm(algorithm));
        Assert.NotNull(importedKey.CryptoProviderFactory);
        Assert.Equal(typeof(MlDsaCryptoProviderFactory), importedKey.CryptoProviderFactory.GetType());
    }
    
    [Theory]
    [MemberData(nameof(Backends))]
    public void CanImportFromJWK_WithoutPrivateKey(IPqcBackend? backend)
    {
        var securityKey = new MlDsaSecurityKey("ML-DSA-44", backend);
        var jwk = securityKey.ToJsonWebKey(includePrivateKey: false);

        var importedKey = new MlDsaSecurityKey(jwk, backend);
        
        Assert.Equal(securityKey.KeyId, importedKey.KeyId);
        Assert.Equal(securityKey.PublicKey, importedKey.PublicKey);
        Assert.True(importedKey.IsSupportedAlgorithm("ML-DSA-44"));
        Assert.NotNull(importedKey.CryptoProviderFactory);
        Assert.Equal(typeof(MlDsaCryptoProviderFactory), importedKey.CryptoProviderFactory.GetType());
        Assert.Null(importedKey.PrivateKey);
        Assert.False(importedKey.HasPrivateKey);
        Assert.Equal(PrivateKeyStatus.DoesNotExist, importedKey.PrivateKeyStatus);
    }
    
    [Theory]
    [MemberData(nameof(BackendAndAlgorithmData))]
    public void CanImportFromByteArrayEncodedKeys(string algorithm, IPqcBackend? backend)
    {
        var securityKey = new MlDsaSecurityKey(algorithm, backend);
        var importedKey = new MlDsaSecurityKey(algorithm, securityKey.KeyId, securityKey.PublicKey, securityKey.PrivateKey, backend);
        
        Assert.Equal(securityKey.KeyId, importedKey.KeyId);
        Assert.Equal(securityKey.PublicKey, importedKey.PublicKey);
        Assert.NotNull(importedKey.PrivateKey);
        Assert.Equal(securityKey.PrivateKey, importedKey.PrivateKey);
        Assert.Equal(PrivateKeyStatus.Exists, importedKey.PrivateKeyStatus);
        Assert.True(importedKey.IsSupportedAlgorithm(algorithm));
        Assert.NotNull(importedKey.CryptoProviderFactory);
        Assert.Equal(typeof(MlDsaCryptoProviderFactory), importedKey.CryptoProviderFactory.GetType());
    }
}
