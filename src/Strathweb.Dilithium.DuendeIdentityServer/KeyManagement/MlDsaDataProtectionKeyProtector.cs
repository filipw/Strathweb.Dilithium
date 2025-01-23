using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services.KeyManagement;
using Microsoft.AspNetCore.DataProtection;

namespace Strathweb.Dilithium.DuendeIdentityServer.KeyManagement;

public class MlDsaDataProtectionKeyProtector : ISigningKeyProtector
{
    private readonly IDataProtector _dataProtectionProvider;
    private readonly KeyManagementOptions _options;

    public MlDsaDataProtectionKeyProtector(KeyManagementOptions options, IDataProtectionProvider dataProtectionProvider)
    {
        _options = options;
        _dataProtectionProvider = dataProtectionProvider.CreateProtector(nameof(DataProtectionKeyProtector));
    }
    
    public SerializedKey Protect(KeyContainer key)
    {
        var data = KeySerializer.Serialize(key);
            
        if (_options.DataProtectKeys)
        {
            data = _dataProtectionProvider.Protect(data);
        }
            
        return new SerializedKey
        {
            Version = 1,
            Created = DateTime.UtcNow,
            Id = key.Id,
            Algorithm = key.Algorithm,
            IsX509Certificate = key.HasX509Certificate,
            Data = data,
            DataProtected = _options.DataProtectKeys,
        };
    }
    
    public KeyContainer Unprotect(SerializedKey key)
    {
        var data = key.DataProtected ? 
            _dataProtectionProvider.Unprotect(key.Data) : 
            key.Data;

        if (key.IsX509Certificate)
        {
            return KeySerializer.Deserialize<X509KeyContainer>(data);
        }

        if (key.Algorithm.StartsWith("R") || key.Algorithm.StartsWith("P"))
        {
            return KeySerializer.Deserialize<RsaKeyContainer>(data);
        }
            
        if (key.Algorithm.StartsWith("E"))
        {
            return KeySerializer.Deserialize<EcKeyContainer>(data);
        }
        
        if (key.Algorithm.StartsWith("ML-DSA"))
        {
            return KeySerializer.Deserialize<MlDsaKeyContainer>(data);
        }

        throw new Exception($"Invalid Algorithm: {key.Algorithm} for kid: {key.Id}");
    }
}