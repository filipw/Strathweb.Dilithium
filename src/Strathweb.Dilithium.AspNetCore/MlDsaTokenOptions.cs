using Microsoft.IdentityModel.Tokens;

namespace Strathweb.Dilithium.AspNetCore;

public record MlDsaTokenOptions
{
    public bool DisableCache { get; set; } = false;

    public uint CacheLifetimeInSeconds { get; set; } = 3600 * 24;

    public bool AllowNonMlDsaKeys { get; set; } = true;

    public SecurityKey[] FixedSecurityKeys { get; set; } = Array.Empty<SecurityKey>();
    
    public AkpAlgorithm[] SupportedAlgorithms { get; set; } = new[] { AkpAlgorithm.MLDSA44, AkpAlgorithm.MLDSA65, AkpAlgorithm.MLDSA87 };
}

public enum AkpAlgorithm
{
    MLDSA44, 
    MLDSA65,
    MLDSA87
}