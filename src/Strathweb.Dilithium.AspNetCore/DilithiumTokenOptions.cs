using Microsoft.IdentityModel.Tokens;

namespace Strathweb.Dilithium.AspNetCore;

public record DilithiumTokenOptions
{
    public bool DisableCache { get; set; } = false;

    public uint CacheLifetimeInSeconds { get; set; } = 3600 * 24;

    public bool AllowNonMlweKeys { get; set; } = true;

    public SecurityKey[] FixedSecurityKeys { get; set; } = Array.Empty<SecurityKey>();
    
    public MlweAlgorithm[] SupportedAlgorithms { get; set; } = new[] { MlweAlgorithm.CRYDI2, MlweAlgorithm.CRYDI3, MlweAlgorithm.CRYDI5 };
}

public enum MlweAlgorithm
{
    CRYDI2, 
    CRYDI3,
    CRYDI5
}