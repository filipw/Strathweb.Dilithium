namespace Strathweb.AspNetCore.Dilithium;

public record LweTokenOptions
{
    public bool DisableCache { get; set; } = false;

    public uint CacheLifetimeInSeconds { get; set; } = 3600 * 24;

    public bool AllowNonLweKeys { get; set; } = true;

    public LweAlgorithm[] SupportedAlgorithms { get; set; } = new[] { LweAlgorithm.CRYDI2, LweAlgorithm.CRYDI3, LweAlgorithm.CRYDI5 };
}

public enum LweAlgorithm
{
    CRYDI2, 
    CRYDI3,
    CRYDI5
}