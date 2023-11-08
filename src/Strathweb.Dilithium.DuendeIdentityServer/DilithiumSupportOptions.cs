using Strathweb.Dilithium.IdentityModel;

namespace Strathweb.Dilithium.DuendeIdentityServer;

public class DilithiumSupportOptions
{
    public bool EnableKeyManagement { get; set; } = true;

    public string KeyManagementAlgorithm { get; set; } = "CRYDI3";

    public bool DisallowNonDilithiumKeys { get; set; } = true;
    
    public DilithiumSecurityKey? StaticKey { get; set; }
}