using Strathweb.Dilithium.IdentityModel;

namespace Strathweb.Dilithium.DuendeIdentityServer;

public class MlDsaSupportOptions
{
    public bool EnableKeyManagement { get; set; } = true;

    public string KeyManagementAlgorithm { get; set; } = "ML-DSA-65";

    public bool DisallowNonMlDsaKeys { get; set; } = true;
    
    public MlDsaSecurityKey? StaticKey { get; set; }
}