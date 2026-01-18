using Duende.IdentityServer.Services.KeyManagement;
using Microsoft.IdentityModel.Tokens;
using Strathweb.Dilithium.IdentityModel;

namespace Strathweb.Dilithium.DuendeIdentityServer.KeyManagement;

public class MlDsaKeyContainer : KeyContainer
{
    /// <summary>
    /// Constructor for MlDsaKeyContainer.
    /// </summary>
    public MlDsaKeyContainer() : base()
    {
    }

    /// <summary>
    /// Constructor for MlDsaKeyContainer.
    /// </summary>
    public MlDsaKeyContainer(MlDsaSecurityKey key, string algorithm, DateTime created)
        : base(key.KeyId, algorithm, created)
    {
        D = key.PrivateKey ?? Array.Empty<byte>();
        X = key.PublicKey;
    }

    /// <summary>
    /// Private key
    /// </summary>
    public byte[] D { get; set; }

    /// <summary>
    /// Public key
    /// </summary>
    public byte[] X { get; set; }

    /// <inheritdoc/>
    public override AsymmetricSecurityKey ToSecurityKey()
    {
        return new MlDsaSecurityKey(Algorithm, Id, X, D);
    }
}