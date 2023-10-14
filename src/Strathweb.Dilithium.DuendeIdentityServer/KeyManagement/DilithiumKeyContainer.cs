using Duende.IdentityServer.Services.KeyManagement;
using Microsoft.IdentityModel.Tokens;
using Strathweb.Dilithium.IdentityModel;

namespace Strathweb.Dilithium.DuendeIdentityServer.KeyManagement;

public class DilithiumKeyContainer : KeyContainer
{
    /// <summary>
    /// Constructor for DilithiumKeyContainer.
    /// </summary>
    public DilithiumKeyContainer() : base()
    {
    }

    /// <summary>
    /// Constructor for DilithiumKeyContainer.
    /// </summary>
    public DilithiumKeyContainer(DilithiumSecurityKey key, string algorithm, DateTime created)
        : base(key.KeyId, algorithm, created)
    {
        D = key.PrivateKey.GetEncoded();
        X = key.PublicKey.GetEncoded();
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
        return new DilithiumSecurityKey(Algorithm, Id, X, D);
    }
}