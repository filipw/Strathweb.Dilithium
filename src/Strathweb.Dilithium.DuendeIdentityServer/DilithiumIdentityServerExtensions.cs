using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Strathweb.Dilithium.IdentityModel;

namespace Strathweb.Dilithium.DuendeIdentityServer;

public static class DilithiumIdentityServerExtensions
{
    public static IIdentityServerBuilder AddDilithiumSigningCredential(this IIdentityServerBuilder builder, DilithiumSecurityKey securityKey)
    {
        var credential = new SigningCredentials(securityKey, securityKey.SupportedAlgorithm);
        builder.Services.AddSingleton<ISigningCredentialStore>(new InMemorySigningCredentialsStore(credential));

        var keyInfo = new SecurityKeyInfo
        {
            Key = securityKey.ToJsonWebKey(includePrivateKey: false),
            SigningAlgorithm = credential.Algorithm
        };

        builder.Services.AddSingleton<IValidationKeysStore>(new InMemoryValidationKeysStore(new[] { keyInfo }));
        return builder;
    }
}