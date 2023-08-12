using System.Text.Json;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Strathweb.Dilithium.IdentityModel;
using JsonWebKey = Microsoft.IdentityModel.Tokens.JsonWebKey;

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
    
    public static IIdentityServerBuilder AddDilithiumSigningCredential(this IIdentityServerBuilder builder, string jwkPath)
    {
        if (jwkPath == null) throw new ArgumentNullException(nameof(jwkPath));

        if (Path.IsPathRooted(jwkPath))
        {
            jwkPath = Path.Combine(Directory.GetCurrentDirectory(), jwkPath);
        }
        
        if (!File.Exists(jwkPath))
        {
            throw new Exception($"JWK file '{jwkPath}' does not exist!");
        }
        
        var rawJwk = File.ReadAllText(jwkPath);
        var jwk = JsonSerializer.Deserialize<JsonWebKey>(rawJwk);
        if (jwk == null)
        {
            throw new Exception($"Could not deserialize JWK from '{jwkPath}'");
        }

        return builder.AddDilithiumSigningCredential(new DilithiumSecurityKey(jwk));
    }
}