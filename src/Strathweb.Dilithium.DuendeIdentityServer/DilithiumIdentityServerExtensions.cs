using System.Text.Json;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.ResponseHandling;
using Duende.IdentityServer.Services.KeyManagement;
using Duende.IdentityServer.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Strathweb.Dilithium.DuendeIdentityServer.KeyManagement;
using Strathweb.Dilithium.IdentityModel;
using JsonWebKey = Microsoft.IdentityModel.Tokens.JsonWebKey;

namespace Strathweb.Dilithium.DuendeIdentityServer;

public static class DilithiumIdentityServerExtensions
{
    public static IIdentityServerBuilder AddDilithiumSupport(this IIdentityServerBuilder builder)
    {
        return builder.AddDilithiumSupport(new DilithiumSupportOptions());
    }
    
    public static IIdentityServerBuilder AddDilithiumSupport(this IIdentityServerBuilder builder, DilithiumSupportOptions dilithiumSupportOptions)
    {
        if (builder == null) throw new ArgumentNullException(nameof(builder));
        if (dilithiumSupportOptions == null) throw new ArgumentNullException(nameof(dilithiumSupportOptions));
        
        if (dilithiumSupportOptions.EnableKeyManagement)
        {
            if (dilithiumSupportOptions.KeyManagementAlgorithm != "CRYDI2" && dilithiumSupportOptions.KeyManagementAlgorithm != "CRYDI3" && dilithiumSupportOptions.KeyManagementAlgorithm != "CRYDI5")
            {
                throw new NotSupportedException(
                    $"Algorithm {dilithiumSupportOptions.KeyManagementAlgorithm} is not supported. Supported algorithms: CRYDI2, CRYDI3 and CRYDI5.");
            }
            
            if (dilithiumSupportOptions.DisallowNonDilithiumKeys)
            {
                builder.Services.Configure((IdentityServerOptions identityServerOptions) =>
                {
                    identityServerOptions.KeyManagement.Enabled = true;
                    identityServerOptions.KeyManagement.SigningAlgorithms = new[]
                    {
                        new SigningAlgorithmOptions(dilithiumSupportOptions.KeyManagementAlgorithm)
                    };
                });
            }
            else
            {
                builder.Services.Configure((IdentityServerOptions identityServerOptions) =>
                {
                    identityServerOptions.KeyManagement.Enabled = true;
                    var configuredAlgorithms = identityServerOptions.KeyManagement.SigningAlgorithms.ToList();
                    configuredAlgorithms.Add(
                        new SigningAlgorithmOptions(dilithiumSupportOptions.KeyManagementAlgorithm));
                    identityServerOptions.KeyManagement.SigningAlgorithms = configuredAlgorithms;
                });
            }
            builder.Services.AddTransient<IKeyManager, DilithiumKeyManager>();
            builder.Services.AddTransient<ISigningKeyProtector, DilithiumDataProtectionKeyProtector>();
            builder.Services.AddTransient<IDiscoveryResponseGenerator, DilithiumAwareDiscoveryResponseGenerator>();
        }

        return builder;
    }
    
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