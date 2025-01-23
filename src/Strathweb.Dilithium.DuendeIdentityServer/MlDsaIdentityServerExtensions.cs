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

public static class MlDsaIdentityServerExtensions
{
    public static IIdentityServerBuilder AddMlDsaSupport(this IIdentityServerBuilder builder)
    {
        return builder.AddMlDsaSupport(new MlDsaSupportOptions());
    }
    
    public static IIdentityServerBuilder AddMlDsaSupport(this IIdentityServerBuilder builder, MlDsaSupportOptions mlDsaSupportOptions)
    {
        if (builder == null) throw new ArgumentNullException(nameof(builder));
        if (mlDsaSupportOptions == null) throw new ArgumentNullException(nameof(mlDsaSupportOptions));
        
        if (mlDsaSupportOptions.EnableKeyManagement)
        {
            if (mlDsaSupportOptions.StaticKey != null)
            {
                throw new ArgumentException(
                    "It is not possible to use both automatic key management and a static key. Choose one or the other.");
            }
            
            if (mlDsaSupportOptions.KeyManagementAlgorithm != "ML-DSA-44" && mlDsaSupportOptions.KeyManagementAlgorithm != "ML-DSA-65" && mlDsaSupportOptions.KeyManagementAlgorithm != "ML-DSA-87")
            {
                throw new NotSupportedException(
                    $"Algorithm {mlDsaSupportOptions.KeyManagementAlgorithm} is not supported. Supported algorithms: ML-DSA-44, ML-DSA-65 and ML-DSA-87.");
            }
            
            if (mlDsaSupportOptions.DisallowNonMlDsaKeys)
            {
                builder.Services.Configure((IdentityServerOptions identityServerOptions) =>
                {
                    identityServerOptions.KeyManagement.Enabled = true;
                    identityServerOptions.KeyManagement.SigningAlgorithms = new[]
                    {
                        new SigningAlgorithmOptions(mlDsaSupportOptions.KeyManagementAlgorithm)
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
                        new SigningAlgorithmOptions(mlDsaSupportOptions.KeyManagementAlgorithm));
                    identityServerOptions.KeyManagement.SigningAlgorithms = configuredAlgorithms;
                });
            }
            builder.Services.AddTransient<IKeyManager, MlDsaKeyManager>();
            builder.Services.AddTransient<ISigningKeyProtector, MlDsaDataProtectionKeyProtector>();
            builder.Services.AddTransient<IDiscoveryResponseGenerator, MlDsaAwareDiscoveryResponseGenerator>();
        } 
        else if (mlDsaSupportOptions.StaticKey is { } fixedKey)
        {
            builder.AddMlDsaSigningCredential(fixedKey);
        }

        return builder;
    }
    
    public static IIdentityServerBuilder AddMlDsaSigningCredential(this IIdentityServerBuilder builder, MlDsaSecurityKey securityKey)
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
    
    public static IIdentityServerBuilder AddMlDsaSigningCredential(this IIdentityServerBuilder builder, string jwkPath)
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

        return builder.AddMlDsaSigningCredential(new MlDsaSecurityKey(jwk));
    }
}