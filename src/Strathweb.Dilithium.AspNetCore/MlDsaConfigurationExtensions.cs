using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Strathweb.Dilithium.IdentityModel;

namespace Strathweb.Dilithium.AspNetCore;

public static class MlDsaConfigurationExtensions
{
    public static void ConfigureMlDsaTokenSupport(this JwtBearerOptions options) =>
        ConfigureMlDsaTokenSupportInternal(options, null);

    public static void ConfigureMlDsaTokenSupport(this JwtBearerOptions options,
        Action<MlDsaTokenOptions> configurationDelegate) =>
        ConfigureMlDsaTokenSupportInternal(options, configurationDelegate);

    private static void ConfigureMlDsaTokenSupportInternal(JwtBearerOptions options,
        Action<MlDsaTokenOptions>? configurationDelegate)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));
        if (options.TokenValidationParameters == null) throw new ArgumentNullException(nameof(options.TokenValidationParameters));
        var mlDsaTokenOptions = new MlDsaTokenOptions();

        configurationDelegate?.Invoke(mlDsaTokenOptions);
        if (!mlDsaTokenOptions.SupportedAlgorithms.Any())
        {
            return;
        }
        
        var mlDsaCryptoProviderFactory = new MlDsaCryptoProviderFactory();
        options.TokenValidationParameters.IssuerSigningKeyResolver = (_, securityToken, kid, tokenValidationParameters) =>
        {
            if (securityToken is not JwtSecurityToken && securityToken is not JsonWebToken)
            {
                return Enumerable.Empty<SecurityKey>();
            }

            if (mlDsaTokenOptions.FixedSecurityKeys.Any())
            {
                return mlDsaTokenOptions.FixedSecurityKeys;
            }

            if (!mlDsaTokenOptions.DisableCache && KeyCache.Default.TryGetValue(kid, out var result) &&
                result is ICollection<SecurityKey> cachedSecurityKeys)
            {
                return cachedSecurityKeys;
            }

            var serverUrl = tokenValidationParameters.ValidIssuer ??
                            tokenValidationParameters.ValidIssuers?.FirstOrDefault() ?? options.Authority;

            if (serverUrl == null)
                throw new Exception(
                    "Impossible to determine the issuer. Make sure to set Authority of the JwtBearerOptions.Authority, TokenValidationParameters.ValidIssuer or TokenValidationParameters.ValidIssuers");
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>($"{serverUrl.TrimEnd('/')}/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever());
            
            JsonWebKeySet.DefaultSkipUnresolvedJsonWebKeys = false;
            
            var config = configManager.GetConfigurationAsync().GetAwaiter().GetResult();
            if (config?.SigningKeys is null || !config.SigningKeys.Any())
            {
                return Enumerable.Empty<SecurityKey>();
            }

            var matchingKeys = config.SigningKeys.Where(key => key.KeyId == kid).ToArray();
            if (!matchingKeys.Any())
            {
                return Enumerable.Empty<SecurityKey>();
            }

            var processedKeys = new List<SecurityKey>();
            foreach (var key in matchingKeys)
            {
                if (key is JsonWebKey jsonWebKey && Enum.TryParse<AkpAlgorithm>(jsonWebKey.Alg.Replace("-",""), true, out var parsedAlg) && mlDsaTokenOptions.SupportedAlgorithms.Contains(parsedAlg))
                {
                    processedKeys.Add(new MlDsaSecurityKey(jsonWebKey)
                    {
                        CryptoProviderFactory = mlDsaCryptoProviderFactory
                    });
                }
                else
                {
                    if (mlDsaTokenOptions.AllowNonMlDsaKeys)
                    {
                        processedKeys.Add(key);
                    }
                }
            }

            if (!mlDsaTokenOptions.DisableCache)
            {
                KeyCache.Default.Set(kid, processedKeys,
                    TimeSpan.FromSeconds(mlDsaTokenOptions.CacheLifetimeInSeconds));
            }

            return processedKeys;
        };
    }
}