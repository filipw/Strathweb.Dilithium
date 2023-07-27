using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Strathweb.AspNetCore.Dilithium;

public static class LweConfigurationExtensions
{
    public static void ConfigureLweTokenSupport(this JwtBearerOptions options) =>
        ConfigureLweTokenSupport(options, new LweTokenOptions());
    public static void ConfigureLweTokenSupport(this JwtBearerOptions options, LweTokenOptions lweTokenOptions)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));
        if (options.TokenValidationParameters == null) throw new ArgumentNullException(nameof(options.TokenValidationParameters));
        if (!lweTokenOptions.SupportedAlgorithms.Any())
        {
            return;
        }
        
        options.TokenValidationParameters.CryptoProviderFactory = new LweCryptoProviderFactory();
        options.TokenValidationParameters.IssuerSigningKeyResolver = (_, securityToken, kid, tokenValidationParameters) =>
        {
            if (securityToken is not JwtSecurityToken _)
            {
                return Enumerable.Empty<SecurityKey>();
            }

            if (!lweTokenOptions.DisableCache && KeyCache.Default.TryGetValue(kid, out var result) &&
                result is ICollection<SecurityKey> cachedSecurityKeys)
            {
                return cachedSecurityKeys;
            }

            var serverUrl = tokenValidationParameters.ValidIssuer ??
                            tokenValidationParameters.ValidIssuers.FirstOrDefault() ?? options.Authority;

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
                if (key is JsonWebKey jsonWebKey && Enum.TryParse<LweAlgorithm>(jsonWebKey.Alg, true, out var parsedAlg) && lweTokenOptions.SupportedAlgorithms.Contains(parsedAlg))
                {
                    processedKeys.Add(new LweSecurityKey(jsonWebKey, lweTokenOptions.SupportedAlgorithms));
                }
                else
                {
                    if (lweTokenOptions.AllowNonLweKeys)
                    {
                        processedKeys.Add(key);
                    }
                }
            }

            if (!lweTokenOptions.DisableCache)
            {
                KeyCache.Default.Set(kid, processedKeys,
                    TimeSpan.FromSeconds(lweTokenOptions.CacheLifetimeInSeconds));
            }

            return processedKeys;
        };
    }
}