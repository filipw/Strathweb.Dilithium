using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Strathweb.Dilithium.IdentityModel;

namespace Strathweb.Dilithium.AspNetCore;

public static class DilithiumConfigurationExtensions
{
    public static void ConfigureDilithiumTokenSupport(this JwtBearerOptions options) =>
        ConfigureDilithiumTokenSupportInternal(options, null);

    public static void ConfigureDilithiumTokenSupport(this JwtBearerOptions options,
        Action<DilithiumTokenOptions> configurationDelegate) =>
        ConfigureDilithiumTokenSupportInternal(options, configurationDelegate);

    private static void ConfigureDilithiumTokenSupportInternal(JwtBearerOptions options,
        Action<DilithiumTokenOptions>? configurationDelegate)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));
        if (options.TokenValidationParameters == null) throw new ArgumentNullException(nameof(options.TokenValidationParameters));
        var dilithiumTokenOptions = new DilithiumTokenOptions();

        configurationDelegate?.Invoke(dilithiumTokenOptions);
        if (!dilithiumTokenOptions.SupportedAlgorithms.Any())
        {
            return;
        }
        
        var lweCryptoProvideFactory = new DilithiumCryptoProviderFactory();
        options.TokenValidationParameters.IssuerSigningKeyResolver = (_, securityToken, kid, tokenValidationParameters) =>
        {
            if (securityToken is not JwtSecurityToken && securityToken is not JsonWebToken)
            {
                return Enumerable.Empty<SecurityKey>();
            }

            if (dilithiumTokenOptions.FixedSecurityKeys.Any())
            {
                return dilithiumTokenOptions.FixedSecurityKeys;
            }

            if (!dilithiumTokenOptions.DisableCache && KeyCache.Default.TryGetValue(kid, out var result) &&
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
                if (key is JsonWebKey jsonWebKey && Enum.TryParse<MlweAlgorithm>(jsonWebKey.Alg, true, out var parsedAlg) && dilithiumTokenOptions.SupportedAlgorithms.Contains(parsedAlg))
                {
                    processedKeys.Add(new DilithiumSecurityKey(jsonWebKey)
                    {
                        CryptoProviderFactory = lweCryptoProvideFactory
                    });
                }
                else
                {
                    if (dilithiumTokenOptions.AllowNonMlweKeys)
                    {
                        processedKeys.Add(key);
                    }
                }
            }

            if (!dilithiumTokenOptions.DisableCache)
            {
                KeyCache.Default.Set(kid, processedKeys,
                    TimeSpan.FromSeconds(dilithiumTokenOptions.CacheLifetimeInSeconds));
            }

            return processedKeys;
        };
    }
}