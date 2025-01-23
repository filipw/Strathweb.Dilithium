using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.ResponseHandling;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Duende.IdentityServer.Validation;
using Microsoft.Extensions.Logging;
using Strathweb.Dilithium.IdentityModel;

namespace Strathweb.Dilithium.DuendeIdentityServer.KeyManagement;

public class MlDsaAwareDiscoveryResponseGenerator : DiscoveryResponseGenerator
{
    public MlDsaAwareDiscoveryResponseGenerator(IdentityServerOptions options, IResourceStore resourceStore, IKeyMaterialService keys, ExtensionGrantValidator extensionGrants, ISecretsListParser secretParsers, IResourceOwnerPasswordValidator resourceOwnerValidator, ILogger<DiscoveryResponseGenerator> logger) : base(options, resourceStore, keys, extensionGrants, secretParsers, resourceOwnerValidator, logger)
    {
    }

    public override async Task<IEnumerable<JsonWebKey>> CreateJwkDocumentAsync()
    {
        var publishedKeys = (await base.CreateJwkDocumentAsync()).ToList();
        var mlDsaKeys = (await Keys.GetValidationKeysAsync()).Where(key => key.Key is MlDsaSecurityKey);

        foreach (var mlDsaKey in mlDsaKeys)
        {
            var jsonWebKey = (mlDsaKey.Key as MlDsaSecurityKey)?.ToJsonWebKey(includePrivateKey: false);
            var webKey = new JsonWebKey
            {
                kty = jsonWebKey.Kty,
                use = jsonWebKey.Use ?? "sig",
                kid = jsonWebKey.Kid,
                x5t = jsonWebKey.X5t,
                e = jsonWebKey.E,
                n = jsonWebKey.N,
                x5c = jsonWebKey.X5c?.Count == 0 ? null : jsonWebKey.X5c.ToArray(),
                alg = jsonWebKey.Alg,
                crv = jsonWebKey.Crv,
                x = jsonWebKey.X,
                y = jsonWebKey.Y
            };
            publishedKeys.Add(webKey);
        }

        return publishedKeys;
    }
}