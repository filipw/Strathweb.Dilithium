using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.ResponseHandling;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Duende.IdentityServer.Validation;
using IdentityModel;

class DilithiumAwareDiscoveryResponseGenerator : DiscoveryResponseGenerator
{
    private readonly DilithiumCredentials _dilithiumCredentials;

    public DilithiumAwareDiscoveryResponseGenerator(IdentityServerOptions options, IResourceStore resourceStore, IKeyMaterialService keys, ExtensionGrantValidator extensionGrants, ISecretsListParser secretParsers, IResourceOwnerPasswordValidator resourceOwnerValidator, ILogger<DiscoveryResponseGenerator> logger, DilithiumCredentials dilithiumCredentials) : base(options, resourceStore, keys, extensionGrants, secretParsers, resourceOwnerValidator, logger)
    {
        _dilithiumCredentials = dilithiumCredentials;
    }

    public override async Task<IEnumerable<JsonWebKey>> CreateJwkDocumentAsync()
    {
        // see https://www.ietf.org/id/draft-ietf-cose-dilithium-00.html
        var current = await base.CreateJwkDocumentAsync();
        current = current.Append(new JsonWebKey
        {
            kty = "LWE",
            kid = _dilithiumCredentials.KeyId,
            x = Base64Url.Encode(_dilithiumCredentials.PublicKey.GetEncoded()),
            alg = _dilithiumCredentials.Alg,
            use = "sig"
        });

        return current;
    }
}