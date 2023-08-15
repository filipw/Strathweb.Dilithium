using Duende.IdentityServer.Models;

namespace Strathweb.Dilithium.AspNetCore.Tests;

public static class Config
{
    public static IEnumerable<ApiScope> ApiScopes =>
        new List<ApiScope>
        {
            new ApiScope(name: "scope1", displayName: "Scope 1")
        };

    public static IEnumerable<ApiResource> ApiResources =>
        new List<ApiResource>
        {
            new ApiResource(name: "https://localhost:7104", displayName: "SampleApi") {
                Scopes = new HashSet<string> { "scope1" },
                AllowedAccessTokenSigningAlgorithms = new HashSet<string> { "CRYDI3" }
            }
        };

    public static IEnumerable<Client> Clients =>
        new Client[]
        {
            new Client
            {
                ClientId = "client",
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                ClientSecrets =
                {
                    new Secret("secret".Sha256())
                },
                AllowedScopes = { "scope1" }
            }
        };
}