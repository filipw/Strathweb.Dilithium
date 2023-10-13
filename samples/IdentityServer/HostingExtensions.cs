using System.Reflection;
using System.Text.Json;
using Duende.IdentityServer;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.ResponseHandling;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Services.KeyManagement;
using Duende.IdentityServer.Stores;
using Microsoft.IdentityModel.Tokens;
using Strathweb.Dilithium.DuendeIdentityServer;
using Strathweb.Dilithium.IdentityModel;
using JsonWebKey = Microsoft.IdentityModel.Tokens.JsonWebKey;

namespace IdentityServer;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        var rawJwk = File.ReadAllText(Path.Combine(Directory.GetCurrentDirectory(), "crydi3.json"));
        var jwk = JsonSerializer.Deserialize<JsonWebKey>(rawJwk);

        builder.Services.AddSingleton<IKeyManager, DilithiumKeyManager>();
        builder.Services.AddSingleton<ISigningKeyProtector, DilithiumDataProtectionKeyProtector>();
        builder.Services.AddSingleton<IDiscoveryResponseGenerator, DilithiumAwareDiscoveryResponseGenerator>();
        builder.Services.AddIdentityServer(opt =>
            {
                opt.EmitStaticAudienceClaim = true;
                opt.KeyManagement.SigningAlgorithms = new[]
                {
                    new SigningAlgorithmOptions("CRYDI3")
                };
            })
            //.AddDilithiumSigningCredential(new DilithiumSecurityKey("CRYDI3")) // new key per startup
            //.AddDilithiumSigningCredential(new DilithiumSecurityKey(jwk)) // key from the filesystem
            .AddInMemoryApiScopes(Config.ApiScopes)
            .AddInMemoryApiResources(Config.ApiResources)
            .AddInMemoryClients(Config.Clients);

        return builder.Build();
    }
    
    public static WebApplication ConfigurePipeline(this WebApplication app)
    { 
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseIdentityServer();
        return app;
    }
}
