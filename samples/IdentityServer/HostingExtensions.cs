using System.Text.Json;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.ResponseHandling;
using Duende.IdentityServer.Services.KeyManagement;
using Strathweb.Dilithium.DuendeIdentityServer;
using Strathweb.Dilithium.DuendeIdentityServer.KeyManagement;
using JsonWebKey = Microsoft.IdentityModel.Tokens.JsonWebKey;

namespace IdentityServer;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        //var rawJwk = File.ReadAllText(Path.Combine(Directory.GetCurrentDirectory(), "crydi3.json"));
        //var jwk = JsonSerializer.Deserialize<JsonWebKey>(rawJwk);

        builder.Services.AddIdentityServer(opt =>
            {
                opt.EmitStaticAudienceClaim = true;
            })
            .AddDilithiumSupport() // automatic key management
            //.AddDilithiumSigningCredential(new DilithiumSecurityKey("CRYDI3")) // new fixed key per startup
            //.AddDilithiumSigningCredential(new DilithiumSecurityKey(jwk)) // fixed key from the filesystem / storage
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
