using System.Text.Json;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.ResponseHandling;
using Duende.IdentityServer.Services.KeyManagement;
using Strathweb.Dilithium.DuendeIdentityServer;
using Strathweb.Dilithium.DuendeIdentityServer.KeyManagement;
using Strathweb.Dilithium.IdentityModel;
using JsonWebKey = Microsoft.IdentityModel.Tokens.JsonWebKey;

namespace IdentityServer;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        //var rawJwk = File.ReadAllText(Path.Combine(Directory.GetCurrentDirectory(), "ml-dsa-44.json"));
        //var jwk = JsonSerializer.Deserialize<JsonWebKey>(rawJwk);

        builder.Services.AddIdentityServer(opt =>
            {
                opt.EmitStaticAudienceClaim = true;
            })
            .AddMlDsaSupport() // automatic key management
            //.AddMlDsaSigningCredential(new MlDsaSecurityKey("ML-DSA-65")) // new fixed key per startup
            //.AddMlDsaSigningCredential(new MlDsaSecurityKey(jwk)) // fixed key from the filesystem / storage
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
