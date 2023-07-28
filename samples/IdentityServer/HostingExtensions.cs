using System.Reflection;
using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.ResponseHandling;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.IdentityModel.Tokens;
using Strathweb.Dilithium.Duende;
using Strathweb.Dilithium.IdentityModel;

namespace IdentityServer;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentityServer(opt => opt.EmitStaticAudienceClaim = true)
            .AddDilithiumSigningCredential(new DilithiumSecurityKey("CRYDI3"))
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
