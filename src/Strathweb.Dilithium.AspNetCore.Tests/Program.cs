using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Strathweb.Dilithium.AspNetCore;
using Strathweb.Dilithium.AspNetCore.Tests;
using Strathweb.Dilithium.DuendeIdentityServer;
using Strathweb.Dilithium.IdentityModel;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = Directory.GetCurrentDirectory()
});

var key = new DilithiumSecurityKey("ML-DSA-65");
builder.Services.AddIdentityServer(opt => opt.EmitStaticAudienceClaim = true)
    .AddDilithiumSigningCredential(key) // new key per startup
    .AddInMemoryApiScopes(Config.ApiScopes)
    .AddInMemoryApiResources(Config.ApiResources)
    .AddInMemoryClients(Config.Clients);

builder.Services.AddAuthentication().AddJwtBearer(opt =>
{
    opt.Audience = "https://localhost:7104";
    opt.Configuration = new OpenIdConnectConfiguration { Issuer = "http://localhost/idp"};
    opt.ConfigureDilithiumTokenSupport(c =>
    {
        c.FixedSecurityKeys = new SecurityKey[] { key };
    });
});

builder.Services.AddAuthorization(options =>
    options.AddPolicy("api", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("scope", "scope1");
    })
);
        
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.Map("/idp", subapp =>
{
    subapp.UseIdentityServer();
});

app.Run(async ctx =>
{
    var authn = ctx.RequestServices.GetRequiredService<IAuthenticationService>();
    var authenticationResult = await authn.AuthenticateAsync(ctx, "Bearer");
    if (authenticationResult is { Succeeded: true, Principal: not null })
    {
        var authz = ctx.RequestServices.GetRequiredService<IAuthorizationService>();
        var authorizationResult = await authz.AuthorizeAsync(authenticationResult.Principal, "api");
        if (authorizationResult.Succeeded)
        {
            await ctx.Response.WriteAsync("hello!");
            return;
        }
    }
    
    ctx.Response.StatusCode = 401;
});

app.Run();

public partial class Program {}