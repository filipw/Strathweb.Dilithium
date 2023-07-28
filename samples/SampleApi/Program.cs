using Microsoft.AspNetCore.Authorization;
using Strathweb.Dilithium.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddAuthentication().AddJwtBearer(opt =>
{
    opt.Authority = "https://localhost:5001";
    opt.Audience = "https://localhost:7104";
    opt.ConfigureDilithiumTokenSupport();
});

builder.Services.AddAuthorization(options =>
    options.AddPolicy("api", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("scope", "scope1");
    })
);

var app = builder.Build();
app.UseHttpsRedirection();
app.UseAuthorization();
app.MapGet("/demo", [Authorize("api")] (HttpContext context) => context.User.Claims.Select(c => new { c.Type, c.Value }));

app.Run();