using System.Net;
using System.Net.Http.Headers;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Strathweb.Dilithium.DuendeIdentityServer;
using Strathweb.Dilithium.IdentityModel;
using Xunit;

namespace Strathweb.Dilithium.AspNetCore.Tests;

public class TokenIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{

    private readonly WebApplicationFactory<Program> _factory;

    public TokenIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }
    
    [Fact]
    public async Task AnonymousRequest401()
    {
        var client = _factory.CreateClient();
        
        var response = await client.GetAsync("/demo");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
    
    [Fact]
    public async Task CanFetchAndValidateToken()
    {
        var client = _factory.CreateClient();
        
        var token = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
        {
            Address = "/idp/connect/token",
            ClientId = "client",
            ClientSecret = "secret"
        });

        var apiRequest = new HttpRequestMessage(HttpMethod.Get, "/");
        apiRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
        var apiResponse = await client.SendAsync(apiRequest);
        Assert.Equal(HttpStatusCode.OK, apiResponse.StatusCode);
    }
}