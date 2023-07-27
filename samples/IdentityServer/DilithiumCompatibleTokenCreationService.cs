using System.Text;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

public class DilithiumCompatibleTokenCreationService : DefaultTokenCreationService
{
    private readonly DilithiumCredentials _dilithiumCredentials;
    private readonly DilithiumSigner _signer;
    private readonly JsonWebTokenHandler _handler;

    static DilithiumCompatibleTokenCreationService() {
        var defaultHeaderParameters = new List<string>()
        {
            JwtHeaderParameterNames.X5t,
            JwtHeaderParameterNames.Enc,
            JwtHeaderParameterNames.Zip
        };

        typeof(JwtTokenUtilities).GetField("DefaultHeaderParameters", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static).SetValue(null, defaultHeaderParameters);
    }

    public DilithiumCompatibleTokenCreationService(ISystemClock clock, IKeyMaterialService keys, IdentityServerOptions options, ILogger<DefaultTokenCreationService> logger, DilithiumCredentials dilithiumCredentials) : base(clock, keys, options, logger)
    {
        _dilithiumCredentials = dilithiumCredentials;
        _signer = new DilithiumSigner();
        _signer.Init(true, _dilithiumCredentials.PrivateKey);
        _handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
    }

    protected override Task<string> CreateJwtAsync(Token token, string payload, Dictionary<string, object> headerElements)
    {
        if (!token.AllowedSigningAlgorithms.Contains(_dilithiumCredentials.Alg)) return base.CreateJwtAsync(token, payload, headerElements);

        headerElements["kid"] = _dilithiumCredentials.KeyId;
        headerElements["alg"] = _dilithiumCredentials.Alg;

        // strip last "." as the handler generates <header>.<payload>.<empty> becasue we did not ask it to sign
        var jwt = _handler.CreateToken(payload, headerElements);
        jwt = jwt.TrimEnd('.');

        var signature = _signer.GenerateSignature(Encoding.UTF8.GetBytes(jwt));
        return Task.FromResult($"{jwt}.{Base64Url.Encode(signature)}");
    }
}
