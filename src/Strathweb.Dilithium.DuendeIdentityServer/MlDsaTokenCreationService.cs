using Duende.IdentityServer;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json;

namespace Strathweb.Dilithium.DuendeIdentityServer;

public class MlDsaTokenCreationService : DefaultTokenCreationService
{
    public MlDsaTokenCreationService(
        IClock clock,
        IKeyMaterialService keys,
        IdentityServerOptions options,
        ILogger<DefaultTokenCreationService> logger)
        : base(clock, keys, options, logger)
    {
    }

    protected override async Task<string> CreateJwtAsync(Token token, string payload, Dictionary<string, object> headerElements)
    {
        var credential = await Keys.GetSigningCredentialsAsync(token.AllowedSigningAlgorithms);
        if (credential == null) throw new InvalidOperationException("No signing credential configured.");

        // this is is necessary because JsonWebTokenHandler has a hardcoded internal limits on buffer sizes
        // if it does not recognize the algorithm, it falls back to a 2048 byte buffer size which is too small for ML-DSA signatures
        if (credential.Algorithm.StartsWith("ML-DSA"))
        {
            return CreateMlDsaToken(credential, payload, headerElements);
        }

        // use base for everything else
        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.CreateToken(payload, credential, headerElements);
    }

    private string CreateMlDsaToken(SigningCredentials credential, string payloadJson, Dictionary<string, object> extraHeaderElements)
    {
        // first construct the header
        var header = new Dictionary<string, object>(extraHeaderElements ?? new Dictionary<string, object>());
        header[JwtHeaderParameterNames.Alg] = credential.Algorithm;
        if (!string.IsNullOrEmpty(credential.Key.KeyId))
        {
            header[JwtHeaderParameterNames.Kid] = credential.Key.KeyId;
        }

        if (credential.Key is X509SecurityKey x509Key)
        {
            // calculate SHA-1 hash of the cert and Base64UrlEncode it
            var certHash = x509Key.Certificate.GetCertHash();
            header[JwtHeaderParameterNames.X5t] = Base64UrlEncoder.Encode(certHash);
        }

        // serialize and encode
        var headerJson = JsonSerializer.Serialize(header);
        var encodedHeader = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerJson));
        var encodedPayload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payloadJson));

        // sign!
        var dataToSign = encodedHeader + "." + encodedPayload;
        byte[] dataBytes = Encoding.ASCII.GetBytes(dataToSign);

        byte[] signatureBytes;
        using (var cryptoProvider = credential.Key.CryptoProviderFactory.CreateForSigning(credential.Key, credential.Algorithm))
        {
            signatureBytes = cryptoProvider.Sign(dataBytes);
        }

        var encodedSignature = Base64UrlEncoder.Encode(signatureBytes);
        return encodedHeader + "." + encodedPayload + "." + encodedSignature;
    }
}