# Strathweb.Dilithium

This repo contains a set of libraries facilitating and streamlining the integration of [Crystals-Dilithium](https://pq-crystals.org/dilithium/) signature scheme (a Post-Quantum Cryptography suite) into ASP.NET Core projects - both for the purposes of token signing and their validation.
The algorithm implementations come from the excellent [BouncyCastle](https://www.bouncycastle.org/csharp/).

The libraries are intended to be used as the ASP.NET Core implementation of [JOSE and COSE Encoding for Dilithium](https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium-01) IETF draft.

## Available packages

### Strathweb.Dilithium.IdentityModel

Contains integration of Dilithium into the ecosystem of [Microsoft.IdentityModel.Tokens](https://www.nuget.org/packages/Microsoft.IdentityModel.Tokens). Those are:

 - `DilithiumSecurityKey`, which implements `AsymmetricSecurityKey` abstract class
 - `DilithiumSignatureProvider`, which implements `SignatureProvider` abstract class
 - `DilithiumCryptoProviderFactory`, which extends the default `CryptoProviderFactory`

This is the base package on top of which other features can be built.

### Strathweb.Dilithium.DuendeIdentityServer

Add-on to [Duende IdentityServer](https://duendesoftware.com/products/identityserver), which allows for registering a `DilithiumSecurityKey` as valid token signing credential. Once configured, the Dilithium key can be used for token signing for API resources that are flagged as compatible with the Dilithium algorithms. The public key is also going to get announced with the JWKS document.

Example usage:

#### Create an in-memory public-private pair

```csharp
builder.Services.AddIdentityServer()
    .AddDilithiumSigningCredential(new DilithiumSecurityKey("CRYDI3")) // new key per startup
```

#### Load a Dilithium key from a JSON Web Key format 

```csharp
// load the JWK from somewhere e.g. KeyVault or filesystem
builder.Services.AddIdentityServer()
    .AddDilithiumSigningCredential(new DilithiumSecurityKey(jwk)) // key from the JWK
    // continue with the rest of IDentity Server configuration
```

Once registered, the Identity Server will announce the public part of the Dilithium key in the JWKS document. Other non-post quantum keys are allowed to co-exist. Example:

```json
{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "30F4....",
            "e": "AQAB",
            "n": "scmPFy....",
            "alg": "RS256"
        },
        {
            "kty": "MLWE",
            "use": "sig",
            "kid": "A574....",
            "alg": "CRYDI3",
            "x": "OMjMS...."
        }
    ]
}
```

The JWT tokens issued by the Identity Server will contains the `"alg": "CRYDI3"` in the header; otherwise the token will be indistinguishable from the other tokens.

### Strathweb.Dilithium.AspNetCore

Add-on for [Microsoft.AspNetCore.Authentication.JwtBearer](https://www.nuget.org/packages/Microsoft.AspNetCore.Authentication.JwtBearer) package, allowing for enabling Dilithium-signed JWT token validation for the `Bearer` scheme.

Usage:

```csharp
builder.Services.AddAuthentication().AddJwtBearer(opt =>
{
    // all the usual necessary configuration such as authoritiy or audience
    // omitted for brevity
    
    // enable Dilithium tokens
    opt.ConfigureDilithiumTokenSupport();
});
```

When Dilithium token support is enabled, the extension takes over the management of JWKS fetched from the trusted authority. Those are cached for 24h, but this can be changed in the configuration.
By default any other tokens from the trusted authority are allowed as well. However, it is also possible to restrict the API to only accept Dilithium based signing keys.

```csharp
builder.Services.AddAuthentication().AddJwtBearer(opt =>
{
    // all the usual necessary configuration such as authoritiy or audience
    // omitted for brevity
    
    // enable Dilithium tokens
    opt.ConfigureDilithiumTokenSupport(dopt => dopt.AllowNonMlweKeys = false;);
});
```