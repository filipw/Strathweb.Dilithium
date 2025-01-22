# Strathweb.Dilithium

This repo contains a set of libraries facilitating and streamlining the integration of [Crystals-Dilithium](https://pq-crystals.org/dilithium/) signature scheme (a Post-Quantum Cryptography suite) into ASP.NET Core projects - both for the purposes of token signing and their validation.

The algorithm implementations come from the excellent [BouncyCastle](https://www.bouncycastle.org/csharp/) and supports Dilithium2, Dilithium3 and Dilithium5 parameter sets.

The libraries are intended to be used as the ASP.NET Core implementation of [JOSE and COSE Encoding for Dilithium](https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium-01) IETF draft.

## Available packages

### Strathweb.Dilithium.IdentityModel

[![NuGet](https://img.shields.io/nuget/v/Strathweb.Dilithium.IdentityModel.svg)](https://www.nuget.org/packages/Strathweb.Dilithium.IdentityModel/)

This is the base package on top of which other features can be built. Contains integration of Dilithium into the ecosystem of [Microsoft.IdentityModel.Tokens](https://www.nuget.org/packages/Microsoft.IdentityModel.Tokens). Those are:

 - `DilithiumSecurityKey`, which implements `AsymmetricSecurityKey` abstract class
 - `DilithiumSignatureProvider`, which implements `SignatureProvider` abstract class
 - `DilithiumCryptoProviderFactory`, which extends the default `CryptoProviderFactory`

A new instance of a Dilithium public-private pair can be created by using the main constructor that takes in the algorithm (`ML-DSA-44`, `ML-DSA-65` or `ML-DSA-87`) identifier.

```csharp
var securityKey = new DilithiumSecurityKey("ML-DSA-65");
```

The encoded private and public keys can then be read using the relevant properties:

```csharp
byte[] publicKey = securityKey.PublicKey;
byte[] privateKey = securityKey.PrivateKey;
```

They can also be exported out of process (e.g. using base64url encoding) and later used to re-initialize the key:

```csharp
var securityKey = new DilithiumSecurityKey("ML-DSA-65", publicKey, privateKey);
```

The private key is optional - in which case the key can still be used for signature validation but not longer for signing. 

It is also possible to export the key to JSON Web Key format (where it is possible to decide whether the private key should be included or not):

```csharp
JsonWebKey jwk = securityKey.ToJsonWebKey(includePrivateKey: true);
```

Such a JWK can be serialized, persisted or published, and later re-imported:

```csharp
var securityKey = new DilithiumSecurityKey(jwk);
```

Depending on whether the JWK was exported with the private key or not, the instance of `DilithiumSecurityKey` will be suitable for signing or only for validation of signatures.

### Strathweb.Dilithium.DuendeIdentityServer

[![NuGet](https://img.shields.io/nuget/v/Strathweb.Dilithium.DuendeIdentityServer.svg)](https://www.nuget.org/packages/Strathweb.Dilithium.DuendeIdentityServer/)

Add-on to [Duende IdentityServer](https://duendesoftware.com/products/identityserver), which allows for registering a `DilithiumSecurityKey` as valid token signing credential. Once configured, the Dilithium key can be used for token signing for API resources that are flagged as compatible with the Dilithium algorithms. The public key is also going to get announced with the JWKS document.

Example usage:

#### Create an ephemeral public-private pair

This pair will be discarded upon application shutdown.

```csharp
builder.Services.AddIdentityServer()
    .AddDilithiumSigningCredential(new DilithiumSecurityKey("ML-DSA-65")) // new key per startup
```

#### Load a Dilithium key from a JSON Web Key format

It is possible to manually load JWK (`Microsoft.IdentityModel.Tokens.JsonWebKey`) from some source, such as a key vault, and then use it to initialize the `DilithiumSecurityKey`:

```csharp
// load the JWK from somewhere e.g. KeyVault or filesystem
builder.Services.AddIdentityServer()
    .AddDilithiumSigningCredential(new DilithiumSecurityKey(jwk)) // key from the JWK
    // continue with the rest of Identity Server configuration
```

Alternatively, it can also be loaded from the file system (using a path relative to the current directory or an absolute one):

```csharp
builder.Services.AddIdentityServer()
    .AddDilithiumSigningCredential(pathToDilithiumJWK) // key from the JWK on the filesystem
    // continue with the rest of Identity Server configuration
```

#### Load a Dilithium key from byte array public/private key representations

```csharp
// load the public key and private key from somewhere e.g. KeyVault or filesystem
byte[] privateKey = ...
byte[] publicKey = ...
builder.Services.AddIdentityServer()
    .AddDilithiumSigningCredential(new DilithiumSecurityKey("ML-DSA-65", publicKey, privateKey)) // key from the JWK
    // continue with the rest of Identity Server configuration
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
            "kty": "AKP",
            "use": "sig",
            "kid": "A574....",
            "alg": "ML-DSA-65",
            "x": "OMjMS...."
        }
    ]
}
```

The JWT tokens issued by the Identity Server will contains the `"alg": "ML-DSA-65"` in the header; otherwise the token will be indistinguishable from the other tokens.

#### Automatic key management

The library can also manage its own Dilithium keys using Identity Server's [key management feature](https://docs.duendesoftware.com/identityserver/v5/fundamentals/keys/). 

```csharp
builder.Services.AddIdentityServer()
    .AddDilithiumSupport() // automatically manage Dilithium keys
    // continue with the rest of Identity Server configuration
```

This set up instructs the library to create `ML-DSA-65` keys, store them securely and rotate them according to the schedule configured in Identity Server. By default, the keys are automatically rotated every 90 days, announced 14 days in advance, and retained for 14 days after it expires.

The normal customization of key management rules is still supported, and the library will respect those rules:

```csharp
builder.Services.AddIdentityServer(options =>
    {
        // new key every 14 days
        options.KeyManagement.RotationInterval = TimeSpan.FromDays(14);
        
        // announce new key 3 days in advance in discovery
        options.KeyManagement.PropagationTime = TimeSpan.FromDays(3);
        
        // keep old key for 3 days in discovery for validation of tokens
        options.KeyManagement.RetentionDuration = TimeSpan.FromDays(3);
    })
    .AddDilithiumSupport() // automatically manage Dilithium keys
    // continue with the rest of Identity Server configuration
```

By default, the library disallows any other keys than Dilithium, which means the built-in Identity Server behavior of generating RSA keys gets suppressed. It can be restored via the options. The same options can also be used to choose a different algorithm than `ML-DSA-65`:

```csharp
builder.Services.AddIdentityServer()
    .AddDilithiumSupport(new DilithiumSupportOptions {
        KeyManagementAlgorithm = "ML-DSA-87", // override the default "ML-DSA-65"
        DisallowNonDilithiumKeys = false // allow RSA keys to co-exist
     }) // automatically manage Dilithium keys
    // continue with the rest of Identity Server configuration
```

### Strathweb.Dilithium.AspNetCore

[![NuGet](https://img.shields.io/nuget/v/Strathweb.Dilithium.AspNetCore.svg)](https://www.nuget.org/packages/Strathweb.Dilithium.AspNetCore/)

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

## License
[MIT](https://github.com/filipw/Strathweb.Dilithium/blob/main/LICENSE)
