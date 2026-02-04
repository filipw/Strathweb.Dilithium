# Strathweb.Dilithium

This repo contains a set of libraries facilitating and streamlining the integration of [Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final) signature scheme (a FIPS 204 Post-Quantum Cryptography suite, based on the original [Crystals-Dilithium](https://pq-crystals.org/dilithium/)) into ASP.NET Core projects - both for the purposes of token signing and their validation.

The libraries are intended to be used as the ASP.NET Core implementation of [ML-DSA for JOSE and COSE](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/) IETF draft.

While the type names all follow the ML-DSA convention, the naming of the library intentionally still refers to "Dilithium" (the original name before standardization), because it is cool 😎 

## PQC Backends

The library supports different PQC backends for the ML-DSA-44, ML-DSA-65 and ML-DSA-87 parameter sets.

The supported backends are:
 - `LibOqsPqcBackend` (default) - uses [Maybe LibOQS.NET](https://github.com/filipw/maybe-liboqs-dotnet) which wraps [liboqs](https://openquantumsafe.org/liboqs/)
 - `BouncyCastlePqcBackend` - uses the excellent [BouncyCastle](https://www.bouncycastle.org/csharp/)
 - `SystemCryptographyPqcBackend` - uses the built-in [System.Security.Cryptography](https://techcommunity.microsoft.com/blog/microsoft-security-blog/post-quantum-cryptography-apis-now-generally-available-on-microsoft-platforms/4469093) PQC APIs available in .NET 10+ (under certain OS and platform conditions)

## Available packages

### Strathweb.Dilithium.IdentityModel

[![NuGet](https://img.shields.io/nuget/v/Strathweb.Dilithium.IdentityModel.svg)](https://www.nuget.org/packages/Strathweb.Dilithium.IdentityModel/)

This is the base package on top of which other features can be built. Contains integration of ML-DSA into the ecosystem of [Microsoft.IdentityModel.Tokens](https://www.nuget.org/packages/Microsoft.IdentityModel.Tokens). Those are:

 - `MlDsaSecurityKey`, which implements `AsymmetricSecurityKey` abstract class
 - `MlDsaSignatureProvider`, which implements `SignatureProvider` abstract class
 - `MlDsaCryptoProviderFactory`, which extends the default `CryptoProviderFactory`

A new instance of a ML-DSA public-private pair can be created by using the main constructor that takes in the algorithm (`ML-DSA-44`, `ML-DSA-65` or `ML-DSA-87`) identifier. By default, it will use the `LibOqsPqcBackend`, but it is possible to provide a different backend.

```csharp
var securityKey = new MlDsaSecurityKey("ML-DSA-65"); // use default backend
var bcSecurityKey = new MlDsaSecurityKey("ML-DSA-65", new BouncyCastlePqcBackend()); // use BouncyCastle backend
```

The encoded private and public keys can then be read using the relevant properties:

```csharp
byte[] publicKey = securityKey.PublicKey;
byte[] privateKey = securityKey.PrivateKey;
```

They can also be exported out of process (e.g. using base64url encoding) and later used to re-initialize the key:

```csharp
var securityKey = new MlDsaSecurityKey("ML-DSA-65", keyId, publicKey, privateKey);
```

The private key is optional - in which case the key can still be used for signature validation but not longer for signing. 

The backend can also be specified here (optional, defaults to `LibOqsPqcBackend`):

```csharp
var securityKey = new MlDsaSecurityKey("ML-DSA-65", keyId, publicKey, privateKey, new BouncyCastlePqcBackend());
```

It is also possible to export the key to JSON Web Key format (where it is possible to decide whether the private key should be included or not):

```csharp
JsonWebKey jwk = securityKey.ToJsonWebKey(includePrivateKey: true);
```

Such a JWK can be serialized, persisted or published, and later re-imported:

```csharp
var securityKey = new MlDsaSecurityKey(jwk); // use default backend
var bcSecurityKey = new MlDsaSecurityKey(jwk, new BouncyCastlePqcBackend()); // use BouncyCastle backend
```

Depending on whether the JWK was exported with the private key or not, the instance of `MlDsaSecurityKey` will be suitable for signing or only for validation of signatures.

### Strathweb.Dilithium.DuendeIdentityServer

[![NuGet](https://img.shields.io/nuget/v/Strathweb.Dilithium.DuendeIdentityServer.svg)](https://www.nuget.org/packages/Strathweb.Dilithium.DuendeIdentityServer/)

Add-on to [Duende IdentityServer](https://duendesoftware.com/products/identityserver), which allows for registering a `MlDsaSecurityKey` as valid token signing credential. Once configured, the ML-DSA key can be used for token signing for API resources that are flagged as compatible with the ML-DSA algorithms. The public key is also going to get announced with the JWKS document.

Example usage:

#### Create an ephemeral public-private pair

This pair will be discarded upon application shutdown.

```csharp
builder.Services.AddIdentityServer()
    .AddMlDsaSigningCredential(new MlDsaSecurityKey("ML-DSA-65")) // new key per startup
```

#### Load an ML-DSA key from a JSON Web Key format

It is possible to manually load JWK (`Microsoft.IdentityModel.Tokens.JsonWebKey`) from some source, such as a key vault, and then use it to initialize the `MlDsaSecurityKey`:

```csharp
// load the JWK from somewhere e.g. KeyVault or filesystem
builder.Services.AddIdentityServer()
    .AddMlDsaSigningCredential(new MlDsaSecurityKey(jwk)) // key from the JWK
    // continue with the rest of Identity Server configuration
```

Alternatively, it can also be loaded from the file system (using a path relative to the current directory or an absolute one):

```csharp
builder.Services.AddIdentityServer()
    .AddMlDsaSigningCredential(pathToMlDsaJwk) // key from the JWK on the filesystem
    // continue with the rest of Identity Server configuration
```

#### Load an ML-DSA key from byte array public/private key representations

```csharp
// load the public key and private key from somewhere e.g. KeyVault or filesystem
string keyId = ...
byte[] privateKey = ...
byte[] publicKey = ...
builder.Services.AddIdentityServer()
    .AddMlDsaSigningCredential(new MlDsaSecurityKey("ML-DSA-65", keyId, publicKey, privateKey)) // key from the JWK
    // continue with the rest of Identity Server configuration
```

Once registered, the Identity Server will announce the public part of the ML-DSA key in the JWKS document. Other non-post quantum keys are allowed to co-exist. Example:

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

The library can also manage its own ML-DSA keys using Identity Server's [key management feature](https://docs.duendesoftware.com/identityserver/v5/fundamentals/keys/). 

```csharp
builder.Services.AddIdentityServer()
    .AddMlDsaSupport() // automatically manage ML-DSA keys
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
    .AddMlDsaSupport() // automatically manage ML-DSA keys
    // continue with the rest of Identity Server configuration
```

By default, the library disallows any other keys than ML-DSA, which means the built-in Identity Server behavior of generating RSA keys gets suppressed. It can be restored via the options. The same options can also be used to choose a different algorithm than `ML-DSA-65`:

```csharp
builder.Services.AddIdentityServer()
    .AddMlDsaSupport(new MlDsaSupportOptions {
        KeyManagementAlgorithm = "ML-DSA-87", // override the default "ML-DSA-65"
        DisallowNonMlDsaKeys = false, // allow RSA keys to co-exist
        Backend = new BouncyCastlePqcBackend() // use BouncyCastle backend
     }) // automatically manage ML-DSA keys
    // continue with the rest of Identity Server configuration
```

### Strathweb.Dilithium.AspNetCore

[![NuGet](https://img.shields.io/nuget/v/Strathweb.Dilithium.AspNetCore.svg)](https://www.nuget.org/packages/Strathweb.Dilithium.AspNetCore/)

Add-on for [Microsoft.AspNetCore.Authentication.JwtBearer](https://www.nuget.org/packages/Microsoft.AspNetCore.Authentication.JwtBearer) package, allowing for enabling ML-DSA-signed JWT token validation for the `Bearer` scheme.

Usage:

```csharp
builder.Services.AddAuthentication().AddJwtBearer(opt =>
{
    // all the usual necessary configuration such as authoritiy or audience
    // omitted for brevity
    
    // enable ML-DSA tokens
    opt.ConfigureMlDsaTokenSupport();
});
```

When ML-DSA token support is enabled, the extension takes over the management of JWKS fetched from the trusted authority. Those are cached for 24h, but this can be changed in the configuration.

By default any other tokens from the trusted authority are allowed as well. However, it is also possible to restrict the API to only accept ML-DSA based signing keys.

```csharp
builder.Services.AddAuthentication().AddJwtBearer(opt =>
{
    // all the usual necessary configuration such as authoritiy or audience
    // omitted for brevity
    
    // enable ML-DSA tokens
    opt.ConfigureMlDsaTokenSupport(dopt => 
    {
        dopt.AllowNonMlDsaKeys = false;
        dopt.Backend = new BouncyCastlePqcBackend();
    });
});
```

## License
[MIT](https://github.com/filipw/Strathweb.Dilithium/blob/main/LICENSE)
