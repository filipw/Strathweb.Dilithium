using Microsoft.Extensions.Caching.Memory;

namespace Strathweb.Dilithium.IdentityModel;

internal class KeyCache
{
    public static readonly MemoryCache Default = new(new MemoryCacheOptions());
}