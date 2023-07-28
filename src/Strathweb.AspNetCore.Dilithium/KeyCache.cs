using Microsoft.Extensions.Caching.Memory;

namespace Strathweb.AspNetCore.Dilithium;

internal class KeyCache
{
    public static readonly MemoryCache Default = new(new MemoryCacheOptions());
}