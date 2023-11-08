using System.Text.Json;

namespace Strathweb.Dilithium.DuendeIdentityServer.KeyManagement;

internal static class KeySerializer
{
    static readonly JsonSerializerOptions Settings = new()
        {
            IncludeFields = true
        };

    public static string Serialize<T>(T item) => JsonSerializer.Serialize(item, item.GetType(), Settings);

    public static T Deserialize<T>(string json) => JsonSerializer.Deserialize<T>(json, Settings);
}