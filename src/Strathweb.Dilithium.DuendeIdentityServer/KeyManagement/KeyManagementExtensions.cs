using Duende.IdentityServer.Configuration;
using Microsoft.AspNetCore.Authentication;

namespace Strathweb.Dilithium.DuendeIdentityServer.KeyManagement;

internal static class KeyManagementExtensions
{
    internal static bool IsRetired(this KeyManagementOptions options, TimeSpan age)
    {
        return (age >= options.KeyRetirementAge());
    }

    internal static bool IsExpired(this KeyManagementOptions options, TimeSpan age)
    {
        return (age >= options.RotationInterval);
    }
    
    internal static TimeSpan KeyRetirementAge(this KeyManagementOptions options)
    {
        return options.RotationInterval + options.RetentionDuration;
    }

    internal static bool IsWithinInitializationDuration(this KeyManagementOptions options, TimeSpan age)
    {
        return (age <= options.InitializationDuration);
    }

    internal static IEnumerable<string> AllowedSigningAlgorithmNames(this KeyManagementOptions options) 
        => options.SigningAlgorithms.Select(x => x.Name);

    internal static TimeSpan GetAge(this ISystemClock clock, DateTime date)
    {
        var now = clock.UtcNow.UtcDateTime;
        if (date > now) now = date;
        return now.Subtract(date);
    }
    
    internal static bool IsRsaKey(this SigningAlgorithmOptions opt) => opt.Name.StartsWith("R") || opt.Name.StartsWith("P");
    internal static bool IsEcKey(this SigningAlgorithmOptions opt) => opt.Name.StartsWith("E");
    internal static bool IsDilithiumKey(this SigningAlgorithmOptions opt) => opt.Name.StartsWith("CRYDI");
    
    internal static string GetCurveNameFromSigningAlgorithm(this SigningAlgorithmOptions opt)
    {
        return opt.Name switch
        {
            "ES256" => "P-256",
            "ES384" => "P-384",
            "ES512" => "P-521",
            _ => null
        };
    }
}