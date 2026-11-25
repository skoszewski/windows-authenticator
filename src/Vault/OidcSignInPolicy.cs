namespace Vault;

/// <summary>What the identity provider sent to the redirect URI.</summary>
/// <param name="Error">The provider's <c>error_description</c>, or its <c>error</c>, when the login was refused.</param>
public sealed record OidcCallback(string? State, string? Code, string? Error)
{
    /// <summary>The callback in the query of the redirect URI.</summary>
    public static OidcCallback FromUri(Uri uri)
    {
        var values = new Dictionary<string, string>();
        foreach (var item in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var pair = item.Split('=', 2);
            values[Uri.UnescapeDataString(pair[0])] = pair.Length == 2 ? Uri.UnescapeDataString(pair[1]) : "";
        }
        return new OidcCallback(values.GetValueOrDefault("state"), values.GetValueOrDefault("code"),
                                values.GetValueOrDefault("error_description") ?? values.GetValueOrDefault("error"));
    }
}

/// <summary>What the sign-in window does with a navigation.</summary>
public abstract record OidcNavigation
{
    private OidcNavigation()
    {
    }

    /// <summary>The navigation is the redirect: the sign-in ends with the callback and the page is not loaded.</summary>
    public sealed record Callback(OidcCallback Value) : OidcNavigation;

    /// <summary>The page loads.</summary>
    public sealed record Allow : OidcNavigation;

    /// <summary>The navigation is refused, for the reason.</summary>
    public sealed record Block(string Reason) : OidcNavigation;
}

/// <summary>
/// Decides which navigations of the sign-in window may happen: the redirect URI ends the sign-in, pages over
/// HTTPS load, and everything else is refused.
/// </summary>
public sealed class OidcSignInPolicy(Uri redirect)
{
    public OidcNavigation Decide(string? address)
    {
        if (address is null || !Uri.TryCreate(address, UriKind.Absolute, out var uri))
        {
            return new OidcNavigation.Block("The page has no address.");
        }
        if (uri.Scheme == redirect.Scheme && uri.Host.Equals(redirect.Host, StringComparison.OrdinalIgnoreCase)
            && uri.Port == redirect.Port && uri.AbsolutePath == redirect.AbsolutePath)
        {
            return new OidcNavigation.Callback(OidcCallback.FromUri(uri));
        }
        return uri.Scheme switch
        {
            "https" => new OidcNavigation.Allow(),
            "about" when uri.OriginalString == "about:blank" => new OidcNavigation.Allow(),
            "http" => new OidcNavigation.Block($"The page {uri.Host} is not served over HTTPS."),
            _ => new OidcNavigation.Block($"Pages of the kind {uri.Scheme}: are not opened."),
        };
    }
}
