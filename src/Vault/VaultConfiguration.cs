namespace Vault;

/// <summary>How the app signs in to Vault.</summary>
public enum AuthMethod
{
    Token,
    Userpass,
    Approle,
    Oidc,
}

/// <summary>The names of the sign-in methods as Vault mounts them by default.</summary>
public static class AuthMethodNames
{
    /// <summary>The method's name: token, userpass, approle or oidc.</summary>
    public static string Name(this AuthMethod method) => method switch
    {
        AuthMethod.Token => "token",
        AuthMethod.Userpass => "userpass",
        AuthMethod.Approle => "approle",
        AuthMethod.Oidc => "oidc",
        _ => throw new ArgumentOutOfRangeException(nameof(method)),
    };

    /// <summary>The method of a name, in any case; null for an unknown name.</summary>
    public static AuthMethod? FromName(string? name) => name?.ToLowerInvariant() switch
    {
        "token" => AuthMethod.Token,
        "userpass" => AuthMethod.Userpass,
        "approle" => AuthMethod.Approle,
        "oidc" => AuthMethod.Oidc,
        _ => null,
    };
}

/// <summary>Where Vault is and how to sign in to it; it holds no secret.</summary>
public sealed record VaultConfiguration
{
    public const int DefaultOidcPort = 8250;

    public VaultConfiguration(string address, string? @namespace = null, string totpMount = "totp",
                              AuthMethod authMethod = AuthMethod.Token, string? authMount = null,
                              string? username = null, string? roleId = null, string? oidcRole = null,
                              int oidcPort = DefaultOidcPort)
    {
        Address = address;
        Namespace = @namespace;
        TotpMount = totpMount;
        AuthMethod = authMethod;
        AuthMount = authMount ?? authMethod.Name();
        Username = username;
        RoleId = roleId;
        OidcRole = oidcRole;
        OidcPort = oidcPort;
    }

    public string Address { get; init; }
    public string? Namespace { get; init; }
    public string TotpMount { get; init; }
    public AuthMethod AuthMethod { get; init; }
    public string AuthMount { get; init; }
    public string? Username { get; init; }
    public string? RoleId { get; init; }
    public string? OidcRole { get; init; }
    public int OidcPort { get; init; }

    /// <summary>The redirect URI the OIDC role must allow.</summary>
    public string OidcRedirectUri => $"http://localhost:{OidcPort}/oidc/callback";
}
