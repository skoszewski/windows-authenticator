namespace Totp;

/// <summary>Accounts read from what is typed in the Add Account dialog.</summary>
public static class OtpAuth
{
    /// <summary>
    /// An account from a typed name and a base32 secret or an otpauth://totp/ URI; an empty name is
    /// taken from the URI's issuer and account name.
    /// </summary>
    public static NewAccount Parse(string typedName, string input)
    {
        var name = typedName.Trim();
        var text = input.Trim();
        if (!text.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
        {
            if (name.Length == 0)
            {
                throw TotpException.MissingName();
            }
            return new NewAccount(new Account(name), text);
        }

        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri))
        {
            throw TotpException.BadUri();
        }
        var type = uri.Host.ToLowerInvariant();
        if (type != "totp")
        {
            throw TotpException.NotTotp(type.Length == 0 ? "an empty type" : type);
        }
        var parameters = new Dictionary<string, string>();
        foreach (var item in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = item.Split('=', 2);
            parameters[Uri.UnescapeDataString(parts[0]).ToLowerInvariant()] =
                parts.Length == 2 ? Uri.UnescapeDataString(parts[1]) : "";
        }

        // The label is the account name, optionally after the issuer and a colon.
        var label = Uri.UnescapeDataString(uri.AbsolutePath).TrimStart('/');
        string? labelIssuer = null;
        var accountName = label;
        var colon = label.IndexOf(':');
        if (colon >= 0)
        {
            labelIssuer = label[..colon].Trim();
            accountName = label[(colon + 1)..];
        }
        accountName = accountName.Trim();
        var issuer = new[] { parameters.GetValueOrDefault("issuer"), labelIssuer }
            .Select(value => value?.Trim())
            .FirstOrDefault(value => !string.IsNullOrEmpty(value));

        var secret = parameters.GetValueOrDefault("secret");
        if (string.IsNullOrEmpty(secret))
        {
            throw TotpException.MissingSecret();
        }

        // The typed name wins; else the issuer and the account name of the URI.
        var resolvedName = name;
        if (resolvedName.Length == 0)
        {
            resolvedName = (issuer, accountName.Length > 0) switch
            {
                (not null, true) => $"{issuer}: {accountName}",
                (not null, false) => issuer,
                (null, true) => accountName,
                (null, false) => throw TotpException.MissingName(),
            };
        }
        var account = Account.FromText(Guid.NewGuid(), resolvedName, issuer, parameters.GetValueOrDefault("algorithm"),
                                       parameters.GetValueOrDefault("digits"), parameters.GetValueOrDefault("period"));
        return new NewAccount(account, secret);
    }
}
