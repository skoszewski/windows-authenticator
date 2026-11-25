using System.Globalization;
using Totp;

namespace Vault;

/// <summary>A Vault token and when it ends; a token without an end has no expiry.</summary>
/// <param name="Lease">The lease length, as Vault stated it, for judging when to renew.</param>
public sealed record VaultToken(string Token, DateTimeOffset? Expires, bool Renewable, TimeSpan? Lease = null);

/// <summary>What the TOTP engine holds about a key, apart from its secret.</summary>
public sealed record VaultKeyInfo(string Name, string AccountName, string Issuer, string Algorithm, int Digits,
                                  int Period)
{
    /// <summary>A name for the account, <c>&lt;issuer&gt;: &lt;account name&gt;</c>, or whichever is set, or the key's name.</summary>
    public string SuggestedName => (Issuer.Length > 0, AccountName.Length > 0) switch
    {
        (true, true) => $"{Issuer}: {AccountName}",
        (true, false) => Issuer,
        (false, true) => AccountName,
        (false, false) => Name,
    };

    /// <summary>The account showing this key's codes, which have the key's algorithm, digits and period.</summary>
    public Account Account(string name, Guid? id = null) =>
        Totp.Account.FromText(id ?? Guid.NewGuid(), name, Issuer.Length == 0 ? null : Issuer, Algorithm,
                              Digits.ToString(CultureInfo.InvariantCulture),
                              Period.ToString(CultureInfo.InvariantCulture));
}

/// <summary>
/// A key Vault generated: its QR code as PNG data, when Vault made one, and its otpauth URL, which holds the
/// secret. Vault shows the secret only in the answer that creates the key.
/// </summary>
public sealed record GeneratedKey(byte[]? QrCode, string Url);
