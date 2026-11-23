namespace Totp;

/// <summary>An account to be registered, with its secret.</summary>
public sealed class NewAccount
{
    public NewAccount(Account account, string secret)
    {
        if (Base32.Decode(secret) is null)
        {
            throw TotpException.BadSecret();
        }
        Account = account;
        Secret = Base32.Normalize(secret);
    }

    public Account Account { get; }

    /// <summary>The base32 secret, normalised by <see cref="Base32.Normalize"/>.</summary>
    public string Secret { get; }
}
