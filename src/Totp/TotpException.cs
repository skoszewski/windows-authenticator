namespace Totp;

/// <summary>Why an account could not be made from what was typed or stored.</summary>
public sealed class TotpException : FormatException
{
    private TotpException(string message) : base(message)
    {
    }

    public static TotpException BadSecret() =>
        new("The secret is not base32 (the letters A to Z and the digits 2 to 7).");

    public static TotpException BadDigits(string value) =>
        new($"The number of digits must be 6 to 10, not {value}.");

    public static TotpException BadPeriod(string value) =>
        new($"The period must be a whole number of seconds, at least 1, not {value}.");

    public static TotpException BadAlgorithm(string value) =>
        new($"The algorithm must be SHA1, SHA256 or SHA512, not {value}.");

    public static TotpException BadUri() =>
        new("The otpauth URI cannot be read.");

    public static TotpException NotTotp(string type) =>
        new($"Only time-based (totp) accounts are supported, not {type}.");

    public static TotpException MissingSecret() =>
        new("The otpauth URI holds no secret.");

    public static TotpException MissingName() =>
        new("Give the account a name.");

    public static TotpException BadParameters(string value) =>
        new($"The stored parameters {value} cannot be read.");
}
