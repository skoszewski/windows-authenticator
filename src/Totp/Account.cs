using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;

namespace Totp;

/// <summary>The kind of an account: one that shows TOTP codes, or one that holds a plain secret.</summary>
public enum AccountKind
{
    Otp,
    Secret,
}

/// <summary>
/// A registered account: its name and, for an OTP account, the RFC 6238 parameters of its codes, without its
/// secret. A secret account holds a plain string and has no codes; its algorithm, digits and period are the
/// defaults, which nothing reads.
/// </summary>
public sealed record Account
{
    public const int MinDigits = 6;
    public const int MaxDigits = 10;

    public Account(Guid id, string name, string? issuer = null, Algorithm algorithm = Algorithm.Sha1,
                   int digits = 6, int period = 30)
    {
        if (digits is < MinDigits or > MaxDigits)
        {
            throw TotpException.BadDigits(digits.ToString(CultureInfo.InvariantCulture));
        }
        if (period < 1)
        {
            throw TotpException.BadPeriod(period.ToString(CultureInfo.InvariantCulture));
        }
        Id = id;
        Name = name;
        Issuer = issuer;
        Algorithm = algorithm;
        Digits = digits;
        Period = period;
    }

    public Account(string name, string? issuer = null, Algorithm algorithm = Algorithm.Sha1, int digits = 6,
                   int period = 30)
        : this(Guid.NewGuid(), name, issuer, algorithm, digits, period)
    {
    }

    /// <summary>A secret account, which asks the user to authenticate before its secret is shown or copied unless told not to.</summary>
    public static Account Secret(Guid id, string name, bool requiresAuthentication = true) =>
        new(id, name) { Kind = AccountKind.Secret, RequiresAuthentication = requiresAuthentication };

    public AccountKind Kind { get; private init; } = AccountKind.Otp;

    /// <summary>Whether showing or copying a secret account's secret asks the user to authenticate; nothing reads it for an OTP account.</summary>
    public bool RequiresAuthentication { get; init; } = true;
    public Guid Id { get; }
    public string Name { get; }
    public string? Issuer { get; }
    public Algorithm Algorithm { get; }
    public int Digits { get; }
    public int Period { get; }

    /// <summary>The algorithm, digits and period as <c>algorithm=SHA1&amp;digits=6&amp;period=30</c>.</summary>
    public string Parameters =>
        string.Create(CultureInfo.InvariantCulture, $"algorithm={Algorithm.Name()}&digits={Digits}&period={Period}");

    /// <summary>
    /// An account whose algorithm, digits and period are given as the text values of an otpauth URI or
    /// of <see cref="Parameters"/>; a value left out takes its default.
    /// </summary>
    public static Account FromText(Guid id, string name, string? issuer, string? algorithm, string? digits,
                                   string? period)
    {
        var hash = Algorithm.Sha1;
        if (algorithm is not null)
        {
            hash = AlgorithmNames.FromName(algorithm) ?? throw TotpException.BadAlgorithm(algorithm);
        }
        var digitCount = 6;
        if (digits is not null && !TryParseInt(digits, out digitCount))
        {
            throw TotpException.BadDigits(digits);
        }
        var seconds = 30;
        if (period is not null && !TryParseInt(period, out seconds))
        {
            throw TotpException.BadPeriod(period);
        }
        return new Account(id, name, issuer, hash, digitCount, seconds);
    }

    /// <summary>An account whose algorithm, digits and period are read from the <see cref="Parameters"/> form.</summary>
    public static Account FromParameters(Guid id, string name, string? issuer, string parameters)
    {
        var values = new Dictionary<string, string>();
        foreach (var pair in parameters.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2)
            {
                throw TotpException.BadParameters(parameters);
            }
            values[parts[0]] = parts[1];
        }
        return FromText(id, name, issuer, values.GetValueOrDefault("algorithm"), values.GetValueOrDefault("digits"),
                        values.GetValueOrDefault("period"));
    }

    /// <summary>The RFC 6238 code of the base32 secret at the given time.</summary>
    public string Code(string secret, DateTimeOffset time)
    {
        var counter = (ulong)Math.Floor(time.ToUnixTimeMilliseconds() / 1000.0 / Period);
        var message = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(message, counter);
        var key = Base32.Decode(secret) ?? [];
        var digest = Algorithm switch
        {
            Algorithm.Sha1 => HMACSHA1.HashData(key, message),
            Algorithm.Sha256 => HMACSHA256.HashData(key, message),
            Algorithm.Sha512 => HMACSHA512.HashData(key, message),
            _ => throw new InvalidOperationException(),
        };

        // Dynamic truncation of RFC 4226, section 5.3.
        var offset = digest[^1] & 0x0F;
        var value = BinaryPrimitives.ReadUInt32BigEndian(digest.AsSpan(offset, 4)) & 0x7FFF_FFFF;
        ulong modulus = 1;
        for (var i = 0; i < Digits; i++)
        {
            modulus *= 10;
        }
        return (value % modulus).ToString(CultureInfo.InvariantCulture).PadLeft(Digits, '0');
    }

    /// <summary>The whole seconds until the code of the given time changes.</summary>
    public int SecondsLeft(DateTimeOffset time)
    {
        var seconds = (long)Math.Floor(time.ToUnixTimeMilliseconds() / 1000.0);
        return Period - (int)(seconds % Period);
    }

    private static bool TryParseInt(string text, out int value) =>
        int.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value);
}
