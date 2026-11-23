namespace Totp.Tests;

[TestClass]
public sealed class ParseTests
{
    /// <summary>The parsed account as name|issuer|secret|algorithm|digits|period, or the error message.</summary>
    private static string Parsed(string name, string input)
    {
        try
        {
            var created = OtpAuth.Parse(name, input);
            var account = created.Account;
            return $"{account.Name}|{account.Issuer ?? "-"}|{created.Secret}|{account.Algorithm.Name()}|{account.Digits}|{account.Period}";
        }
        catch (TotpException error)
        {
            return $"error: {error.Message}";
        }
    }

    /// <summary>Typed name, typed secret or URI, and the expected result of <see cref="Parsed"/>.</summary>
    [TestMethod]
    [DataRow("Box", "jbsw y3dp ehpk 3pxp==", "Box|-|JBSWY3DPEHPK3PXP|SHA1|6|30")]
    [DataRow("", "JBSWY3DPEHPK3PXP", "error: Give the account a name.")]
    [DataRow("Box", "JBSWY3DP1", "error: The secret is not base32 (the letters A to Z and the digits 2 to 7).")]
    [DataRow("", "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
             "Example: alice@google.com|Example|JBSWY3DPEHPK3PXP|SHA1|6|30")]
    [DataRow("", "otpauth://totp/Big%20Corporation%3A%20alice%40bigco.com?secret=JBSWY3DPEHPK3PXP",
             "Big Corporation: alice@bigco.com|Big Corporation|JBSWY3DPEHPK3PXP|SHA1|6|30")]
    [DataRow("", "otpauth://totp/Old:bob?secret=JBSWY3DPEHPK3PXP&issuer=New%20Name",
             "New Name: bob|New Name|JBSWY3DPEHPK3PXP|SHA1|6|30")]
    [DataRow("Router", "OTPAUTH://TOTP/lcr?secret=jbswy3dpehpk3pxp&algorithm=sha256&digits=8&period=60",
             "Router|-|JBSWY3DPEHPK3PXP|SHA256|8|60")]
    [DataRow("", "otpauth://totp/otp?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512&digits=10&period=30",
             "otp|-|JBSWY3DPEHPK3PXP|SHA512|10|30")]
    [DataRow("", "otpauth://totp/x?issuer=y", "error: The otpauth URI holds no secret.")]
    [DataRow("", "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1",
             "error: Only time-based (totp) accounts are supported, not hotp.")]
    [DataRow("", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=11",
             "error: The number of digits must be 6 to 10, not 11.")]
    [DataRow("", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
             "error: The period must be a whole number of seconds, at least 1, not 0.")]
    [DataRow("", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
             "error: The algorithm must be SHA1, SHA256 or SHA512, not MD5.")]
    public void SecretsAndOtpAuthUris(string name, string input, string expected)
    {
        Assert.AreEqual(expected, Parsed(name, input));
    }
}
