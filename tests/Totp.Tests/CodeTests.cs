using System.Text;

namespace Totp.Tests;

[TestClass]
public sealed class CodeTests
{
    private const string OtpPySecret = "URA3F2HGC7E47VE5A7PTOJOJLJT7EYT6";

    /// <summary>The base32 text of an ASCII seed, as the RFC 6238 seeds are given.</summary>
    private static string ToBase32(string ascii)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var text = new StringBuilder();
        uint buffer = 0;
        var bits = 0;
        foreach (var b in Encoding.ASCII.GetBytes(ascii))
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                text.Append(alphabet[(int)((buffer >> bits) & 0x1F)]);
            }
        }
        if (bits > 0)
        {
            text.Append(alphabet[(int)((buffer << (5 - bits)) & 0x1F)]);
        }
        return text.ToString();
    }

    private static string RfcSeed(Algorithm algorithm) => algorithm switch
    {
        Algorithm.Sha1 => "12345678901234567890",
        Algorithm.Sha256 => "12345678901234567890123456789012",
        _ => "1234567890123456789012345678901234567890123456789012345678901234",
    };

    private static DateTimeOffset At(long milliseconds) => DateTimeOffset.FromUnixTimeMilliseconds(milliseconds);

    /// <summary>The test vectors of RFC 6238 Appendix B: time in seconds, algorithm, 8-digit code.</summary>
    [TestMethod]
    [DataRow(59L, Algorithm.Sha1, "94287082")]
    [DataRow(59L, Algorithm.Sha256, "46119246")]
    [DataRow(59L, Algorithm.Sha512, "90693936")]
    [DataRow(1111111109L, Algorithm.Sha1, "07081804")]
    [DataRow(1111111109L, Algorithm.Sha256, "68084774")]
    [DataRow(1111111109L, Algorithm.Sha512, "25091201")]
    [DataRow(1111111111L, Algorithm.Sha1, "14050471")]
    [DataRow(1111111111L, Algorithm.Sha256, "67062674")]
    [DataRow(1111111111L, Algorithm.Sha512, "99943326")]
    [DataRow(1234567890L, Algorithm.Sha1, "89005924")]
    [DataRow(1234567890L, Algorithm.Sha256, "91819424")]
    [DataRow(1234567890L, Algorithm.Sha512, "93441116")]
    [DataRow(2000000000L, Algorithm.Sha1, "69279037")]
    [DataRow(2000000000L, Algorithm.Sha256, "90698825")]
    [DataRow(2000000000L, Algorithm.Sha512, "38618901")]
    [DataRow(20000000000L, Algorithm.Sha1, "65353130")]
    [DataRow(20000000000L, Algorithm.Sha256, "77737706")]
    [DataRow(20000000000L, Algorithm.Sha512, "47863826")]
    public void Rfc6238(long seconds, Algorithm algorithm, string expected)
    {
        var account = new Account("rfc", algorithm: algorithm, digits: 8);
        Assert.AreEqual(expected, account.Code(ToBase32(RfcSeed(algorithm)), At(seconds * 1000)));
    }

    /// <summary>
    /// Codes printed by <c>otp.py code</c> of linux-cloud-router for one secret with a 45 s period:
    /// time in milliseconds, algorithm, digits, code.
    /// </summary>
    [TestMethod]
    [DataRow(0L, Algorithm.Sha1, 6, "807499")]
    [DataRow(0L, Algorithm.Sha1, 10, "0447807499")]
    [DataRow(1700000000000L, Algorithm.Sha1, 6, "520751")]
    [DataRow(1700000000000L, Algorithm.Sha1, 10, "0192520751")]
    [DataRow(1999999999500L, Algorithm.Sha1, 6, "545436")]
    [DataRow(1999999999500L, Algorithm.Sha1, 10, "2027545436")]
    [DataRow(0L, Algorithm.Sha256, 6, "467694")]
    [DataRow(0L, Algorithm.Sha256, 10, "0151467694")]
    [DataRow(1700000000000L, Algorithm.Sha256, 6, "143759")]
    [DataRow(1700000000000L, Algorithm.Sha256, 10, "1590143759")]
    [DataRow(1999999999500L, Algorithm.Sha256, 6, "893692")]
    [DataRow(1999999999500L, Algorithm.Sha256, 10, "1391893692")]
    [DataRow(0L, Algorithm.Sha512, 6, "038044")]
    [DataRow(0L, Algorithm.Sha512, 10, "2145038044")]
    [DataRow(1700000000000L, Algorithm.Sha512, 6, "271912")]
    [DataRow(1700000000000L, Algorithm.Sha512, 10, "1853271912")]
    [DataRow(1999999999500L, Algorithm.Sha512, 6, "396365")]
    [DataRow(1999999999500L, Algorithm.Sha512, 10, "1722396365")]
    public void SameCodesAsOtpPy(long milliseconds, Algorithm algorithm, int digits, string expected)
    {
        var account = new Account("otp.py", algorithm: algorithm, digits: digits, period: 45);
        Assert.AreEqual(expected, account.Code(OtpPySecret, At(milliseconds)));
    }

    [TestMethod]
    public void SixDigitsByDefault()
    {
        var account = new Account("rfc");
        Assert.AreEqual("287082", account.Code(ToBase32(RfcSeed(Algorithm.Sha1)), At(59_000)));
    }

    [TestMethod]
    public void ParametersRoundTrip()
    {
        var account = new Account("x", algorithm: Algorithm.Sha512, digits: 10, period: 45);
        Assert.AreEqual("algorithm=SHA512&digits=10&period=45", account.Parameters);
        var read = Account.FromParameters(account.Id, "x", null, account.Parameters);
        Assert.AreEqual(account, read);
    }

    [TestMethod]
    public void BadParameters()
    {
        var noValue = Assert.ThrowsExactly<TotpException>(() => Account.FromParameters(Guid.NewGuid(), "x", null, "digits"));
        Assert.AreEqual(TotpException.BadParameters("digits").Message, noValue.Message);
        var fewDigits = Assert.ThrowsExactly<TotpException>(
            () => Account.FromParameters(Guid.NewGuid(), "x", null, "algorithm=SHA1&digits=5&period=30"));
        Assert.AreEqual(TotpException.BadDigits("5").Message, fewDigits.Message);
    }

    [TestMethod]
    public void SecondsLeft()
    {
        var account = new Account("rfc");
        Assert.AreEqual(1, account.SecondsLeft(At(59_000)));
        Assert.AreEqual(30, account.SecondsLeft(At(60_000)));
    }

    [TestMethod]
    public void Base32Decoding()
    {
        byte[] expected = [.. Encoding.ASCII.GetBytes("Hello!"), 0xDE, 0xAD, 0xBE, 0xEF];
        CollectionAssert.AreEqual(expected, Base32.Decode("jbsw y3dp-ehpk 3pxp=="));
        Assert.IsNull(Base32.Decode("JBSWY3DP1"));
        Assert.IsNull(Base32.Decode(""));
    }
}
