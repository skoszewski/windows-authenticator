namespace Totp;

/// <summary>RFC 4648 base32, as TOTP secrets are written.</summary>
public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <summary>The secret in upper case without spaces, dashes and padding.</summary>
    public static string Normalize(string text) =>
        string.Concat(text.ToUpperInvariant().Where(c => c != ' ' && c != '=' && c != '-'));

    /// <summary>
    /// The bytes of a base32 text, case-insensitive, spaces, dashes and padding ignored; null for
    /// another character or no bytes at all.
    /// </summary>
    public static byte[]? Decode(string text)
    {
        var bytes = new List<byte>();
        uint buffer = 0;
        var bits = 0;
        foreach (var character in Normalize(text))
        {
            var value = Alphabet.IndexOf(character);
            if (value < 0)
            {
                return null;
            }
            buffer = (buffer << 5) | (uint)value;
            bits += 5;
            if (bits >= 8)
            {
                bits -= 8;
                bytes.Add((byte)((buffer >> bits) & 0xFF));
            }
        }
        return bytes.Count == 0 ? null : [.. bytes];
    }
}
