namespace Totp;

/// <summary>The HMAC hash of an account's codes.</summary>
public enum Algorithm
{
    Sha1,
    Sha256,
    Sha512,
}

/// <summary>The names of the algorithms as otpauth URIs and the stored parameters write them.</summary>
public static class AlgorithmNames
{
    /// <summary>The name of the algorithm: SHA1, SHA256 or SHA512.</summary>
    public static string Name(this Algorithm algorithm) => algorithm switch
    {
        Algorithm.Sha1 => "SHA1",
        Algorithm.Sha256 => "SHA256",
        Algorithm.Sha512 => "SHA512",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    /// <summary>The algorithm of a name, in any case; null for an unknown name.</summary>
    public static Algorithm? FromName(string name) => name.ToUpperInvariant() switch
    {
        "SHA1" => Algorithm.Sha1,
        "SHA256" => Algorithm.Sha256,
        "SHA512" => Algorithm.Sha512,
        _ => null,
    };
}
