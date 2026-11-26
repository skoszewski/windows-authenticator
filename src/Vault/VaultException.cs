using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Vault;

/// <summary>The kind of a failed Vault call.</summary>
public enum VaultErrorKind
{
    BadAddress,
    Http,
    BadResponse,
    NotSignedIn,
    Oidc,
    KeyExists,
    UnsupportedKey,
    Transport,
    NoSecret,
    MissingField,
    SecretDeleted,
    WriteLost,
}

/// <summary>What was wrong with the certificate of a refused TLS connection.</summary>
public sealed record CertificateErrors(SslPolicyErrors PolicyErrors, X509ChainStatusFlags ChainStatus);

/// <summary>Why a Vault call did not succeed.</summary>
public sealed class VaultException : Exception
{
    private VaultException(VaultErrorKind kind, string message, string value = "", int status = 0,
                           IReadOnlyList<string>? messages = null, Exception? inner = null,
                           CertificateErrors? certificate = null)
        : base(message, inner)
    {
        Kind = kind;
        Value = value;
        Status = status;
        Messages = messages ?? [];
        Certificate = certificate;
    }

    public VaultErrorKind Kind { get; }

    /// <summary>
    /// The address, the unreadable part, the message, the key name, the reason, the host, the secret's name or the
    /// field of the error.
    /// </summary>
    public string Value { get; }

    /// <summary>The HTTP status of an <see cref="VaultErrorKind.Http"/> error.</summary>
    public int Status { get; }

    /// <summary>Vault's messages of an <see cref="VaultErrorKind.Http"/> error, or the secret of a missing field.</summary>
    public IReadOnlyList<string> Messages { get; }

    /// <summary>The certificate's errors of a <see cref="VaultErrorKind.Transport"/> error refused in the TLS handshake.</summary>
    public CertificateErrors? Certificate { get; }

    /// <summary>Whether Vault denied the call: a token it does not accept, or a policy that lacks the path.</summary>
    public bool IsDenied => Kind == VaultErrorKind.Http && Status == 403;

    public static VaultException BadAddress(string address) =>
        new(VaultErrorKind.BadAddress, $"{address} is not a Vault address; use the form https://vault.example.com:8200.",
            address);

    public static VaultException Http(int status, IReadOnlyList<string> messages) =>
        new(VaultErrorKind.Http,
            $"Vault answered {status}: {(messages.Count == 0 ? "no message" : string.Join("; ", messages))}",
            status: status, messages: messages);

    public static VaultException BadResponse(string what) =>
        new(VaultErrorKind.BadResponse, $"Vault's answer could not be read: {what}", what);

    public static VaultException NotSignedIn() => new(VaultErrorKind.NotSignedIn, "Not signed in to Vault.");

    public static VaultException Oidc(string message) =>
        new(VaultErrorKind.Oidc, $"The OIDC sign-in failed: {message}", message);

    public static VaultException KeyExists(string name) =>
        new(VaultErrorKind.KeyExists, $"Vault holds a key named {name} already; choose another name.", name);

    public static VaultException UnsupportedKey(string reason) =>
        new(VaultErrorKind.UnsupportedKey, $"Vault cannot keep this key: {reason}", reason);

    public static VaultException NoSecret(string name) =>
        new(VaultErrorKind.NoSecret, $"Vault holds no secret named {name}.", name);

    /// <summary>A secret without the field; the value is the field, the messages hold the secret's name.</summary>
    public static VaultException MissingField(string field, string secret) =>
        new(VaultErrorKind.MissingField, $"The secret {secret} has no field named {field}.", field, messages: [secret]);

    public static VaultException SecretDeleted(string name) =>
        new(VaultErrorKind.SecretDeleted, $"The latest version of the secret {name} is deleted.", name);

    public static VaultException WriteLost(string name) =>
        new(VaultErrorKind.WriteLost, $"The secret {name} was changed by another writer while the field was written.", name);

    /// <summary>A request that got no HTTP answer from the host, with the failure of the connection.</summary>
    public static VaultException Transport(string host, Exception inner, CertificateErrors? certificate = null) =>
        new(VaultErrorKind.Transport, $"The connection to {host} failed: {inner.Message}", host, inner: inner,
            certificate: certificate);
}
