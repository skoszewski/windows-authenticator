using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Vault;

/// <summary>An error that states its own problem, for the errors of the layers above the library.</summary>
public interface IVaultProblemSource
{
    VaultProblem Problem { get; }
}

/// <summary>The kind of a problem with a Vault.</summary>
public enum VaultProblemKind
{
    Address,
    Network,
    Tls,
    NotSignedIn,
    Denied,
    Credential,
    Server,
    Response,
    Other,
}

/// <summary>
/// What is wrong with a Vault, in words: the title says what, the detail what happened, and the suggestion what
/// to do about it.
/// </summary>
public sealed record VaultProblem(VaultProblemKind Kind, string Title, string Detail, string Suggestion)
{
    /// <summary>The problem as one text, to copy into a report.</summary>
    public string Report => $"{Title}\n{Detail}\n{Suggestion}";

    /// <summary>
    /// The problem of an error of a Vault call or a layer above; the method of the vault, when known, words what
    /// to do about a refused token.
    /// </summary>
    public static VaultProblem From(Exception error, AuthMethod? method = null) => error switch
    {
        IVaultProblemSource source => source.Problem,
        VaultException vault => Of(vault, method),
        OperationCanceledException => new(VaultProblemKind.Other, "The request was cancelled",
                                          "The request to the vault was cancelled before it ended.",
                                          "Run it again when you are ready."),
        _ => new(VaultProblemKind.Other, "The operation failed", error.Message,
                 "Try again. If it keeps failing, copy the details into a report."),
    };

    private static VaultProblem Of(VaultException error, AuthMethod? method) => error.Kind switch
    {
        VaultErrorKind.BadAddress => new(VaultProblemKind.Address, "The address is not usable",
                                         $"\"{error.Value}\" is not a Vault address.",
                                         "Use the form https://vault.example.com:8200."),
        VaultErrorKind.Http => OfStatus(error.Status,
                                        error.Messages.Count == 0 ? "Vault gave no message." : string.Join("; ", error.Messages),
                                        method),
        VaultErrorKind.BadResponse => new(VaultProblemKind.Response, "The answer is not from a Vault",
                                          $"The answer could not be read as {error.Value}.",
                                          "Check that the address and the port are those of the Vault API, not of a web page or a proxy."),
        VaultErrorKind.NotSignedIn => new(VaultProblemKind.NotSignedIn, "Not signed in",
                                          "No sign-in is active, and an OIDC vault signs in interactively when it has no token, or when its token ends.",
                                          "Sign in to the vault."),
        VaultErrorKind.Oidc => new(VaultProblemKind.Denied, "The OIDC sign-in failed", error.Value,
                                   "Sign in again; check the OIDC role and its redirect URI."),
        VaultErrorKind.KeyExists => new(VaultProblemKind.Other, "The key exists",
                                        $"The vault holds a key named {error.Value}.", "Choose another name."),
        VaultErrorKind.UnsupportedKey => new(VaultProblemKind.Other, "The vault cannot keep this key", error.Value,
                                             "Use a key of 6 or 8 digits."),
        VaultErrorKind.Transport => OfTransport(error.Value, error.InnerException, error.Certificate),
        VaultErrorKind.NoSecret => new(VaultProblemKind.Server, "The secret does not exist",
                                       $"The vault holds no secret named {error.Value}.",
                                       "Check the KV version, the mount and the secret name."),
        VaultErrorKind.SecretDeleted => new(VaultProblemKind.Server, "The secret was deleted",
                                            $"The latest version of the secret {error.Value} is deleted or destroyed.",
                                            "Undelete the version in Vault, or choose another secret."),
        VaultErrorKind.WriteLost => new(VaultProblemKind.Server, "The secret was changed by another writer",
                                        $"The field was not kept in {error.Value}: another writer replaced the secret while it was written.",
                                        "Try again."),
        VaultErrorKind.MissingField => new(VaultProblemKind.Other, "The secret has no such field",
                                           $"The secret {error.Messages[0]} holds no field named {error.Value}.",
                                           "Check the name of the field."),
        _ => new(VaultProblemKind.Other, "The operation failed", error.Message,
                 "Try again. If it keeps failing, copy the details into a report."),
    };

    private static VaultProblem OfStatus(int status, string said, AuthMethod? method) => status switch
    {
        400 => new(VaultProblemKind.Server, "Vault refused the request", said,
                   "Check the key name and the vault's address, mounts and method; Vault's message says what is wrong."),
        403 => new(VaultProblemKind.Denied, "Vault denied the access", said,
                   $"The token may have ended, or its policy lacks this access. {Again(method)}, or ask for the policy."),
        404 => new(VaultProblemKind.Server, "Vault does not know the path", said,
                   "Check the mount of the TOTP engine and the mount of the authentication method."),
        429 => new(VaultProblemKind.Server, "Vault is busy", said, "Wait and try again."),
        503 => new(VaultProblemKind.Server, "Vault is sealed or in standby", said,
                   "Unseal Vault, or use the address of the active node."),
        _ => new(VaultProblemKind.Server, $"Vault answered {status}", said,
                 status >= 500 ? "The server has a problem; try again later, and look at its log." : "Check the vault's address, mounts and method."),
    };

    /// <summary>What to do for a new token, in the words of the method.</summary>
    private static string Again(AuthMethod? method) => method switch
    {
        AuthMethod.Token => "Replace the token",
        AuthMethod.Userpass or AuthMethod.Approle => "Log in again",
        AuthMethod.Oidc => "Sign in again",
        _ => "Authenticate again",
    };

    /// <summary>The problem of a request that got no HTTP answer from the host.</summary>
    private static VaultProblem OfTransport(string host, Exception? failure, CertificateErrors? certificate)
    {
        if (failure is TaskCanceledException)
        {
            return TimedOut(host);
        }
        if (failure is not HttpRequestException request)
        {
            return ConnectionFailed(failure);
        }
        var socket = Inner<SocketException>(request);
        switch (request.HttpRequestError)
        {
            case HttpRequestError.NameResolutionError:
                return new(VaultProblemKind.Network, "The vault's name does not resolve", $"The name {host} was not found.",
                           "Check the address, the network and the VPN; try the IP address.");
            case HttpRequestError.ConnectionError when socket?.SocketErrorCode is SocketError.TimedOut:
                return TimedOut(host);
            case HttpRequestError.ConnectionError when socket?.SocketErrorCode is SocketError.NetworkUnreachable
                                                         or SocketError.NetworkDown or SocketError.HostUnreachable:
                return new(VaultProblemKind.Network, "The network is down", $"This computer has no route to {host}.",
                           "Connect to the network or the VPN.");
            case HttpRequestError.ConnectionError:
                return new(VaultProblemKind.Network, "Nothing answers at the vault's address",
                           $"The connection to {host} was refused or blocked.",
                           "Check the host and the port, that Vault runs, and any firewall or VPN.");
            case HttpRequestError.SecureConnectionError:
                return OfCertificate(host, certificate);
            case HttpRequestError.ResponseEnded:
                return new(VaultProblemKind.Network, "The connection was lost",
                           $"The connection to {host} broke while it was in use.",
                           "Try again; check the network and the server.");
            case HttpRequestError.InvalidResponse or HttpRequestError.HttpProtocolError:
                return new(VaultProblemKind.Response, "The answer is not from a Vault",
                           $"{host} gave an answer that is not valid HTTP.",
                           "Check that the address and the port are those of the Vault API.");
            default:
                return ConnectionFailed(request);
        }
    }

    /// <summary>The problem of a TLS handshake, by the errors of the certificate it refused, if any.</summary>
    private static VaultProblem OfCertificate(string host, CertificateErrors? certificate)
    {
        if (certificate is null)
        {
            return new(VaultProblemKind.Tls, "The secure connection failed",
                       $"A TLS connection to {host} could not be made.",
                       "Check that the address is https and the port serves TLS; a plain HTTP port fails this way when asked for https.");
        }
        if (certificate.ChainStatus.HasFlag(X509ChainStatusFlags.NotTimeValid))
        {
            return new(VaultProblemKind.Tls, "The vault's certificate is expired or not yet valid",
                       $"The dates of the certificate of {host} do not include today.",
                       "Renew the certificate; check the date of this computer.");
        }
        if (certificate.PolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            return new(VaultProblemKind.Tls, "The vault's certificate is for another name",
                       $"The certificate of {host} does not name {host}.",
                       "Use the name the certificate holds in the address, or issue a certificate for this name.");
        }
        return new(VaultProblemKind.Tls, "The vault's certificate is not trusted",
                   $"The certificate of {host} was not issued by an authority this computer trusts.",
                   "Trust the issuing CA in the Windows certificate store, and make the server send its intermediate certificates.");
    }

    private static VaultProblem TimedOut(string host) =>
        new(VaultProblemKind.Network, "The vault did not answer in time", $"{host} did not answer before the time ran out.",
            "Check that the host is up and reachable, and the VPN.");

    private static VaultProblem ConnectionFailed(Exception? failure) =>
        new(VaultProblemKind.Network, "The connection failed", failure?.Message ?? "The request got no answer.",
            "Check the address and the network, and try again.");

    /// <summary>The first exception of the type among the inner exceptions of the error.</summary>
    private static T? Inner<T>(Exception error) where T : Exception
    {
        for (var inner = error.InnerException; inner is not null; inner = inner.InnerException)
        {
            if (inner is T found)
            {
                return found;
            }
        }
        return null;
    }
}
