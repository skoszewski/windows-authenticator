using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Vault.Tests;

/// <summary>The requests, the configuration and the address checks, without a server.</summary>
[TestClass]
public sealed class RequestTests
{
    [TestMethod]
    public void RequestsCarryTheTokenAndNamespace()
    {
        var configuration = new VaultConfiguration("https://vault.example.com:8200/", "team-a", "/otp/");
        using var request = new VaultClient(configuration, "t").MakeRequest(new HttpMethod("LIST"), "otp/keys");
        Assert.AreEqual("https://vault.example.com:8200/v1/otp/keys", request.RequestUri?.AbsoluteUri);
        Assert.AreEqual("LIST", request.Method.Method);
        CollectionAssert.AreEqual(new[] { "t" }, request.Headers.GetValues("X-Vault-Token").ToList());
        CollectionAssert.AreEqual(new[] { "team-a" }, request.Headers.GetValues("X-Vault-Namespace").ToList());
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("vault")]
    [DataRow("ftp://vault.example.com")]
    [DataRow("http://")]
    public void BadAddressesAreRefused(string address)
    {
        var error = Assert.ThrowsExactly<VaultException>(
            () => new VaultClient(new VaultConfiguration(address)).MakeRequest(HttpMethod.Get, "sys/health"));
        Assert.AreEqual(VaultErrorKind.BadAddress, error.Kind);
        Assert.AreEqual(address, error.Value);
    }

    [TestMethod]
    public void ConfigurationDefaults()
    {
        var configuration = new VaultConfiguration("http://127.0.0.1:8200", authMethod: AuthMethod.Approle);
        Assert.AreEqual("approle", configuration.AuthMount);
        Assert.AreEqual("totp", configuration.TotpMount);
        Assert.AreEqual("http://localhost:8250/oidc/callback", configuration.OidcRedirectUri);
    }

    [TestMethod]
    [DataRow("localhost")]
    [DataRow("127.0.0.1")]
    [DataRow("127.1.2.3")]
    [DataRow("::1")]
    [DataRow("[::1]")]
    public async Task AHostOfThisComputerResolvesToLoopback(string host) =>
        Assert.IsTrue(await VaultDiagnostics.ResolvesToLoopbackAsync(host));

    [TestMethod]
    [DataRow("192.168.1.10")]
    [DataRow("10.0.0.1")]
    [DataRow("8.8.8.8")]
    [DataRow("2001:db8::1")]
    [DataRow("vault.invalid")]
    public async Task AHostOfAnotherMachineDoesNotResolveToLoopback(string host) =>
        Assert.IsFalse(await VaultDiagnostics.ResolvesToLoopbackAsync(host));
}

/// <summary>The rules of the OIDC sign-in window: which pages load and which address ends the sign-in.</summary>
[TestClass]
public sealed class OidcSignInPolicyTests
{
    private static readonly OidcSignInPolicy Policy = new(new Uri("http://localhost:8250/oidc/callback"));

    [TestMethod]
    public void TheRedirectEndsTheSignInWithItsCallback() =>
        Assert.AreEqual(new OidcNavigation.Callback(new OidcCallback("abc", "x y", null)),
                        Policy.Decide("http://localhost:8250/oidc/callback?state=abc&code=x%20y"));

    [TestMethod]
    public void AProviderErrorIsCarriedByTheCallback()
    {
        Assert.AreEqual(new OidcNavigation.Callback(new OidcCallback("s", null, "No way")),
                        Policy.Decide("http://localhost:8250/oidc/callback?error=access_denied&error_description=No%20way&state=s"));
        Assert.AreEqual(new OidcNavigation.Callback(new OidcCallback(null, null, "access_denied")),
                        Policy.Decide("http://localhost:8250/oidc/callback?error=access_denied"));
    }

    [TestMethod]
    public void TheHostOfTheRedirectIsComparedWithoutCase() =>
        Assert.AreEqual(new OidcNavigation.Callback(new OidcCallback(null, "c", null)),
                        Policy.Decide("http://LOCALHOST:8250/oidc/callback?code=c"));

    [TestMethod]
    [DataRow("http://localhost:9999/oidc/callback?code=c")]
    [DataRow("http://localhost:8250/other?code=c")]
    [DataRow("http://127.0.0.1:8250/oidc/callback?code=c")]
    [DataRow("http://evil.example.com:8250/oidc/callback?code=c")]
    public void ALookalikeOfTheRedirectIsNotTheCallback(string address) =>
        Assert.IsInstanceOfType<OidcNavigation.Block>(Policy.Decide(address));

    [TestMethod]
    [DataRow("https://login.example.com/authorize?x=1")]
    [DataRow("https://login.example.com:8443/")]
    [DataRow("about:blank")]
    public void ASecurePageLoads(string address) =>
        Assert.AreEqual(new OidcNavigation.Allow(), Policy.Decide(address));

    [TestMethod]
    [DataRow("http://login.example.com/authorize")]
    [DataRow("data:text/html,hello")]
    [DataRow("file:///etc/hosts")]
    [DataRow("javascript:alert(1)")]
    [DataRow("windowsauthenticator://callback")]
    [DataRow("about:srcdoc")]
    [DataRow(null)]
    public void AnyOtherPageIsBlocked(string? address) =>
        Assert.IsInstanceOfType<OidcNavigation.Block>(Policy.Decide(address));

    [TestMethod]
    public void ABlockedPlainHttpPageIsNamed() =>
        Assert.AreEqual(new OidcNavigation.Block("The page login.example.com is not served over HTTPS."),
                        Policy.Decide("http://login.example.com/authorize"));
}

/// <summary>The problems of failed calls, in words.</summary>
[TestClass]
public sealed class ProblemTests
{
    private const string Host = "vault.example.com";

    private static VaultProblem Transport(HttpRequestError kind, Exception? inner = null, CertificateErrors? certificate = null) =>
        VaultProblem.From(VaultException.Transport(Host, new HttpRequestException(kind, "failed", inner), certificate));

    public static IEnumerable<object?[]> TransportFailures =>
    [
        [HttpRequestError.NameResolutionError, null, null, VaultProblemKind.Network],
        [HttpRequestError.ConnectionError, new SocketException((int)SocketError.ConnectionRefused), null, VaultProblemKind.Network],
        [HttpRequestError.ConnectionError, new SocketException((int)SocketError.TimedOut), null, VaultProblemKind.Network],
        [HttpRequestError.ConnectionError, new SocketException((int)SocketError.NetworkUnreachable), null, VaultProblemKind.Network],
        [HttpRequestError.SecureConnectionError, null, null, VaultProblemKind.Tls],
        [HttpRequestError.SecureConnectionError, null,
         new CertificateErrors(SslPolicyErrors.RemoteCertificateChainErrors, X509ChainStatusFlags.UntrustedRoot), VaultProblemKind.Tls],
        [HttpRequestError.SecureConnectionError, null,
         new CertificateErrors(SslPolicyErrors.RemoteCertificateChainErrors, X509ChainStatusFlags.NotTimeValid), VaultProblemKind.Tls],
        [HttpRequestError.SecureConnectionError, null,
         new CertificateErrors(SslPolicyErrors.RemoteCertificateNameMismatch, X509ChainStatusFlags.NoError), VaultProblemKind.Tls],
        [HttpRequestError.ResponseEnded, null, null, VaultProblemKind.Network],
        [HttpRequestError.InvalidResponse, null, null, VaultProblemKind.Response],
    ];

    [TestMethod]
    [DynamicData(nameof(TransportFailures))]
    public void ATransportFailureIsSaidInWords(HttpRequestError kind, Exception? inner, CertificateErrors? certificate,
                                               VaultProblemKind expected)
    {
        var found = Transport(kind, inner, certificate);
        Assert.AreEqual(expected, found.Kind);
        Assert.AreNotEqual("", found.Title);
        Assert.AreNotEqual("", found.Detail);
        Assert.AreNotEqual("", found.Suggestion);
        Assert.AreNotEqual("The connection failed", found.Title);
    }

    [TestMethod]
    public void TheCertificateErrorsNameTheirCause()
    {
        Assert.AreEqual("The vault's certificate is not trusted", Transport(HttpRequestError.SecureConnectionError, null,
            new CertificateErrors(SslPolicyErrors.RemoteCertificateChainErrors, X509ChainStatusFlags.PartialChain)).Title);
        Assert.AreEqual("The vault's certificate is expired or not yet valid", Transport(HttpRequestError.SecureConnectionError, null,
            new CertificateErrors(SslPolicyErrors.RemoteCertificateChainErrors, X509ChainStatusFlags.NotTimeValid)).Title);
        Assert.AreEqual("The vault's certificate is for another name", Transport(HttpRequestError.SecureConnectionError, null,
            new CertificateErrors(SslPolicyErrors.RemoteCertificateNameMismatch, X509ChainStatusFlags.NoError)).Title);
    }

    [TestMethod]
    public void ATimeoutIsSaidInWords()
    {
        var found = VaultProblem.From(VaultException.Transport(Host, new TaskCanceledException("t", new TimeoutException())));
        Assert.AreEqual("The vault did not answer in time", found.Title);
    }

    [TestMethod]
    public void ANameThatDoesNotResolveNamesTheHost() =>
        StringAssert.Contains(Transport(HttpRequestError.NameResolutionError).Detail, Host);

    [TestMethod]
    [DataRow(400, VaultProblemKind.Server)]
    [DataRow(403, VaultProblemKind.Denied)]
    [DataRow(404, VaultProblemKind.Server)]
    [DataRow(429, VaultProblemKind.Server)]
    [DataRow(503, VaultProblemKind.Server)]
    [DataRow(500, VaultProblemKind.Server)]
    public void AnHttpStatusIsSaidInWords(int status, VaultProblemKind kind)
    {
        var found = VaultProblem.From(VaultException.Http(status, ["permission denied"]));
        Assert.AreEqual(kind, found.Kind);
        StringAssert.Contains(found.Detail, "permission denied");
        Assert.AreNotEqual("", found.Suggestion);
    }

    [TestMethod]
    public void ABadAddressIsSaidInWords() =>
        Assert.AreEqual(VaultProblemKind.Address, VaultProblem.From(VaultException.BadAddress("vault")).Kind);

    [TestMethod]
    public void AProblemOfAnotherErrorKeepsItsText()
    {
        var found = VaultProblem.From(new InvalidOperationException("odd failure"));
        Assert.AreEqual(VaultProblemKind.Other, found.Kind);
        Assert.AreEqual("odd failure", found.Detail);
    }
}
