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

/// <summary>The listener of the OIDC redirect.</summary>
[TestClass]
public sealed class OidcCallbackTests
{
    [TestMethod]
    public void ParsesTheRequestLine()
    {
        const string request = "GET /oidc/callback?state=abc&code=x%20y HTTP/1.1\r\nHost: localhost:8250\r\n\r\n";
        Assert.AreEqual(new OidcCallback("abc", "x y", null), OidcCallbackListener.Parse(request));
    }

    [TestMethod]
    public void ParsesAProviderError()
    {
        const string request = "GET /oidc/callback?error=access_denied&error_description=No%20way&state=s HTTP/1.1\r\n\r\n";
        Assert.AreEqual("No way", OidcCallbackListener.Parse(request)?.Error);
    }

    [TestMethod]
    [DataRow("GET /favicon.ico HTTP/1.1\r\n\r\n")]
    [DataRow("POST /oidc/callback HTTP/1.1\r\n\r\n")]
    [DataRow("")]
    public void IgnoresOtherRequests(string request) => Assert.IsNull(OidcCallbackListener.Parse(request));

    [TestMethod]
    [DataRow("127.0.0.1")]
    [DataRow("[::1]")]
    public async Task ReceivesTheBrowsersRedirect(string host)
    {
        using var listener = new OidcCallbackListener(18250);
        listener.Start();
        var callback = listener.CallbackAsync(TimeSpan.FromSeconds(5));

        using var http = new HttpClient();
        using var other = await http.GetAsync($"http://{host}:18250/favicon.ico");
        Assert.AreEqual(HttpStatusCode.NotFound, other.StatusCode);
        using var response = await http.GetAsync($"http://{host}:18250/oidc/callback?state=s1&code=c1");
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        StringAssert.Contains(await response.Content.ReadAsStringAsync(), "You can close this tab");
        Assert.AreEqual(new OidcCallback("s1", "c1", null), await callback);
    }

    [TestMethod]
    public async Task AnIdleConnectionDoesNotHoldUpTheRedirect()
    {
        using var listener = new OidcCallbackListener(18253);
        listener.Start();
        var callback = listener.CallbackAsync(TimeSpan.FromSeconds(5));

        using var idle = new TcpClient();
        await idle.ConnectAsync(IPAddress.Loopback, 18253);
        using var http = new HttpClient();
        using var response = await http.GetAsync("http://127.0.0.1:18253/oidc/callback?state=s2&code=c2");
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual(new OidcCallback("s2", "c2", null), await callback);
    }

    [TestMethod]
    public async Task TimesOutWithoutARedirect()
    {
        using var listener = new OidcCallbackListener(18251);
        listener.Start();
        var error = await Assert.ThrowsExactlyAsync<VaultException>(() => listener.CallbackAsync(TimeSpan.FromMilliseconds(300)));
        Assert.AreEqual(VaultErrorKind.Oidc, error.Kind);
    }

    [TestMethod]
    public void APortInUseIsSaidInWords()
    {
        using var first = new OidcCallbackListener(18252);
        first.Start();
        using var second = new OidcCallbackListener(18252);
        var error = Assert.ThrowsExactly<SocketException>(second.Start);
        Assert.AreEqual("The callback port is in use", VaultProblem.From(error).Title);
    }
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
