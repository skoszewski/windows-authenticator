using Totp;

namespace Vault.Tests;

/// <summary>The client and the connection test against the dev server.</summary>
[TestClass]
public sealed class ServerTests
{
    private static VaultClient Client(string? token = null, string mount = "totp", AuthMethod method = AuthMethod.Token) =>
        new(new VaultConfiguration(VaultDevServer.Address, totpMount: mount, authMethod: method), token);

    private static VaultConfiguration Configuration(string? address = null, AuthMethod method = AuthMethod.Token) =>
        new(address ?? VaultDevServer.Address, authMethod: method, username: "alice");

    /// <summary>Waits until the code of the account changes no sooner than in three seconds.</summary>
    private static async Task AwayFromPeriodEndAsync(Account account)
    {
        while (account.SecondsLeft(DateTimeOffset.Now) < 3)
        {
            await Task.Delay(250);
        }
    }

    private static async Task<VaultException> RefusedAsync(Func<Task> call) =>
        await Assert.ThrowsExactlyAsync<VaultException>(call);

    [TestMethod]
    public async Task TokenLookupReportsTheEndOfTheToken()
    {
        var token = await VaultDevServer.TokenAsync("full");
        var found = await Client(token).LookupSelfAsync();
        Assert.AreEqual(token, found.Token);
        Assert.IsTrue(found.Renewable);
        Assert.IsNotNull(found.Expires);
        Assert.IsTrue(found.Expires > DateTimeOffset.Now.AddSeconds(3000));
    }

    [TestMethod]
    public async Task RootTokenHasNoEnd()
    {
        var found = await Client(VaultDevServer.RootToken).LookupSelfAsync();
        Assert.IsNull(found.Expires);
    }

    [TestMethod]
    public async Task UserpassLogin()
    {
        var vault = Client(method: AuthMethod.Userpass);
        var token = await vault.LoginUserpassAsync("alice", VaultDevServer.Password);
        Assert.AreNotEqual("", token.Token);
        CollectionAssert.Contains((await Client(token.Token).ListKeysAsync()).ToList(), "default");
        await RefusedAsync(() => vault.LoginUserpassAsync("alice", "wrong"));
    }

    [TestMethod]
    public async Task AppRoleLogin()
    {
        var vault = Client(method: AuthMethod.Approle);
        var token = await vault.LoginAppRoleAsync(VaultDevServer.RoleId, VaultDevServer.SecretId);
        CollectionAssert.Contains((await Client(token.Token).ListKeysAsync()).ToList(), "strong");
        await RefusedAsync(() => vault.LoginAppRoleAsync(VaultDevServer.RoleId, "wrong"));
    }

    [TestMethod]
    public async Task RenewingAToken()
    {
        var renewed = await Client(await VaultDevServer.TokenAsync("full")).RenewSelfAsync();
        Assert.IsTrue(renewed.Renewable);
        Assert.IsNotNull(renewed.Expires);
    }

    [TestMethod]
    public async Task ListingKeysOfTwoMounts()
    {
        var token = await VaultDevServer.TokenAsync("full");
        CollectionAssert.AreEqual(new[] { "default", "strong" }, (await Client(token).ListKeysAsync()).Order().ToList());
        CollectionAssert.AreEqual(new[] { "shared" }, (await Client(token, "/team/totp/").ListKeysAsync()).ToList());
    }

    [TestMethod]
    public async Task ListingIsDeniedWithoutThePolicy()
    {
        var vault = Client(await VaultDevServer.TokenAsync("nolist"));
        Assert.IsTrue((await RefusedAsync(() => vault.ListKeysAsync())).IsDenied);
        Assert.AreEqual(6, (await vault.CodeAsync("default")).Length);
    }

    [TestMethod]
    public async Task ReadingAKeyGivesItsParameters()
    {
        var vault = Client(await VaultDevServer.TokenAsync("full"));
        var strong = await vault.ReadKeyAsync("strong");
        Assert.AreEqual(new VaultKeyInfo("strong", "bob@example.com", "Acme", "SHA256", 8, 60), strong);
        Assert.AreEqual("Acme: bob@example.com", strong.SuggestedName);
        var account = strong.Account("Bob");
        Assert.AreEqual(Algorithm.Sha256, account.Algorithm);
        Assert.AreEqual(8, account.Digits);
        Assert.AreEqual(60, account.Period);
        var shared = Client(await VaultDevServer.TokenAsync("full"), "team/totp");
        Assert.AreEqual("team", (await shared.ReadKeyAsync("shared")).SuggestedName);
    }

    [TestMethod]
    [DataRow("default")]
    [DataRow("strong")]
    public async Task CodesAgreeWithTheTotpLibrary(string key)
    {
        var vault = Client(await VaultDevServer.TokenAsync("full"));
        var account = (await vault.ReadKeyAsync(key)).Account(key);
        await AwayFromPeriodEndAsync(account);
        var code = await vault.CodeAsync(key);
        Assert.AreEqual(account.Code(VaultDevServer.Secret, DateTimeOffset.Now), code);
    }

    [TestMethod]
    public async Task AGeneratedKeyComesWithItsQrCodeAndUrl()
    {
        var vault = Client(VaultDevServer.RootToken, "scratch/totp");
        var generated = await vault.GenerateKeyAsync("generated", "Acme", "carol@example.com");
        Assert.IsNotNull(generated.QrCode);
        CollectionAssert.AreEqual(new byte[] { 0x89, 0x50, 0x4E, 0x47 }, generated.QrCode.Take(4).ToArray());
        var parsed = OtpAuth.Parse("", generated.Url);
        Assert.AreEqual("Acme: carol@example.com", parsed.Account.Name);
        var info = await vault.ReadKeyAsync("generated");
        Assert.AreEqual("Acme", info.Issuer);
        Assert.AreEqual("carol@example.com", info.AccountName);
        var account = info.Account("generated");
        await AwayFromPeriodEndAsync(account);
        Assert.AreEqual(account.Code(parsed.Secret, DateTimeOffset.Now), await vault.CodeAsync("generated"));
    }

    [TestMethod]
    public async Task AKeyIsNotReplacedByGenerating()
    {
        var vault = Client(VaultDevServer.RootToken);
        var generated = await RefusedAsync(() => vault.GenerateKeyAsync("default", "Acme", "mallory"));
        Assert.AreEqual(VaultErrorKind.KeyExists, generated.Kind);
        Assert.AreEqual("default", generated.Value);
        var imported = await RefusedAsync(() => vault.ImportKeyAsync("default", VaultDevServer.Secret));
        Assert.AreEqual(VaultErrorKind.KeyExists, imported.Kind);
    }

    [TestMethod]
    public async Task GeneratingNeedsTheWritePolicy()
    {
        var vault = Client(await VaultDevServer.TokenAsync("full"), "scratch/totp");
        Assert.IsTrue((await RefusedAsync(() => vault.GenerateKeyAsync("denied", "Acme", "dave"))).IsDenied);
    }

    [TestMethod]
    [DataRow(VaultDevServer.Secret)]
    [DataRow("otpauth://totp/Acme:erin@example.com?secret=" + VaultDevServer.Secret + "&digits=8&algorithm=SHA256&period=60")]
    public async Task AnImportedKeyGivesTheCodesOfItsSecret(string input)
    {
        var vault = Client(VaultDevServer.RootToken, "scratch/totp");
        var name = "imported-" + Guid.NewGuid().ToString("D");
        await vault.ImportKeyAsync(name, input);
        var info = await vault.ReadKeyAsync(name);
        var account = info.Account(name);
        if (input.StartsWith("otpauth", StringComparison.Ordinal))
        {
            Assert.AreEqual("Acme", info.Issuer);
            Assert.AreEqual(Algorithm.Sha256, account.Algorithm);
            Assert.AreEqual(8, account.Digits);
            Assert.AreEqual(60, account.Period);
        }
        await AwayFromPeriodEndAsync(account);
        Assert.AreEqual(account.Code(VaultDevServer.Secret, DateTimeOffset.Now), await vault.CodeAsync(name));
    }

    [TestMethod]
    [DataRow("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=7")]
    [DataRow("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=10")]
    public async Task AnImportedKeyOfUnsupportedDigitsIsRefused(string input)
    {
        var vault = Client(VaultDevServer.RootToken, "scratch/totp");
        Assert.AreEqual(VaultErrorKind.UnsupportedKey, (await RefusedAsync(() => vault.ImportKeyAsync("unsupported", input))).Kind);
        var missing = await RefusedAsync(() => vault.CodeAsync("unsupported"));
        Assert.AreEqual(400, missing.Status);
        CollectionAssert.AreEqual(new[] { "unknown key: unsupported" }, missing.Messages.ToList());
    }

    [TestMethod]
    public async Task AConnectionTestPassesAgainstTheServer()
    {
        var checks = await VaultDiagnostics.RunAsync(Configuration(), VaultDevServer.RootToken);
        CollectionAssert.AreEqual(new[] { "Address", "Server", "Token", "TOTP engine" }, checks.Select(c => c.Step).ToList());
        Assert.IsTrue(checks.All(c => c.Outcome == VaultCheckOutcome.Passed));
        Assert.AreEqual(VaultDevServer.Address, checks[0].Message);
        Assert.AreEqual("The token is valid and has no end.", checks[2].Message);
    }

    [TestMethod]
    public async Task AConnectionTestSaysUntilWhenATokenEnds()
    {
        var checks = await VaultDiagnostics.RunAsync(Configuration(), await VaultDevServer.TokenAsync("full"));
        Assert.AreEqual("Token", checks[2].Step);
        StringAssert.StartsWith(checks[2].Message, "The token is valid until ");
    }

    [TestMethod]
    public async Task AConnectionTestLogsInWithAPassword()
    {
        var checks = await VaultDiagnostics.RunAsync(Configuration(method: AuthMethod.Userpass), VaultDevServer.Password);
        CollectionAssert.AreEqual(new[] { "Address", "Server", "Login", "TOTP engine" }, checks.Select(c => c.Step).ToList());
        Assert.AreEqual(VaultCheckOutcome.Passed, checks[2].Outcome);
        Assert.AreEqual("Vault issued a token to the user alice.", checks[2].Message);
    }

    [TestMethod]
    public async Task AConnectionTestLogsInWithAnAppRole()
    {
        var configuration = new VaultConfiguration(VaultDevServer.Address, authMethod: AuthMethod.Approle,
                                                   roleId: VaultDevServer.RoleId);
        var checks = await VaultDiagnostics.RunAsync(configuration, VaultDevServer.SecretId);
        CollectionAssert.AreEqual(new[] { "Address", "Server", "Login", "TOTP engine" }, checks.Select(c => c.Step).ToList());
        Assert.AreEqual("Vault issued a token to the AppRole.", checks[2].Message);
    }

    [TestMethod]
    public async Task AConnectionTestNamesARefusedLogin()
    {
        var checks = await VaultDiagnostics.RunAsync(Configuration(method: AuthMethod.Userpass), "wrong");
        Assert.AreEqual("Login", checks[^1].Step);
        Assert.AreEqual(VaultCheckOutcome.Failed, checks[^1].Outcome);
        Assert.AreEqual("Vault refused the login.", checks[^1].Message);
    }

    [TestMethod]
    public async Task AConnectionTestNamesTheStepOfAnUnreachableServer()
    {
        var checks = await VaultDiagnostics.RunAsync(Configuration("http://127.0.0.1:1"), VaultDevServer.RootToken);
        CollectionAssert.AreEqual(new[] { "Address", "Server" }, checks.Select(c => c.Step).ToList());
        Assert.AreEqual(VaultCheckOutcome.Failed, checks[^1].Outcome);
        Assert.AreEqual(VaultProblemKind.Network, checks[^1].Problem?.Kind);
        Assert.AreEqual("Nothing answers at the vault's address", checks[^1].Problem?.Title);
    }

    [TestMethod]
    public async Task AConnectionTestOfTlsToAPlainPortFailsAsTls()
    {
        var checks = await VaultDiagnostics.RunAsync(Configuration($"https://127.0.0.1:{VaultDevServer.Port}"),
                                                     VaultDevServer.RootToken);
        Assert.AreEqual("Server", checks[^1].Step);
        Assert.AreEqual(VaultProblemKind.Tls, checks[^1].Problem?.Kind);
    }

    [TestMethod]
    public async Task AConnectionTestNamesTheStepOfARefusedToken()
    {
        var checks = await VaultDiagnostics.RunAsync(Configuration(), "not-a-token");
        Assert.AreEqual("Token", checks[^1].Step);
        Assert.AreEqual(VaultCheckOutcome.Failed, checks[^1].Outcome);
        Assert.AreEqual("Vault did not accept the token.", checks[^1].Message);
        StringAssert.Contains(checks[^1].Problem?.Suggestion, "Replace the token");
        Assert.AreEqual(VaultProblemKind.Denied, checks[^1].Problem?.Kind);
    }

    [TestMethod]
    public async Task AConnectionTestNamesAnEmptyCredential()
    {
        var checks = await VaultDiagnostics.RunAsync(Configuration(method: AuthMethod.Userpass), "");
        Assert.AreEqual("Login", checks[^1].Step);
        Assert.AreEqual(VaultProblemKind.Credential, checks[^1].Problem?.Kind);
        Assert.AreEqual("The password is empty", checks[^1].Problem?.Title);
    }

    [TestMethod]
    public async Task AConnectionTestWarnsWhenTheKeysCannotBeListed()
    {
        var checks = await VaultDiagnostics.RunAsync(Configuration(), await VaultDevServer.TokenAsync("nolist"));
        Assert.AreEqual("TOTP engine", checks[^1].Step);
        Assert.AreEqual(VaultCheckOutcome.Warning, checks[^1].Outcome);
        Assert.AreEqual(VaultProblemKind.Denied, checks[^1].Problem?.Kind);
    }

    [TestMethod]
    public async Task AConnectionTestOfABadAddressStopsAtTheAddress()
    {
        var checks = await VaultDiagnostics.RunAsync(Configuration("vault"), null);
        CollectionAssert.AreEqual(new[] { "Address" }, checks.Select(c => c.Step).ToList());
        Assert.AreEqual(VaultProblemKind.Address, checks[0].Problem?.Kind);
    }

    [TestMethod]
    public async Task AConnectionTestDoesNotTestOidc()
    {
        var checks = await VaultDiagnostics.RunAsync(Configuration(method: AuthMethod.Oidc), null);
        CollectionAssert.AreEqual(new[] { "Address", "Server", "Authentication", "TOTP engine" },
                                  checks.Select(c => c.Step).ToList());
        CollectionAssert.AreEqual(
            new[] { VaultCheckOutcome.Passed, VaultCheckOutcome.Passed, VaultCheckOutcome.Skipped, VaultCheckOutcome.Skipped },
            checks.Select(c => c.Outcome).ToList());
        Assert.AreEqual("Not tested: an OIDC vault signs in interactively.", checks[2].Message);
        Assert.AreEqual("Not tested: there is no token.", checks[3].Message);
    }

    [TestMethod]
    public async Task AConnectionTestChecksTheTokenOfAnOidcSignIn()
    {
        var token = new VaultToken(VaultDevServer.RootToken, null, false);
        var checks = await VaultDiagnostics.RunAsync(Configuration(method: AuthMethod.Oidc), null, token);
        CollectionAssert.AreEqual(new[] { "Address", "Server", "Token", "TOTP engine" }, checks.Select(c => c.Step).ToList());
        Assert.AreEqual(VaultCheckOutcome.Passed, checks[2].Outcome);
        Assert.AreNotEqual(VaultCheckOutcome.Skipped, checks[3].Outcome);
    }

    [TestMethod]
    public async Task AConnectionTestNamesTheStepOfARefusedOidcToken()
    {
        var token = new VaultToken("not-a-token", null, false);
        var checks = await VaultDiagnostics.RunAsync(Configuration(method: AuthMethod.Oidc), null, token);
        Assert.AreEqual("Token", checks[^1].Step);
        Assert.AreEqual(VaultCheckOutcome.Failed, checks[^1].Outcome);
        Assert.AreEqual("Vault did not accept the token.", checks[^1].Message);
        Assert.AreEqual(VaultProblemKind.Denied, checks[^1].Problem?.Kind);
    }

    [TestMethod]
    public async Task AConnectionTestWarnsOfPlainHttpToAnotherHost()
    {
        var checks = await VaultDiagnostics.RunAsync(Configuration("http://vault.invalid:1"), VaultDevServer.RootToken);
        Assert.AreEqual("Address", checks[0].Step);
        Assert.AreEqual(VaultCheckOutcome.Warning, checks[0].Outcome);
        Assert.AreEqual("The vault's name does not resolve", checks[^1].Problem?.Title);
    }

    [TestMethod]
    public async Task ARevokedTokenIsDenied()
    {
        var token = await VaultDevServer.TokenAsync("full");
        var vault = Client(token);
        await vault.ListKeysAsync();
        await VaultDevServer.AdminAsync("POST", "auth/token/revoke", new { token });
        Assert.IsTrue((await RefusedAsync(() => vault.ListKeysAsync())).IsDenied);
    }

    [TestMethod]
    public async Task AMissingKeyIsReportedWithVaultsMessage()
    {
        var vault = Client(await VaultDevServer.TokenAsync("full"));
        var missing = await RefusedAsync(() => vault.CodeAsync("nothing"));
        Assert.AreEqual(VaultErrorKind.Http, missing.Kind);
        Assert.AreEqual(400, missing.Status);
        CollectionAssert.AreEqual(new[] { "unknown key: nothing" }, missing.Messages.ToList());
    }
}
