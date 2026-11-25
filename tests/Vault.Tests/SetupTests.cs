namespace Vault.Tests;

/// <summary>Vault Setup against the dev server.</summary>
[TestClass]
public sealed class SetupTests
{
    private static VaultClient Client(string token, string mount = "totp") =>
        new(new VaultConfiguration(VaultDevServer.Address, totpMount: mount), token);

    private static List<VaultCheckOutcome> Outcomes(IEnumerable<VaultCheck> checks) => [.. checks.Select(c => c.Outcome)];

    private static readonly VaultCheckOutcome[] AllPassed =
        [VaultCheckOutcome.Passed, VaultCheckOutcome.Passed, VaultCheckOutcome.Passed];

    private static readonly VaultCheckOutcome[] PoliciesWritten =
        [VaultCheckOutcome.Skipped, VaultCheckOutcome.Passed, VaultCheckOutcome.Passed];

    [TestMethod]
    public async Task TheSetupEnablesTheEngineAndWritesThePolicies()
    {
        var options = new VaultSetupOptions("setup-a/totp", CreatorPolicy: "setup_a_creator", UserPolicy: "setup_a_user");
        CollectionAssert.AreEqual(AllPassed, Outcomes(await VaultSetup.RunAsync(Client(VaultDevServer.RootToken), options)));

        var creator = Client(await VaultDevServer.TokenAsync("setup_a_creator"), "setup-a/totp");
        await creator.ImportKeyAsync("shared", VaultDevServer.Secret);
        Assert.AreEqual("SHA1", (await creator.ReadKeyAsync("shared")).Algorithm);
        Assert.IsTrue((await Assert.ThrowsExactlyAsync<VaultException>(() => creator.CodeAsync("shared"))).IsDenied);

        var user = Client(await VaultDevServer.TokenAsync("setup_a_user"), "setup-a/totp");
        Assert.AreEqual(6, (await user.CodeAsync("shared")).Length);
        CollectionAssert.AreEqual(new[] { "shared" }, (await user.ListKeysAsync()).ToList());
        Assert.AreEqual("", (await user.ReadKeyAsync("shared")).Issuer);
        Assert.IsTrue((await Assert.ThrowsExactlyAsync<VaultException>(
            () => user.ImportKeyAsync("other", VaultDevServer.Secret))).IsDenied);
    }

    [TestMethod]
    public async Task ASecondSetupStopsAtTheEngineAndWritesNothing()
    {
        var root = Client(VaultDevServer.RootToken);
        var first = new VaultSetupOptions("setup-b/totp", CreatorPolicy: "setup_b_creator", UserPolicy: "setup_b_user");
        CollectionAssert.AreEqual(AllPassed, Outcomes(await VaultSetup.RunAsync(root, first)));

        var second = first with { CreatorPolicy = "setup_b2_creator", UserPolicy = "setup_b2_user" };
        var checks = await VaultSetup.RunAsync(root, second);
        CollectionAssert.AreEqual(new[] { "Engine" }, checks.Select(c => c.Step).ToList());
        CollectionAssert.AreEqual(new[] { VaultCheckOutcome.Failed }, Outcomes(checks));
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => VaultDevServer.AdminAsync("GET", "sys/policies/acl/setup_b2_creator"));

        CollectionAssert.AreEqual(PoliciesWritten, Outcomes(await VaultSetup.RunAsync(root, second with { EngineExists = true })));
    }

    [TestMethod]
    public async Task AnExistingPolicyStopsTheSetupUnlessItIsReplaced()
    {
        var root = Client(VaultDevServer.RootToken);
        var options = new VaultSetupOptions("setup-c/totp", CreatorPolicy: "setup_c_creator", UserPolicy: "setup_c_user");
        CollectionAssert.AreEqual(AllPassed, Outcomes(await VaultSetup.RunAsync(root, options)));

        options = options with { EngineExists = true };
        var stopped = await VaultSetup.RunAsync(root, options);
        CollectionAssert.AreEqual(new[] { VaultCheckOutcome.Skipped, VaultCheckOutcome.Failed }, Outcomes(stopped));
        Assert.AreEqual("The policy exists", stopped[^1].Problem?.Title);

        CollectionAssert.AreEqual(PoliciesWritten,
                                  Outcomes(await VaultSetup.RunAsync(root, options with { OverwritePolicies = true })));
    }

    [TestMethod]
    public async Task TheSetupStopsAtTheFirstCallThatIsDenied()
    {
        var denied = Client(await VaultDevServer.TokenAsync("nolist"));
        var checks = await VaultSetup.RunAsync(denied, new VaultSetupOptions("setup-d/totp"));
        CollectionAssert.AreEqual(new[] { VaultCheckOutcome.Failed }, Outcomes(checks));
        Assert.AreEqual(VaultProblemKind.Denied, checks[0].Problem?.Kind);
    }

    [TestMethod]
    public async Task TheSetupOfBadOptionsMakesNoCall()
    {
        var checks = await VaultSetup.RunAsync(Client(VaultDevServer.RootToken), new VaultSetupOptions("has space/totp"));
        CollectionAssert.AreEqual(new[] { "Settings" }, checks.Select(c => c.Step).ToList());
        CollectionAssert.AreEqual(new[] { VaultCheckOutcome.Failed }, Outcomes(checks));
    }
}

/// <summary>The texts and the checks of the setup's policies, without a server.</summary>
[TestClass]
public sealed class SetupPolicyTests
{
    [TestMethod]
    public void TheCreatorPolicyListsCreatesAndReadsKeys()
    {
        var policy = VaultSetup.CreatorPolicy("totp");
        StringAssert.Contains(policy, "path \"totp/keys\" {\n  capabilities = [\"list\"]");
        StringAssert.Contains(policy, "path \"totp/keys/*\" {\n  capabilities = [\"create\", \"update\", \"read\"]");
        Assert.IsFalse(policy.Contains("code", StringComparison.Ordinal));
        Assert.IsFalse(policy.Contains("delete", StringComparison.Ordinal));
    }

    [TestMethod]
    public void TheUserPolicyReadsKeysAndCodes()
    {
        var policy = VaultSetup.UserPolicy("totp");
        StringAssert.Contains(policy, "path \"totp/keys/*\" {\n  capabilities = [\"read\"]");
        StringAssert.Contains(policy, "path \"totp/code/*\" {\n  capabilities = [\"read\"]");
        Assert.IsFalse(policy.Contains("create", StringComparison.Ordinal));
    }

    [TestMethod]
    public void AMountIsTrimmedAndMayBeNested()
    {
        var policy = VaultSetup.UserPolicy("/team/totp/");
        StringAssert.Contains(policy, "path \"team/totp/keys\"");
        StringAssert.Contains(policy, "path \"team/totp/code/*\"");
    }

    public static IEnumerable<object[]> UnusableOptions =>
    [
        [new VaultSetupOptions("")],
        [new VaultSetupOptions("a b")],
        [new VaultSetupOptions(CreatorPolicy: "")],
        [new VaultSetupOptions(UserPolicy: "has space")],
        [new VaultSetupOptions(CreatorPolicy: "same", UserPolicy: "same")],
    ];

    [TestMethod]
    [DynamicData(nameof(UnusableOptions))]
    public void OptionsThatCannotBeUsedAreRefused(VaultSetupOptions options) =>
        Assert.IsNotNull(VaultSetup.Problem(options));

    [TestMethod]
    public void TheDefaultsAreUsable() => Assert.IsNull(VaultSetup.Problem(new VaultSetupOptions()));
}
