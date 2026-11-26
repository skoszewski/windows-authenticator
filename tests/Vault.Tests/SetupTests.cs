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

    private static KvSetupOptions Kv(KvVersion version, string mount, string creator, string user) =>
        KvSetupOptions.Default(version) with { Mount = mount, CreatorPolicy = creator, UserPolicy = user };

    [TestMethod]
    [DataRow(KvVersion.V2, "setup-e/kv", "setup_e")]
    [DataRow(KvVersion.V1, "setup-g/kv", "setup_g")]
    public async Task TheSetupOfAKvEngineLetsTheCreatorWriteAndTheUserRead(KvVersion version, string mount, string prefix)
    {
        var kv = Kv(version, mount, $"{prefix}_creator", $"{prefix}_user");
        var options = version == KvVersion.V2 ? new VaultSetupOptions(Totp: false, Kv: kv) : new VaultSetupOptions(Totp: false, Kv1: kv);
        var checks = await VaultSetup.RunAsync(Client(VaultDevServer.RootToken), options);
        var label = $"KV v{(int)version}";
        CollectionAssert.AreEqual(new[] { $"{label} engine", $"{label} creator policy", $"{label} user policy" },
                                  checks.Select(c => c.Step).ToList());
        CollectionAssert.AreEqual(AllPassed, Outcomes(checks));

        var reference = new SecretReference(version, mount, "app", "password");
        var creator = Client(await VaultDevServer.TokenAsync($"{prefix}_creator"));
        await creator.WriteSecretAsync(reference, "one");
        await creator.WriteSecretAsync(reference with { Field = "second" }, "two");
        Assert.AreEqual("one", await creator.ReadSecretAsync(reference));
        CollectionAssert.AreEqual(new[] { "app" }, (await creator.ListSecretsAsync(mount, version)).ToList());

        var user = Client(await VaultDevServer.TokenAsync($"{prefix}_user"));
        Assert.AreEqual("one", await user.ReadSecretAsync(reference));
        CollectionAssert.AreEqual(new[] { "app" }, (await user.ListSecretsAsync(mount, version)).ToList());
        Assert.IsTrue((await Assert.ThrowsExactlyAsync<VaultException>(() => user.WriteSecretAsync(reference, "three"))).IsDenied);
    }

    [TestMethod]
    public async Task TheSetupOfEveryEngineRunsTheTotpStepsFirstThenKvV2ThenKvV1()
    {
        var options = new VaultSetupOptions("setup-h/totp", CreatorPolicy: "setup_h_creator", UserPolicy: "setup_h_user",
                                            Kv: Kv(KvVersion.V2, "setup-h/kv2", "setup_h_kv2_creator", "setup_h_kv2_user"),
                                            Kv1: Kv(KvVersion.V1, "setup-h/kv1", "setup_h_kv1_creator", "setup_h_kv1_user"));
        var checks = await VaultSetup.RunAsync(Client(VaultDevServer.RootToken), options);
        CollectionAssert.AreEqual(new[] { "Engine", "KV v2 engine", "KV v1 engine" },
                                  checks.Select(c => c.Step).Where(s => s.EndsWith("engine", StringComparison.OrdinalIgnoreCase)).ToList());
        Assert.AreEqual(9, checks.Count);
        Assert.IsTrue(checks.All(c => c.Outcome == VaultCheckOutcome.Passed));
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
        [new VaultSetupOptions(Totp: false)],
        [new VaultSetupOptions(Kv: KvSetupOptions.Default(KvVersion.V2) with { Mount = "totp" })],
        [new VaultSetupOptions(Kv: KvSetupOptions.Default(KvVersion.V2) with { Mount = "" })],
        [new VaultSetupOptions(Kv: KvSetupOptions.Default(KvVersion.V2) with { CreatorPolicy = "totp_creator" })],
        [new VaultSetupOptions(Kv: KvSetupOptions.Default(KvVersion.V2) with { UserPolicy = "has space" })],
        [new VaultSetupOptions(Kv: KvSetupOptions.Default(KvVersion.V2),
                               Kv1: KvSetupOptions.Default(KvVersion.V1) with { Mount = "secret" })],
        [new VaultSetupOptions(Kv: KvSetupOptions.Default(KvVersion.V2),
                               Kv1: KvSetupOptions.Default(KvVersion.V1) with { CreatorPolicy = "kv_creator" })],
        [new VaultSetupOptions(Totp: false, Kv1: KvSetupOptions.Default(KvVersion.V1) with { Mount = "" })],
    ];

    public static IEnumerable<object[]> UsableOptions =>
    [
        [new VaultSetupOptions()],
        [new VaultSetupOptions(Kv: KvSetupOptions.Default(KvVersion.V2))],
        [new VaultSetupOptions(Totp: false, Kv: KvSetupOptions.Default(KvVersion.V2))],
        [new VaultSetupOptions(Totp: false, Kv1: KvSetupOptions.Default(KvVersion.V1))],
        [new VaultSetupOptions(Kv: KvSetupOptions.Default(KvVersion.V2), Kv1: KvSetupOptions.Default(KvVersion.V1))],
    ];

    [TestMethod]
    [DynamicData(nameof(UnusableOptions))]
    public void OptionsThatCannotBeUsedAreRefused(VaultSetupOptions options) =>
        Assert.IsNotNull(VaultSetup.Problem(options));

    [TestMethod]
    [DynamicData(nameof(UsableOptions))]
    public void TheDefaultsAreUsable(VaultSetupOptions options) => Assert.IsNull(VaultSetup.Problem(options));

    [TestMethod]
    public void TheKvCreatorPolicyListsAndWritesAndReadsSecrets()
    {
        var policy = VaultSetup.KvCreatorPolicy("secret");
        StringAssert.Contains(policy, "path \"secret/metadata\" {\n  capabilities = [\"list\"]");
        StringAssert.Contains(policy, "path \"secret/data/*\" {\n  capabilities = [\"create\", \"update\", \"patch\", \"read\"]");
        Assert.IsFalse(policy.Contains("delete", StringComparison.Ordinal));
    }

    [TestMethod]
    public void TheKvUserPolicyListsAndReadsSecrets()
    {
        var policy = VaultSetup.KvUserPolicy("/team/secret/");
        StringAssert.Contains(policy, "path \"team/secret/metadata\" {\n  capabilities = [\"list\"]");
        StringAssert.Contains(policy, "path \"team/secret/data/*\" {\n  capabilities = [\"read\"]");
        Assert.IsFalse(policy.Contains("create", StringComparison.Ordinal));
    }

    [TestMethod]
    public void TheKvV1PoliciesNameTheMountsPathsWithoutDataOrMetadata()
    {
        var creator = VaultSetup.KvCreatorPolicy("kv", KvVersion.V1);
        StringAssert.Contains(creator, "path \"kv/*\" {\n  capabilities = [\"list\", \"create\", \"update\", \"read\"]");
        Assert.IsFalse(creator.Contains("data", StringComparison.Ordinal) || creator.Contains("patch", StringComparison.Ordinal));
        var user = VaultSetup.KvUserPolicy("/kv/", KvVersion.V1);
        StringAssert.Contains(user, "path \"kv/*\" {\n  capabilities = [\"list\", \"read\"]");
        Assert.IsFalse(user.Contains("create", StringComparison.Ordinal));
    }
}
