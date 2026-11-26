namespace Vault.Tests;

/// <summary>Fields of KV v1 and v2 secrets against the dev server.</summary>
[TestClass]
public sealed class SecretTests
{
    private static VaultClient Root() => new(new VaultConfiguration(VaultDevServer.Address), VaultDevServer.RootToken);

    private static SecretReference Reference(KvVersion version, string name = "app", string field = "password") =>
        new(version, $"kv{(int)version}", name, field);

    [TestMethod]
    [DataRow(KvVersion.V1)]
    [DataRow(KvVersion.V2)]
    public async Task ReadsAFieldOfASecret(KvVersion version)
    {
        var vault = Root();
        Assert.AreEqual($"p{(int)version}", await vault.ReadSecretAsync(Reference(version)));
        Assert.AreEqual($"keep{(int)version}", await vault.ReadSecretAsync(Reference(version, field: "other")));
    }

    [TestMethod]
    [DataRow(KvVersion.V1)]
    [DataRow(KvVersion.V2)]
    public async Task AMissingSecretOrFieldIsNamed(KvVersion version)
    {
        var vault = Root();
        var secret = await Assert.ThrowsExactlyAsync<VaultException>(() => vault.ReadSecretAsync(Reference(version, name: "nothing")));
        Assert.AreEqual(VaultErrorKind.NoSecret, secret.Kind);
        Assert.AreEqual("The secret does not exist", VaultProblem.From(secret).Title);
        var field = await Assert.ThrowsExactlyAsync<VaultException>(() => vault.ReadSecretAsync(Reference(version, field: "nope")));
        Assert.AreEqual(VaultErrorKind.MissingField, field.Kind);
        Assert.AreEqual("The secret app holds no field named nope.", VaultProblem.From(field).Detail);
    }

    [TestMethod]
    [DataRow(KvVersion.V1)]
    [DataRow(KvVersion.V2)]
    public async Task WritingAFieldKeepsTheOtherFields(KvVersion version)
    {
        var vault = Root();
        await vault.WriteSecretAsync(Reference(version, "kept", "first"), "one");
        await vault.WriteSecretAsync(Reference(version, "kept", "second"), "two");
        await vault.WriteSecretAsync(Reference(version, "kept", "first"), "three");
        Assert.AreEqual("three", await vault.ReadSecretAsync(Reference(version, "kept", "first")));
        Assert.AreEqual("two", await vault.ReadSecretAsync(Reference(version, "kept", "second")));
    }

    [TestMethod]
    [DataRow(KvVersion.V1)]
    [DataRow(KvVersion.V2)]
    public async Task WritingAFieldKeepsAFieldOfAnotherType(KvVersion version)
    {
        if (version == KvVersion.V1)
        {
            await VaultDevServer.AdminAsync("POST", "kv1/typed", new { count = 3 });
        }
        else
        {
            await VaultDevServer.AdminAsync("POST", "kv2/data/typed", new { data = new { count = 3 } });
        }
        await Root().WriteSecretAsync(Reference(version, "typed"), "pw");
        var reply = await VaultDevServer.AdminAsync("GET", version == KvVersion.V1 ? "kv1/typed" : "kv2/data/typed");
        var fields = version == KvVersion.V1 ? reply.GetProperty("data") : reply.GetProperty("data").GetProperty("data");
        Assert.AreEqual(3, fields.GetProperty("count").GetInt32());
        Assert.AreEqual("pw", fields.GetProperty("password").GetString());
    }

    [TestMethod]
    [DataRow(KvVersion.V1)]
    [DataRow(KvVersion.V2)]
    public async Task ListsTheSecretsOfAMountWithoutFolders(KvVersion version)
    {
        var vault = Root();
        var names = await vault.ListSecretsAsync($"kv{(int)version}/", version);
        CollectionAssert.Contains(names.ToList(), "app");
        CollectionAssert.DoesNotContain(names.ToList(), "dir/");
        Assert.AreEqual(0, (await vault.ListSecretsAsync("nowhere", version)).Count);
    }

    [TestMethod]
    [DataRow(KvVersion.V1)]
    [DataRow(KvVersion.V2)]
    public async Task TheExistenceOfAFieldIsToldWithoutAnErrorForAnAbsentSecretOrField(KvVersion version)
    {
        var vault = Root();
        Assert.IsTrue(await vault.SecretFieldExistsAsync(Reference(version)));
        Assert.IsFalse(await vault.SecretFieldExistsAsync(Reference(version, field: "absent")));
        Assert.IsFalse(await vault.SecretFieldExistsAsync(Reference(version, name: "absent")));
    }

    [TestMethod]
    public async Task ADeletedKvV2SecretIsToldApartFromAnAbsentOne()
    {
        await VaultDevServer.AdminAsync("POST", "kv2/data/gone", new { data = new { password = "x" } });
        await VaultDevServer.AdminAsync("POST", "kv2/delete/gone", new { versions = new[] { 1 } });
        var vault = Root();
        var deleted = await Assert.ThrowsExactlyAsync<VaultException>(() => vault.ReadSecretAsync(Reference(KvVersion.V2, "gone")));
        Assert.AreEqual(VaultErrorKind.SecretDeleted, deleted.Kind);
        Assert.AreEqual("The secret was deleted", VaultProblem.From(deleted).Title);
        var absent = await Assert.ThrowsExactlyAsync<VaultException>(() => vault.ReadSecretAsync(Reference(KvVersion.V2, "never")));
        Assert.AreEqual(VaultErrorKind.NoSecret, absent.Kind);
    }

    [TestMethod]
    public async Task ACancelledCallThrowsOperationCanceledException()
    {
        using var source = new CancellationTokenSource();
        await source.CancelAsync();
        await Assert.ThrowsAsync<OperationCanceledException>(() => Root().ReadSecretAsync(Reference(KvVersion.V2), source.Token));
        Assert.AreEqual("The request was cancelled", VaultProblem.From(new OperationCanceledException()).Title);
    }
}

/// <summary>A secret reference, without a server.</summary>
[TestClass]
public sealed class SecretReferenceTests
{
    [TestMethod]
    public void AReferenceIsTrimmed() =>
        Assert.AreEqual(new SecretReference(KvVersion.V2, "kv2", "app", "password"),
                        new SecretReference(KvVersion.V2, " /kv2/ ", "app/", " password ").Validated());

    [TestMethod]
    [DataRow("", "a", "f")]
    [DataRow("m", " ", "f")]
    [DataRow("m", "a", "")]
    public void AReferenceWithAnEmptyPartIsRefused(string mount, string name, string field) =>
        Assert.ThrowsExactly<EmptyValueException>(() => new SecretReference(KvVersion.V1, mount, name, field).Validated());

    [TestMethod]
    [DataRow("a//b")]
    [DataRow("..")]
    [DataRow("a/../b")]
    [DataRow("./a")]
    [DataRow("a/\u0007")]
    public void AReferenceWithAMountThatIsNotAPathOfNamesIsRefused(string mount) =>
        Assert.ThrowsExactly<InvalidValueException>(() => new SecretReference(KvVersion.V2, mount, "app", "f").Validated());
}

/// <summary>The paths a user types, without a server.</summary>
[TestClass]
public sealed class VaultPathTests
{
    [TestMethod]
    [DataRow("")]
    [DataRow("a//b")]
    [DataRow("..")]
    [DataRow("a/../b")]
    [DataRow("./a")]
    [DataRow("a/\u0007")]
    public void APathWithAnEmptyNameADotNameOrAControlCharacterIsRefused(string path) =>
        Assert.IsNotNull(VaultPath.Problem(path));

    [TestMethod]
    [DataRow("secret")]
    [DataRow("team/kv")]
    [DataRow("a b/c")]
    public void APathOfNamesIsAccepted(string path) => Assert.IsNull(VaultPath.Problem(path));

    [TestMethod]
    public void AMountOrNameIsEscapedInTheRequestPath()
    {
        Assert.AreEqual("a%20b/c%3Fd", VaultPath.Escaped("/a b/c?d/"));
        var client = new VaultClient(new VaultConfiguration("http://127.0.0.1:8200", totpMount: "a b/c?d"), "t");
        using var request = client.MakeRequest(HttpMethod.Get, $"{VaultPath.Escaped("a b/c?d")}/keys");
        Assert.AreEqual("/v1/a%20b/c%3Fd/keys", request.RequestUri!.AbsolutePath);
        Assert.AreEqual("", request.RequestUri.Query);
    }
}
