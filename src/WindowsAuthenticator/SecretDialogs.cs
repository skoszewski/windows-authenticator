using Vault;

namespace WindowsAuthenticator;

/// <summary>Asks for a name and a secret until a secret account is added to Credential Manager or Cancel is chosen.</summary>
internal sealed class SecretDialog : FieldsDialog
{
    public SecretDialog(AccountStore store)
        : base("Add Secret", "The secret is kept in Credential Manager.", "Add")
    {
        var name = AddField("Name", new TextBox { PlaceholderText = "Name of the account" });
        var secret = AddField("Secret", new TextBox
        {
            UseSystemPasswordChar = true,
            PlaceholderText = "The password or key to keep",
        });
        var authenticate = AddField("Authentication", AuthenticateBox());
        InitialFocus = name;
        Accepting = _ =>
        {
            store.AddSecret(name.Text, secret.Text, authenticate.Checked);
            return Task.FromResult(true);
        };
    }

    /// <summary>The setting of a new secret account that asks for Windows Hello before its secret is shown or copied.</summary>
    public static CheckBox AuthenticateBox() =>
        new() { Text = "Ask to authenticate before it is shown or copied", Checked = true, AutoSize = true };
}

/// <summary>
/// Asks for the vault, the KV version, the mount, the secret and the field, and adds a secret account reading that
/// field. When writing, it also asks for the value, which is set in the field first; the other fields of the secret
/// are kept, and a field that holds a value is replaced only after the dialog says so and the button is pressed
/// again. The secrets of the mount are listed when the dialog opens and when the vault, the version or the mount
/// changes, and offered; any name can be typed.
/// </summary>
internal sealed class VaultSecretDialog : VaultFieldsDialog
{
    private readonly ComboBox version;
    private readonly TextBox mount;
    private readonly ComboBox secretName;
    private readonly Label hint;
    private int listing;

    public VaultSecretDialog(AccountStore store, IReadOnlyList<VaultSession> sessions, bool writing)
        : base(sessions, writing ? "Add Secret in Vault" : "Add Secret from Vault",
               writing
                   ? "The field is set in the vault's secret, which is created when it does not exist; its other fields are kept."
                   : "Pick a secret of the mount, or type its name, and name the field to read.",
               "Add")
    {
        version = AddField("KV version", new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList });
        version.Items.AddRange(["KV v2", "KV v1"]);
        version.SelectedIndex = 0;
        mount = AddField("Mount", new TextBox { Text = "secret", PlaceholderText = "The mount of the KV engine" });
        secretName = AddField("Secret name", new ComboBox { DropDownStyle = ComboBoxStyle.DropDown });
        hint = AddHint("");
        var field = AddField("Field", new TextBox { Text = "password", PlaceholderText = "For example password" });
        var value = writing
            ? AddField("Secret value", new TextBox { UseSystemPasswordChar = true, PlaceholderText = "The password or key to keep" })
            : null;
        var name = AddField("Account name", new TextBox { PlaceholderText = "Empty to use the secret name and the field" });
        var authenticate = AddField("Authentication", SecretDialog.AuthenticateBox());
        version.SelectedIndexChanged += (_, _) => VaultChanged(Session);
        mount.Leave += (_, _) => VaultChanged(Session);
        Shown += (_, _) => VaultChanged(Session);
        InitialFocus = mount;

        SecretReference? confirmed = null;
        Accepting = async cancel =>
        {
            var session = Session;
            var reference = new SecretReference(Version, mount.Text, secretName.Text, field.Text).Validated();
            var typed = name.Text.Trim();
            var accountName = typed.Length == 0 ? $"{reference.Name}: {reference.Field}" : typed;
            store.CheckCanAdd(accountName);
            if (value is not null)
            {
                var text = value.Text;
                if (text.Length == 0)
                {
                    throw new StoreException("The secret is empty.");
                }
                if (confirmed != reference)
                {
                    Progress("Checking the field in the vault");
                    try
                    {
                        if (await session.AuthorizedAsync("Checking the field",
                                                          (client, token) => client.SecretFieldExistsAsync(reference, token),
                                                          cancellationToken: cancel))
                        {
                            confirmed = reference;
                            Ask($"The field {reference.Field} of the secret {reference.Name} holds a value, which is replaced. "
                                + "Press Replace to write it.", "Replace");
                            return false;
                        }
                    }
                    catch (VaultException error) when (error.IsDenied)
                    {
                        confirmed = reference;
                        Ask("The vault does not let this token read the field, so it cannot be told whether the field holds a "
                            + "value. A value it holds is replaced. Press Write to write it.", "Write");
                        return false;
                    }
                }
                Progress("Writing the secret in the vault");
                await session.AuthorizedAsync("Writing the secret", async (client, token) =>
                {
                    await client.WriteSecretAsync(reference, text, token);
                    return true;
                }, cancellationToken: cancel);
            }
            else
            {
                Progress("Reading the secret from the vault");
                await session.AuthorizedAsync("Reading the secret", (client, token) => client.ReadSecretAsync(reference, token),
                                              cancellationToken: cancel);
            }

            // A failure to add the account is reported, and the secret is not written again.
            try
            {
                store.AddVaultSecret(accountName, reference, session.Profile.Id, authenticate.Checked);
            }
            catch (Exception error) when (error is StoreException || AccountStore.IsStorageFailure(error))
            {
                Dialogs.ShowError(writing ? "The secret was written in the vault but the account was not added"
                                          : "The account was not added", error.Message, this);
            }
            return true;
        };
    }

    private KvVersion Version => version.SelectedIndex == 1 ? KvVersion.V1 : KvVersion.V2;

    /// <summary>Lists the secrets of the mount again; the list of a vault, version or mount that was left is dropped.</summary>
    protected override async void VaultChanged(VaultSession session)
    {
        var current = ++listing;
        secretName.Items.Clear();
        var mountText = mount.Text;
        if (mountText.Trim().Trim('/').Length == 0)
        {
            hint.Text = "";
            return;
        }
        hint.Text = "Listing the secrets...";
        var kv = Version;
        IReadOnlyList<string> names = [];
        string text;
        try
        {
            names = await session.AuthorizedAsync("Listing the secrets",
                                                  (client, token) => client.ListSecretsAsync(mountText, kv, token),
                                                  reportFailure: false);
            text = "";
        }
        catch (OperationCanceledException)
        {
            text = "Not listed: cancelled";
        }
        catch (Exception error)
        {
            // A policy that does not allow listing leaves the names to be typed.
            text = $"Not listed: {VaultProblem.From(error).Title}";
        }
        if (current == listing && !IsDisposed)
        {
            secretName.Items.AddRange([.. names]);
            hint.Text = text;
        }
    }
}
