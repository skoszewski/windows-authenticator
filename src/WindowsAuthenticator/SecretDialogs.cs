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
        InitialFocus = name;
        Accepting = () =>
        {
            store.AddSecret(name.Text, secret.Text);
            return Task.FromResult(true);
        };
    }
}

/// <summary>
/// Asks for the vault, the KV version, the mount, the secret and the field until a secret account reading that
/// field is added or Cancel is chosen. When writing, it also asks for the value, which is set in the field first;
/// the other fields of the secret are kept. The secrets of the mount are listed when the vault, the version or the
/// mount changes, and offered; any name can be typed.
/// </summary>
internal sealed class VaultSecretDialog : VaultFieldsDialog
{
    private readonly ComboBox version;
    private readonly TextBox mount;
    private readonly ComboBox secretName;
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
        var field = AddField("Field", new TextBox { Text = "password", PlaceholderText = "For example password" });
        var value = writing
            ? AddField("Secret value", new TextBox { UseSystemPasswordChar = true, PlaceholderText = "The password or key to keep" })
            : null;
        var name = AddField("Account name", new TextBox { PlaceholderText = "Empty to use the secret name and the field" });
        version.SelectedIndexChanged += (_, _) => VaultChanged(Session);
        mount.Leave += (_, _) => VaultChanged(Session);
        VaultChanged(Session);
        InitialFocus = mount;

        Accepting = async () =>
        {
            var session = Session;
            var reference = new SecretReference(Version, mount.Text, secretName.Text, field.Text).Validated();
            if (value is not null)
            {
                var text = value.Text;
                if (text.Length == 0)
                {
                    throw new StoreException("The secret is empty.");
                }
                await session.AuthorizedAsync(async client =>
                {
                    await client.WriteSecretAsync(reference, text);
                    return true;
                });
            }
            else
            {
                await session.AuthorizedAsync(client => client.ReadSecretAsync(reference));
            }

            // A failure to add the account is reported, and the secret is not written again.
            var typed = name.Text.Trim();
            try
            {
                store.AddVaultSecret(typed.Length == 0 ? $"{reference.Name}: {reference.Field}" : typed, reference,
                                     session.Profile.Id);
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
            return;
        }
        var kv = Version;
        IReadOnlyList<string> names;
        try
        {
            names = await session.AuthorizedAsync(client => client.ListSecretsAsync(mountText, kv));
        }
        catch (Exception)
        {
            // A policy that does not allow listing leaves the names to be typed.
            return;
        }
        if (current == listing && !IsDisposed)
        {
            secretName.Items.AddRange([.. names]);
        }
    }
}
