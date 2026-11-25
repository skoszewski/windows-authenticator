using Vault;

namespace WindowsAuthenticator;

/// <summary>A dialog whose first field chooses one of the vaults.</summary>
internal abstract class VaultFieldsDialog : FieldsDialog
{
    private readonly ComboBox vault;
    private readonly IReadOnlyList<VaultSession> sessions;

    protected VaultFieldsDialog(IReadOnlyList<VaultSession> sessions, string title, string information, string acceptText)
        : base(title, information, acceptText)
    {
        this.sessions = sessions;
        vault = AddField("Vault", new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList });
        vault.Items.AddRange([.. sessions.Select(s => s.Profile.Name)]);
        vault.SelectedIndex = 0;
        vault.SelectedIndexChanged += (_, _) => VaultChanged(Session);
    }

    /// <summary>The chosen vault.</summary>
    public VaultSession Session => sessions[Math.Max(vault.SelectedIndex, 0)];

    /// <summary>Called when another vault is chosen.</summary>
    protected virtual void VaultChanged(VaultSession session)
    {
    }

    /// <summary>The trimmed text of a field the action needs.</summary>
    protected static string Required(Control field, string name) =>
        field.Text.Trim() is { Length: > 0 } text ? text : throw SessionException.MissingSetting(name);
}

/// <summary>
/// Asks for a vault, one of the keys of its TOTP engine, and an account name until an account is added or
/// Cancel is chosen. The keys the policy lets the app list are offered; any name can be typed.
/// </summary>
internal sealed class FromVaultDialog : VaultFieldsDialog
{
    private readonly ComboBox key;
    private readonly IReadOnlyDictionary<Guid, IReadOnlyList<string>> keys;

    public FromVaultDialog(AccountStore store, IReadOnlyList<VaultSession> sessions,
                           IReadOnlyDictionary<Guid, IReadOnlyList<string>> keys, string notes)
        : base(sessions, "Add from Vault", "Pick a key of the vault's TOTP engine, or type its name." + notes, "Add")
    {
        this.keys = keys;
        key = AddField("Key", new ComboBox { DropDownStyle = ComboBoxStyle.DropDown });
        var name = AddField("Account name", new TextBox { PlaceholderText = "Empty to take it from the key" });
        VaultChanged(Session);
        InitialFocus = key;
        Accepting = async () =>
        {
            await Dialogs.AddVaultAccountAsync(store, Session, Required(key, "Key"), name.Text.Trim());
            return true;
        };
    }

    protected override void VaultChanged(VaultSession session)
    {
        key.Items.Clear();
        key.Text = "";
        key.Items.AddRange([.. keys.GetValueOrDefault(session.Profile.Id) ?? Array.Empty<string>()]);
    }
}

/// <summary>Asks for the parameters of an account until the vault generates it in a new key or Cancel is chosen.</summary>
internal sealed class GenerateKeyDialog : VaultFieldsDialog
{
    public GenerateKeyDialog(IReadOnlyList<VaultSession> sessions)
        : base(sessions, "Generate Account in Vault",
               "The vault makes the secret, keeps it in the key, and shows it once, to be scanned into another authenticator.",
               "Generate")
    {
        var key = AddField("Vault key", new TextBox { PlaceholderText = "Name of the key in the vault" });
        var issuer = AddField("Issuer", new TextBox { PlaceholderText = "The organisation the key is for" });
        var account = AddField("Account name", new TextBox { PlaceholderText = "For example your e-mail address" });
        InitialFocus = key;
        Accepting = async () =>
        {
            var name = Required(key, "Vault key");
            var issuerText = Required(issuer, "Issuer");
            var accountText = Required(account, "Account name");
            Generated = await Session.AuthorizedAsync(client => client.GenerateKeyAsync(name, issuerText, accountText));
            Key = name;
            return true;
        };
    }

    /// <summary>The key the vault generated, once the dialog closed with OK.</summary>
    public GeneratedKey? Generated { get; private set; }

    public string Key { get; private set; } = "";
}

/// <summary>
/// Asks for a key name and a base32 secret or otpauth URI until the vault stores the account in a new key or
/// Cancel is chosen.
/// </summary>
internal sealed class ImportKeyDialog : VaultFieldsDialog
{
    public ImportKeyDialog(IReadOnlyList<VaultSession> sessions)
        : base(sessions, "Import Account into Vault",
               "The vault keeps the secret in the key; it supports SHA1, SHA256 and SHA512 with 6 or 8 digits.", "Import")
    {
        var key = AddField("Vault key", new TextBox { PlaceholderText = "Name of the key in the vault" });
        var secret = AddField("Secret or otpauth URI", new TextBox
        {
            UseSystemPasswordChar = true,
            PlaceholderText = "Base32 secret or otpauth://totp/... URI",
        });
        var name = AddField("Account name", new TextBox { PlaceholderText = "Empty to take it from the key" });
        InitialFocus = key;
        Accepting = async () =>
        {
            var keyName = Required(key, "Vault key");
            var input = secret.Text;
            await Session.AuthorizedAsync(async client =>
            {
                await client.ImportKeyAsync(keyName, input);
                return true;
            });
            Key = keyName;
            AccountName = name.Text.Trim();
            return true;
        };
    }

    /// <summary>The key the vault stored, once the dialog closed with OK.</summary>
    public string Key { get; private set; } = "";

    public string AccountName { get; private set; } = "";
}

/// <summary>Shows the QR code and URL of a generated key until Done is chosen; Copy URL puts the URL in the clipboard.</summary>
internal sealed class GeneratedKeyDialog : FieldsDialog
{
    private readonly PictureBox? picture;

    public GeneratedKeyDialog(GeneratedKey key)
        : base("Account Generated",
               "Scan the QR code with another authenticator now, or copy the URL. Vault does not show the secret again.",
               "Done", cancellable: false)
    {
        if (key.QrCode is { } png)
        {
            try
            {
                using var stream = new MemoryStream(png);
                using var image = Image.FromStream(stream);
                picture = new PictureBox
                {
                    Image = new Bitmap(image),
                    Size = new Size(200, 200),
                    SizeMode = PictureBoxSizeMode.Zoom,
                    Anchor = AnchorStyles.None,
                };
                AddControl(picture);
            }
            catch (ArgumentException)
            {
                picture = null;
            }
        }
        var url = AddField("otpauth URL", new TextBox { Text = key.Url, ReadOnly = true, Multiline = true, Height = 60 });
        InitialFocus = url;
        AddButton("Copy URL").Click += (_, _) => Dialogs.CopyText(key.Url);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            picture?.Image?.Dispose();
        }
        base.Dispose(disposing);
    }
}
