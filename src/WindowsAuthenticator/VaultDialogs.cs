using Totp;
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
/// Asks for a vault, one of the keys of its TOTP engine, and an account name, and adds the account. The keys the
/// policy lets the app list are offered, after the dialog opens and when the vault changes; any name can be typed.
/// </summary>
internal sealed class FromVaultDialog : VaultFieldsDialog
{
    private readonly ComboBox key;
    private readonly Label hint;
    private int listing;

    public FromVaultDialog(AccountStore store, IReadOnlyList<VaultSession> sessions)
        : base(sessions, "Add from Vault", "Pick a key of the vault's TOTP engine, or type its name.", "Add")
    {
        key = AddField("Key", new ComboBox { DropDownStyle = ComboBoxStyle.DropDown });
        hint = AddHint("");
        var name = AddField("Account name", new TextBox { PlaceholderText = "Empty to take it from the key" });
        Shown += (_, _) => VaultChanged(Session);
        InitialFocus = key;
        Accepting = async cancel =>
        {
            var keyName = Required(key, "Key");
            Progress("Reading the key from the vault");
            await Dialogs.AddVaultAccountAsync(store, Session, keyName, name.Text.Trim(), cancel);
            return true;
        };
    }

    /// <summary>Lists the keys of the vault; the list of a vault that was left is dropped.</summary>
    protected override async void VaultChanged(VaultSession session)
    {
        var current = ++listing;
        key.Items.Clear();
        key.Text = "";
        hint.Text = "Listing the keys...";
        string text;
        IReadOnlyList<string> keys = [];
        try
        {
            keys = await session.AuthorizedAsync("Listing the keys", (client, cancel) => client.ListKeysAsync(cancel));
            text = keys.Count == 0 ? "The engine lists no keys." : "";
        }
        catch (OperationCanceledException)
        {
            text = "Not listed: cancelled";
        }
        catch (Exception error)
        {
            text = $"Not listed: {VaultProblem.From(error).Title}";
        }
        if (current != listing || IsDisposed)
        {
            return;
        }
        key.Items.AddRange([.. keys]);
        hint.Text = text;
    }
}

/// <summary>Asks for the parameters of an account, and has the vault generate it in a new key.</summary>
internal sealed class GenerateKeyDialog : VaultFieldsDialog
{
    public GenerateKeyDialog(AccountStore store, IReadOnlyList<VaultSession> sessions)
        : base(sessions, "Generate Account in Vault",
               "The vault makes the secret, keeps it in the key, and shows it once, to be scanned into another authenticator.",
               "Generate")
    {
        var key = AddField("Vault key", new TextBox { PlaceholderText = "Name of the key in the vault" });
        var issuer = AddField("Issuer", new TextBox { PlaceholderText = "The organisation the key is for" });
        var account = AddField("Account name", new TextBox { PlaceholderText = "For example your e-mail address" });
        InitialFocus = key;
        Accepting = async cancel =>
        {
            var name = Required(key, "Vault key");
            var issuerText = Required(issuer, "Issuer");
            var accountText = Required(account, "Account name");
            store.CheckCanAdd($"{issuerText}: {accountText}");
            Progress("Generating the key in the vault");
            Generated = await Session.AuthorizedAsync("Generating the key",
                                                      (client, token) => client.GenerateKeyAsync(name, issuerText, accountText, token),
                                                      cancellationToken: cancel);
            Key = name;
            return true;
        };
    }

    /// <summary>The key the vault generated, once the dialog closed with OK.</summary>
    public GeneratedKey? Generated { get; private set; }

    public string Key { get; private set; } = "";
}

/// <summary>Asks for a key name and a base32 secret or otpauth URI, and has the vault store the account in a new key.</summary>
internal sealed class ImportKeyDialog : VaultFieldsDialog
{
    public ImportKeyDialog(AccountStore store, IReadOnlyList<VaultSession> sessions)
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
        Accepting = async cancel =>
        {
            var keyName = Required(key, "Vault key");
            var input = secret.Text;
            var typed = name.Text.Trim();
            store.CheckCanAdd(typed.Length == 0 ? OtpAuth.Parse(keyName, input).Account.Name : typed);
            Progress("Importing the key into the vault");
            await Session.AuthorizedAsync("Importing the key", async (client, token) =>
            {
                await client.ImportKeyAsync(keyName, input, token);
                return true;
            }, cancellationToken: cancel);
            Key = keyName;
            AccountName = typed;
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
