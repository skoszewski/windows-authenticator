using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using Totp;
using Vault;
using ZXing;

namespace WindowsAuthenticator;

/// <summary>
/// The dialogs of the tray menu and the Settings window: errors, About, adding, adding from a QR code, the Vault
/// keys, and removing.
/// </summary>
internal static class Dialogs
{
    public const string AppName = "Windows Authenticator";

    /// <summary>Shows the page over the owner, or in the middle of the screen without one.</summary>
    private static TaskDialogButton Show(TaskDialogPage page, IWin32Window? owner) =>
        owner is null
            ? TaskDialog.ShowDialog(page, TaskDialogStartupLocation.CenterScreen)
            : TaskDialog.ShowDialog(owner, page, TaskDialogStartupLocation.CenterOwner);

    public static void ShowError(string heading, string text, IWin32Window? owner = null) =>
        Show(new TaskDialogPage
        {
            Caption = AppName,
            Heading = heading,
            Text = text,
            Icon = TaskDialogIcon.Warning,
            Buttons = { TaskDialogButton.OK },
        }, owner);

    /// <summary>
    /// The text of an error: for a Vault problem what is wrong, what happened and what to do, and the message of
    /// any other error.
    /// </summary>
    public static string Describe(Exception error) =>
        error is VaultException or IVaultProblemSource or System.Net.Sockets.SocketException
            ? VaultProblem.From(error).Report
            : error.Message;

    /// <summary>
    /// The steps of a connection test or a setup, one line each with its outcome, and for a step that did not
    /// pass what is wrong and what to do on the lines under it.
    /// </summary>
    public static string FormatChecks(IEnumerable<VaultCheck> checks) =>
        string.Join(Environment.NewLine, checks.Select(check =>
        {
            var line = $"{check.Outcome,-8} {check.Step}: {check.Message}";
            return check.Problem is { } found
                ? $"{line}{Environment.NewLine}         {found.Detail}{Environment.NewLine}         {found.Suggestion}"
                : line;
        }));

    /// <summary>Shows an error as its problem: what is wrong, what happened and what to do.</summary>
    public static void ShowProblem(string heading, Exception error, IWin32Window? owner = null) =>
        ShowError(heading, Describe(error), owner);

    /// <summary>Puts the text in the clipboard, telling when it could not.</summary>
    public static void CopyText(string text)
    {
        try
        {
            Clipboard.SetText(text);
        }
        catch (ExternalException error)
        {
            ShowError("The text was not copied", error.Message);
        }
    }

    public static void ShowAbout() =>
        Show(new TaskDialogPage
        {
            Caption = $"About {AppName}",
            Heading = AppName,
            Text = $"Version {Application.ProductVersion}",
            Icon = TaskDialogIcon.Information,
            Buttons = { TaskDialogButton.OK },
        }, null);

    /// <summary>Asks a question whose answer is the named button or Cancel; true for the named button.</summary>
    private static bool Confirm(string heading, string text, string action, IWin32Window? owner)
    {
        var confirm = new TaskDialogButton(action);
        return Show(new TaskDialogPage
        {
            Caption = AppName,
            Heading = heading,
            Text = text,
            Icon = TaskDialogIcon.Warning,
            Buttons = { confirm, TaskDialogButton.Cancel },
            DefaultButton = TaskDialogButton.Cancel,
        }, owner) == confirm;
    }

    /// <summary>Asks before deleting the account and its secret; true when it was removed.</summary>
    public static bool RemoveAccount(Account account, AccountStore store, IWin32Window? owner = null)
    {
        var text = store.VaultKeyOf(account) is null
            ? "Its secret is deleted from Credential Manager; the account can only be added again with the secret."
            : "The account is removed from this app; its key stays in the vault.";
        if (!Confirm($"Remove {account.Name}?", text, "Remove", owner))
        {
            return false;
        }
        try
        {
            store.Remove(account);
            return true;
        }
        catch (Exception error) when (error is StoreException || AccountStore.IsStorageFailure(error))
        {
            ShowError($"{account.Name} was not removed", error.Message, owner);
            return false;
        }
    }

    /// <summary>Asks before deleting the vault, its credential and its accounts; true when it was removed.</summary>
    public static bool RemoveVault(VaultSession session, AccountStore store, IWin32Window? owner = null)
    {
        var count = store.AccountsOf(session.Profile.Id).Count;
        if (!Confirm($"Remove the vault {session.Profile.Name}?",
                     $"Its credential is deleted from Credential Manager, and so are its {count} accounts from this app; their keys stay in the vault.",
                     "Remove", owner))
        {
            return false;
        }
        try
        {
            store.RemoveVaultProfile(session);
            return true;
        }
        catch (Exception error) when (error is StoreException || AccountStore.IsStorageFailure(error))
        {
            ShowError($"{session.Profile.Name} was not removed", error.Message, owner);
            return false;
        }
    }

    public static void AddAccount(AccountStore store, IWin32Window? owner = null, string input = "")
    {
        using var dialog = new AddAccountDialog(store, input);
        dialog.ShowDialog(owner);
    }

    /// <summary>Reads an otpauth URI from a QR code in the clipboard's image and asks to add it.</summary>
    public static void AddAccountFromClipboard(AccountStore store, IWin32Window? owner = null)
    {
        using var image = Clipboard.GetImage();
        if (image is null)
        {
            ShowError("The clipboard holds no image",
                      "Copy an image of the QR code first, for example with Windows+Shift+S.", owner);
            return;
        }
        string[] payloads;
        try
        {
            payloads = QrPayloads(image);
        }
        catch (Exception error) when (error is ArgumentException or ExternalException or ReaderException)
        {
            ShowError("The QR code could not be read", error.Message, owner);
            return;
        }
        if (payloads.Length == 0)
        {
            ShowError("No QR code was found", "The image in the clipboard holds no QR code that could be read.", owner);
            return;
        }
        var uri = payloads.FirstOrDefault(p => p.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase));
        if (uri is null)
        {
            ShowError("The QR code holds no otpauth URI",
                      "Only otpauth://totp/ codes can be added; exports of other apps, such as otpauth-migration://, cannot.",
                      owner);
            return;
        }
        AddAccount(store, owner, uri);
    }

    /// <summary>The texts of the QR codes in the image, read from its pixels as BGRA.</summary>
    private static string[] QrPayloads(Image image)
    {
        using var bitmap = new Bitmap(image);
        var area = new Rectangle(0, 0, bitmap.Width, bitmap.Height);
        var data = bitmap.LockBits(area, ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
        var rowLength = bitmap.Width * 4;
        var pixels = new byte[rowLength * bitmap.Height];
        try
        {
            for (var row = 0; row < bitmap.Height; row++)
            {
                Marshal.Copy(data.Scan0 + row * data.Stride, pixels, row * rowLength, rowLength);
            }
        }
        finally
        {
            bitmap.UnlockBits(data);
        }
        var reader = new BarcodeReaderGeneric { AutoRotate = true };
        reader.Options.PossibleFormats = [BarcodeFormat.QR_CODE];
        reader.Options.TryHarder = true;
        var results = reader.DecodeMultiple(pixels, bitmap.Width, bitmap.Height, RGBLuminanceSource.BitmapFormat.BGRA32);
        return results is null ? [] : [.. results.Select(r => r.Text).OfType<string>()];
    }

    /// <summary>The vaults to choose from, or null, after telling so, when none is set up.</summary>
    private static IReadOnlyList<VaultSession>? Vaults(AccountStore store, IWin32Window? owner)
    {
        if (store.Vaults.Count == 0)
        {
            ShowError("No vault is set up", "Accounts can be taken from a vault once one is set up.", owner);
            return null;
        }
        return [.. store.Vaults];
    }

    /// <summary>Adds the account the vault key stores to the app; an empty name is the key's suggested name.</summary>
    public static async Task AddVaultAccountAsync(AccountStore store, VaultSession session, string key, string name)
    {
        var info = await session.AuthorizedAsync(client => client.ReadKeyAsync(key));
        store.AddVaultAccount(info.Account(name.Length == 0 ? info.SuggestedName : name), key, session.Profile.Id);
    }

    /// <summary>Lists the keys of each vault, as far as their policies allow, and asks for the key of a new account.</summary>
    public static async Task AddFromVaultAsync(AccountStore store, IWin32Window? owner = null)
    {
        if (Vaults(store, owner) is not { } sessions)
        {
            return;
        }
        var keys = new Dictionary<Guid, IReadOnlyList<string>>();
        var notes = new List<string>();
        foreach (var session in sessions)
        {
            try
            {
                keys[session.Profile.Id] = await session.AuthorizedAsync(client => client.ListKeysAsync());
            }
            catch (Exception error)
            {
                notes.Add($"{session.Profile.Name}: {VaultProblem.From(error).Title}.");
            }
        }
        var note = notes.Count == 0 ? "" : " The keys could not be listed: " + string.Join(" ", notes);
        using var dialog = new FromVaultDialog(store, sessions, keys, note);
        dialog.ShowDialog(owner);
    }

    /// <summary>
    /// Has a vault generate the secret of a new account in a new key, shows its QR code, and adds the account to
    /// the app. A failure to add the account is reported, and the key is not generated again.
    /// </summary>
    public static async Task GenerateAccountAsync(AccountStore store, IWin32Window? owner = null)
    {
        if (Vaults(store, owner) is not { } sessions)
        {
            return;
        }
        using var dialog = new GenerateKeyDialog(sessions);
        if (dialog.ShowDialog(owner) != DialogResult.OK || dialog.Generated is not { } generated)
        {
            return;
        }
        using (var shown = new GeneratedKeyDialog(generated))
        {
            shown.ShowDialog(owner);
        }
        try
        {
            await AddVaultAccountAsync(store, dialog.Session, dialog.Key, "");
        }
        catch (Exception error)
        {
            ShowError("The account was generated in the vault but not added", Describe(error), owner);
        }
    }

    /// <summary>
    /// Has a vault store the secret of an account in a new key, and adds the account to the app. A failure to add
    /// the account is reported, and the key is not imported again.
    /// </summary>
    public static async Task ImportAccountAsync(AccountStore store, IWin32Window? owner = null)
    {
        if (Vaults(store, owner) is not { } sessions)
        {
            return;
        }
        using var dialog = new ImportKeyDialog(sessions);
        if (dialog.ShowDialog(owner) != DialogResult.OK)
        {
            return;
        }
        try
        {
            await AddVaultAccountAsync(store, dialog.Session, dialog.Key, dialog.AccountName);
        }
        catch (Exception error)
        {
            ShowError("The account was imported into the vault but not added", Describe(error), owner);
        }
    }
}
