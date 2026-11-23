using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using Totp;
using ZXing;

namespace WindowsAuthenticator;

/// <summary>The dialogs of the tray menu: errors, removing, About, and adding from a QR code.</summary>
internal static class Dialogs
{
    public const string AppName = "Windows Authenticator";

    public static void ShowError(string heading, string text)
    {
        TaskDialog.ShowDialog(new TaskDialogPage
        {
            Caption = AppName,
            Heading = heading,
            Text = text,
            Icon = TaskDialogIcon.Warning,
            Buttons = { TaskDialogButton.OK },
        }, TaskDialogStartupLocation.CenterScreen);
    }

    public static void ShowAbout()
    {
        TaskDialog.ShowDialog(new TaskDialogPage
        {
            Caption = $"About {AppName}",
            Heading = AppName,
            Text = $"Version {Application.ProductVersion}",
            Icon = TaskDialogIcon.Information,
            Buttons = { TaskDialogButton.OK },
        }, TaskDialogStartupLocation.CenterScreen);
    }

    /// <summary>Asks before deleting the account and its secret; true when it was removed.</summary>
    public static bool RemoveAccount(Account account, AccountStore store)
    {
        var remove = new TaskDialogButton("Remove");
        var answer = TaskDialog.ShowDialog(new TaskDialogPage
        {
            Caption = AppName,
            Heading = $"Remove {account.Name}?",
            Text = "Its secret is deleted from Credential Manager; the account can only be added again with the secret.",
            Icon = TaskDialogIcon.Warning,
            Buttons = { remove, TaskDialogButton.Cancel },
            DefaultButton = TaskDialogButton.Cancel,
        }, TaskDialogStartupLocation.CenterScreen);
        if (answer != remove)
        {
            return false;
        }
        try
        {
            store.Remove(account);
            return true;
        }
        catch (Exception failure) when (failure is StoreException or CredentialStoreException)
        {
            ShowError($"{account.Name} was not removed", failure.Message);
            return false;
        }
    }

    public static void AddAccount(AccountStore store, string input = "")
    {
        using var dialog = new AddAccountDialog(store, input: input);
        dialog.ShowDialog();
    }

    /// <summary>Reads an otpauth URI from a QR code in the clipboard's image and asks to add it.</summary>
    public static void AddAccountFromClipboard(AccountStore store)
    {
        using var image = Clipboard.GetImage();
        if (image is null)
        {
            ShowError("The clipboard holds no image",
                      "Copy an image of the QR code first, for example with Windows+Shift+S.");
            return;
        }
        string[] payloads;
        try
        {
            payloads = QrPayloads(image);
        }
        catch (Exception failure) when (failure is ArgumentException or ExternalException or ReaderException)
        {
            ShowError("The QR code could not be read", failure.Message);
            return;
        }
        if (payloads.Length == 0)
        {
            ShowError("No QR code was found", "The image in the clipboard holds no QR code that could be read.");
            return;
        }
        var uri = payloads.FirstOrDefault(p => p.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase));
        if (uri is null)
        {
            ShowError("The QR code holds no otpauth URI",
                      "Only otpauth://totp/ codes can be added; exports of other apps, such as otpauth-migration://, cannot.");
            return;
        }
        AddAccount(store, uri);
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
}
