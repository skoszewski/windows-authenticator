using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static WindowsAuthenticator.NativeMethods;

namespace WindowsAuthenticator;

/// <summary>
/// Copies a secret to the clipboard kept out of the clipboard history and the cloud clipboard, and empties the
/// clipboard after 30 seconds if it still holds that copy. It runs on the UI thread.
/// </summary>
internal static class ConcealedClipboard
{
    private static readonly TimeSpan ClearAfter = TimeSpan.FromSeconds(30);

    /// <summary>The owner of the copies: a message-only window, since a clipboard emptied without an owner takes no data.</summary>
    private static readonly NativeWindow Owner = new();

    static ConcealedClipboard()
    {
        // HWND_MESSAGE as the parent makes the window message-only.
        Owner.CreateHandle(new CreateParams { Parent = -3 });
    }

    /// <summary>Puts the text in the clipboard with the formats that keep it out of the history and the sync.</summary>
    public static async Task CopyAsync(string text)
    {
        // Another program may hold the clipboard for a moment.
        for (var attempt = 1; !OpenClipboard(Owner.Handle); attempt++)
        {
            if (attempt == 10)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "The clipboard is held by another program.");
            }
            await Task.Delay(100);
        }
        var bytes = Encoding.Unicode.GetBytes(text + '\0');
        try
        {
            if (!EmptyClipboard())
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }
            SetData(CfUnicodeText, bytes);
            var zero = BitConverter.GetBytes(0u);
            SetData(RegisterClipboardFormat("ExcludeClipboardContentFromMonitorProcessing"), zero);
            SetData(RegisterClipboardFormat("CanIncludeInClipboardHistory"), zero);
            SetData(RegisterClipboardFormat("CanUploadToCloudClipboard"), zero);
        }
        finally
        {
            CloseClipboard();
            CryptographicOperations.ZeroMemory(bytes);
        }
        _ = ClearLaterAsync(GetClipboardSequenceNumber());
    }

    /// <summary>Places the bytes in a movable global block, which the clipboard owns once it takes it.</summary>
    private static unsafe void SetData(uint format, byte[] data)
    {
        var memory = GlobalAlloc(GmemMoveable, (nuint)data.Length);
        if (memory == 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
        var target = GlobalLock(memory);
        if (target is null)
        {
            var error = Marshal.GetLastPInvokeError();
            GlobalFree(memory);
            throw new Win32Exception(error);
        }
        data.CopyTo(new Span<byte>(target, data.Length));
        GlobalUnlock(memory);
        if (SetClipboardData(format, memory) == 0)
        {
            var error = Marshal.GetLastPInvokeError();
            GlobalFree(memory);
            throw new Win32Exception(error);
        }
    }

    /// <summary>Empties the clipboard after the delay, unless something else was copied since.</summary>
    private static async Task ClearLaterAsync(uint sequence)
    {
        await Task.Delay(ClearAfter);
        if (GetClipboardSequenceNumber() != sequence)
        {
            return;
        }
        try
        {
            Clipboard.Clear();
        }
        catch (ExternalException)
        {
            // The clipboard is held by another program; the copy stays.
        }
    }
}
