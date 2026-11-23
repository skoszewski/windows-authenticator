using Microsoft.Win32;

namespace WindowsAuthenticator;

/// <summary>
/// The app's settings in the current user's registry: the menu order of the accounts and the Run value
/// that starts the app at sign-in.
/// </summary>
internal static class Settings
{
    private const string KeyPath = @"Software\pl.waw.koszewscy\WindowsAuthenticator";
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunValueName = "Windows Authenticator";

    /// <summary>The ids of the accounts in menu order.</summary>
    public static string[] AccountOrder
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(KeyPath);
            return key?.GetValue("AccountOrder") as string[] ?? [];
        }
        set
        {
            using var key = Registry.CurrentUser.CreateSubKey(KeyPath);
            key.SetValue("AccountOrder", value, RegistryValueKind.MultiString);
        }
    }

    private static string RunCommand => $"\"{Environment.ProcessPath}\"";

    /// <summary>Whether the Run value starts this executable at sign-in.</summary>
    public static bool LaunchesAtLogin
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath);
            return string.Equals(key?.GetValue(RunValueName) as string, RunCommand, StringComparison.OrdinalIgnoreCase);
        }
        set
        {
            using var key = Registry.CurrentUser.CreateSubKey(RunKeyPath);
            if (value)
            {
                key.SetValue(RunValueName, RunCommand, RegistryValueKind.String);
            }
            else
            {
                key.DeleteValue(RunValueName, throwOnMissingValue: false);
            }
        }
    }
}
