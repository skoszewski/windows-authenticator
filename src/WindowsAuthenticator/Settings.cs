using System.Globalization;
using Microsoft.Win32;
using Vault;

namespace WindowsAuthenticator;

/// <summary>A named Vault connection; its credential is a Credential Manager entry named after it.</summary>
internal sealed record VaultProfile(Guid Id, string Name, VaultConfiguration Configuration);

/// <summary>An account whose codes Vault makes: the account's parameters, its profile and the name of its key.</summary>
internal sealed record VaultRecord(Guid Id, Guid Profile, string Name, string? Issuer, string Parameters, string Key,
                                   DateTime Added);

/// <summary>
/// The app's settings in the current user's registry: the menu order of the accounts, the Vault profiles and
/// the accounts taken from Vault, none of which holds a secret, and the Run value that starts the app at sign-in.
/// </summary>
internal static class Settings
{
    private const string KeyPath = @"Software\pl.waw.koszewscy\WindowsAuthenticator";
    private const string VaultsPath = KeyPath + @"\Vaults";
    private const string VaultAccountsPath = KeyPath + @"\VaultAccounts";
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

    private static string? Text(RegistryKey key, string name) => key.GetValue(name) as string is { Length: > 0 } text ? text : null;

    private static DateTime Time(RegistryKey key, string name) =>
        DateTime.TryParse(Text(key, name), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var time)
            ? time
            : DateTime.MinValue;

    private static void SetText(RegistryKey key, string name, string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            key.DeleteValue(name, throwOnMissingValue: false);
        }
        else
        {
            key.SetValue(name, value, RegistryValueKind.String);
        }
    }

    /// <summary>The subkeys of the key whose names are ids, opened for reading.</summary>
    private static IEnumerable<(Guid Id, RegistryKey Key)> Entries(string path)
    {
        using var parent = Registry.CurrentUser.OpenSubKey(path);
        if (parent is null)
        {
            yield break;
        }
        foreach (var name in parent.GetSubKeyNames())
        {
            if (Guid.TryParse(name, out var id) && parent.OpenSubKey(name) is { } key)
            {
                yield return (id, key);
            }
        }
    }

    /// <summary>The Vault profiles in the order they were added; an entry that cannot be read is left out.</summary>
    public static List<VaultProfile> VaultProfiles()
    {
        var profiles = new List<(VaultProfile Profile, DateTime Created)>();
        foreach (var (id, key) in Entries(VaultsPath))
        {
            using (key)
            {
                if (Text(key, "Name") is not { } name || Text(key, "Address") is not { } address
                    || AuthMethodNames.FromName(Text(key, "AuthMethod")) is not { } method)
                {
                    continue;
                }
                var configuration = new VaultConfiguration(
                    address, Text(key, "Namespace"), Text(key, "TotpMount") ?? "totp", method, Text(key, "AuthMount"),
                    Text(key, "Username"), Text(key, "RoleId"), Text(key, "OidcRole"),
                    key.GetValue("OidcPort") is int port ? port : VaultConfiguration.DefaultOidcPort);
                profiles.Add((new VaultProfile(id, name, configuration), Time(key, "Created")));
            }
        }
        return [.. profiles.OrderBy(p => p.Created).Select(p => p.Profile)];
    }

    /// <summary>Writes the profile's name and settings, keeping the time it was added.</summary>
    public static void SaveVaultProfile(VaultProfile profile)
    {
        using var key = Registry.CurrentUser.CreateSubKey($@"{VaultsPath}\{profile.Id}");
        var configuration = profile.Configuration;
        SetText(key, "Name", profile.Name);
        SetText(key, "Address", configuration.Address);
        SetText(key, "Namespace", configuration.Namespace);
        SetText(key, "TotpMount", configuration.TotpMount);
        SetText(key, "AuthMethod", configuration.AuthMethod.Name());
        SetText(key, "AuthMount", configuration.AuthMount);
        SetText(key, "Username", configuration.Username);
        SetText(key, "RoleId", configuration.RoleId);
        SetText(key, "OidcRole", configuration.OidcRole);
        key.SetValue("OidcPort", configuration.OidcPort, RegistryValueKind.DWord);
        if (key.GetValue("Created") is null)
        {
            SetText(key, "Created", DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        }
    }

    public static void DeleteVaultProfile(Guid id)
    {
        using var parent = Registry.CurrentUser.OpenSubKey(VaultsPath, writable: true);
        parent?.DeleteSubKeyTree(id.ToString(), throwOnMissingSubKey: false);
    }

    /// <summary>The accounts taken from Vault; an entry that cannot be read is left out.</summary>
    public static List<VaultRecord> VaultAccounts()
    {
        var records = new List<VaultRecord>();
        foreach (var (id, key) in Entries(VaultAccountsPath))
        {
            using (key)
            {
                if (Guid.TryParse(Text(key, "Profile"), out var profile) && Text(key, "Name") is { } name
                    && Text(key, "Parameters") is { } parameters && Text(key, "Key") is { } vaultKey)
                {
                    records.Add(new VaultRecord(id, profile, name, Text(key, "Issuer"), parameters, vaultKey,
                                                Time(key, "Added")));
                }
            }
        }
        return records;
    }

    public static void SaveVaultAccount(VaultRecord record)
    {
        using var key = Registry.CurrentUser.CreateSubKey($@"{VaultAccountsPath}\{record.Id}");
        SetText(key, "Profile", record.Profile.ToString());
        SetText(key, "Name", record.Name);
        SetText(key, "Issuer", record.Issuer);
        SetText(key, "Parameters", record.Parameters);
        SetText(key, "Key", record.Key);
        SetText(key, "Added", record.Added.ToString("O", CultureInfo.InvariantCulture));
    }

    public static void DeleteVaultAccount(Guid id)
    {
        using var parent = Registry.CurrentUser.OpenSubKey(VaultAccountsPath, writable: true);
        parent?.DeleteSubKeyTree(id.ToString(), throwOnMissingSubKey: false);
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
