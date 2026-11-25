using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Totp;
using static WindowsAuthenticator.NativeMethods;

namespace WindowsAuthenticator;

/// <summary>A Credential Manager call that did not succeed, with the system's description of its error.</summary>
internal sealed class CredentialStoreException(string operation, int error)
    : Exception($"Credential Manager could not {operation}: {new Win32Exception(error).Message}");

/// <summary>An account read from the attributes of its credential, with the time the credential was written.</summary>
internal sealed record ListedAccount(Account Account, DateTime Written);

/// <summary>
/// The accounts as generic credentials of Windows Credential Manager, one per account: the credential's
/// blob is the base32 secret and its other fields hold the rest of the account.
/// </summary>
internal static unsafe class CredentialStore
{
    public const string Service = "pl.waw.koszewscy.WindowsAuthenticator";
    public const string VaultService = Service + ".vault";
    private const string ParametersKeyword = "Koszewscy_Parameters";
    private const string VaultDescription = "Windows Authenticator Vault credential";

    private static string TargetName(Guid id) => $"{Service}:{id}";

    /// <summary>
    /// The accounts of all credentials, read from their fields alone; a credential whose fields cannot be
    /// read is left out. The secrets that come with the listing are cleared before the buffer is freed.
    /// </summary>
    public static List<ListedAccount> Accounts()
    {
        if (!CredEnumerate($"{Service}:*", 0, out var count, out var credentials))
        {
            var error = Marshal.GetLastPInvokeError();
            if (error == ErrorNotFound)
            {
                return [];
            }
            throw new CredentialStoreException("list the accounts", error);
        }
        try
        {
            var listed = new List<ListedAccount>();
            for (var i = 0; i < count; i++)
            {
                var credential = credentials[i];
                new Span<byte>(credential->CredentialBlob, (int)credential->CredentialBlobSize).Clear();
                if (Read(credential) is { } account)
                {
                    listed.Add(account);
                }
            }
            return listed;
        }
        finally
        {
            CredFree(credentials);
        }
    }

    /// <summary>The account held by the credential's fields, or null when they are not this app's.</summary>
    private static ListedAccount? Read(Credential* credential)
    {
        var target = new string(credential->TargetName);
        if (!target.StartsWith(Service + ":", StringComparison.Ordinal)
            || !Guid.TryParse(target.AsSpan(Service.Length + 1), out var id)
            || credential->UserName is null)
        {
            return null;
        }
        string? parameters = null;
        for (var i = 0; i < credential->AttributeCount; i++)
        {
            var attribute = credential->Attributes[i];
            if (new string(attribute.Keyword) == ParametersKeyword)
            {
                parameters = Encoding.Unicode.GetString(attribute.Value, (int)attribute.ValueSize);
            }
        }
        if (parameters is null)
        {
            return null;
        }
        var issuer = credential->Comment is null ? null : new string(credential->Comment);
        try
        {
            var account = Account.FromParameters(id, new string(credential->UserName),
                                                 string.IsNullOrEmpty(issuer) ? null : issuer, parameters);
            var written = DateTime.FromFileTimeUtc(
                ((long)credential->LastWritten.dwHighDateTime << 32) | (uint)credential->LastWritten.dwLowDateTime);
            return new ListedAccount(account, written);
        }
        catch (TotpException)
        {
            return null;
        }
    }

    /// <summary>The base32 secret of the account's credential.</summary>
    public static string Secret(Guid id) =>
        ReadBlob(TargetName(id), "read the secret") ?? throw new CredentialStoreException("read the secret", ErrorNotFound);

    /// <summary>The blob of the credential as UTF-8 text, or null when there is none; the blob is cleared once copied.</summary>
    private static string? ReadBlob(string target, string operation)
    {
        if (!CredRead(target, CredTypeGeneric, 0, out var credential))
        {
            var error = Marshal.GetLastPInvokeError();
            if (error == ErrorNotFound)
            {
                return null;
            }
            throw new CredentialStoreException(operation, error);
        }
        try
        {
            var blob = new Span<byte>(credential->CredentialBlob, (int)credential->CredentialBlobSize);
            var text = Encoding.UTF8.GetString(blob);
            blob.Clear();
            return text;
        }
        finally
        {
            CredFree(credential);
        }
    }

    /// <summary>Writes the account's credential.</summary>
    public static void Add(NewAccount account) =>
        Write(TargetName(account.Account.Id), account.Account.Name, account.Account.Issuer, account.Secret,
              account.Account.Parameters, "add the account");

    /// <summary>
    /// Writes a generic credential persisted on this computer, replacing one of the same target, with the
    /// parameters as its one attribute when given.
    /// </summary>
    private static void Write(string target, string userName, string? comment, string blobText, string? parameters,
                              string operation)
    {
        var blobBytes = Encoding.UTF8.GetBytes(blobText);
        var parameterBytes = parameters is null ? Array.Empty<byte>() : Encoding.Unicode.GetBytes(parameters);
        try
        {
            fixed (char* targetName = target)
            fixed (char* user = userName)
            fixed (char* commentText = comment)
            fixed (char* keyword = ParametersKeyword)
            fixed (byte* value = parameterBytes)
            fixed (byte* blob = blobBytes)
            {
                var attribute = new CredentialAttribute
                {
                    Keyword = keyword,
                    ValueSize = (uint)parameterBytes.Length,
                    Value = value,
                };
                var credential = new Credential
                {
                    Type = CredTypeGeneric,
                    TargetName = targetName,
                    Comment = commentText,
                    CredentialBlobSize = (uint)blobBytes.Length,
                    CredentialBlob = blob,
                    Persist = CredPersistLocalMachine,
                    AttributeCount = parameters is null ? 0u : 1u,
                    Attributes = parameters is null ? null : &attribute,
                    UserName = user,
                };
                if (!CredWrite(&credential, 0))
                {
                    throw new CredentialStoreException(operation, Marshal.GetLastPInvokeError());
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(blobBytes);
        }
    }

    /// <summary>Deletes the account's credential; a credential already gone is no failure.</summary>
    public static void Delete(Guid id) => DeleteTarget(TargetName(id), "remove the account");

    private static void DeleteTarget(string target, string operation)
    {
        if (!CredDelete(target, CredTypeGeneric, 0))
        {
            var error = Marshal.GetLastPInvokeError();
            if (error != ErrorNotFound)
            {
                throw new CredentialStoreException(operation, error);
            }
        }
    }

    /// <summary>The Vault credentials are the credentials of a target prefix of their own.</summary>
    private static string VaultTargetName(Guid profile) => $"{VaultService}:{profile}";

    /// <summary>The token, password or SecretID of the Vault profile; null when none is stored.</summary>
    public static string? VaultCredential(Guid profile)
    {
        var credential = ReadBlob(VaultTargetName(profile), "read the Vault credential");
        return string.IsNullOrEmpty(credential) ? null : credential;
    }

    /// <summary>Writes the credential of the Vault profile, named after the profile.</summary>
    public static void SetVaultCredential(Guid profile, string profileName, string credential) =>
        Write(VaultTargetName(profile), profileName, VaultDescription, credential, null, "store the Vault credential");

    /// <summary>Deletes the credential of the Vault profile; one already gone is no failure.</summary>
    public static void DeleteVaultCredential(Guid profile) =>
        DeleteTarget(VaultTargetName(profile), "remove the Vault credential");
}
