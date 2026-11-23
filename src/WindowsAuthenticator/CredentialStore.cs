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
    private const string ParametersKeyword = "Koszewscy_Parameters";

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
    public static string Secret(Guid id)
    {
        if (!CredRead(TargetName(id), CredTypeGeneric, 0, out var credential))
        {
            throw new CredentialStoreException("read the secret", Marshal.GetLastPInvokeError());
        }
        try
        {
            var blob = new Span<byte>(credential->CredentialBlob, (int)credential->CredentialBlobSize);
            var secret = Encoding.UTF8.GetString(blob);
            blob.Clear();
            return secret;
        }
        finally
        {
            CredFree(credential);
        }
    }

    /// <summary>Writes the account's credential.</summary>
    public static void Add(NewAccount account)
    {
        var secret = Encoding.UTF8.GetBytes(account.Secret);
        var parameters = Encoding.Unicode.GetBytes(account.Account.Parameters);
        try
        {
            fixed (char* target = TargetName(account.Account.Id))
            fixed (char* userName = account.Account.Name)
            fixed (char* comment = account.Account.Issuer)
            fixed (char* keyword = ParametersKeyword)
            fixed (byte* value = parameters)
            fixed (byte* blob = secret)
            {
                var attribute = new CredentialAttribute
                {
                    Keyword = keyword,
                    ValueSize = (uint)parameters.Length,
                    Value = value,
                };
                var credential = new Credential
                {
                    Type = CredTypeGeneric,
                    TargetName = target,
                    Comment = comment,
                    CredentialBlobSize = (uint)secret.Length,
                    CredentialBlob = blob,
                    Persist = CredPersistLocalMachine,
                    AttributeCount = 1,
                    Attributes = &attribute,
                    UserName = userName,
                };
                if (!CredWrite(&credential, 0))
                {
                    throw new CredentialStoreException("add the account", Marshal.GetLastPInvokeError());
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>Deletes the account's credential; a credential already gone is no failure.</summary>
    public static void Delete(Guid id)
    {
        if (!CredDelete(TargetName(id), CredTypeGeneric, 0))
        {
            var error = Marshal.GetLastPInvokeError();
            if (error != ErrorNotFound)
            {
                throw new CredentialStoreException("remove the account", error);
            }
        }
    }
}
