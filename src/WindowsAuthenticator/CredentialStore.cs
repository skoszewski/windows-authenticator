using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Totp;
using Vault;
using static WindowsAuthenticator.NativeMethods;

namespace WindowsAuthenticator;

/// <summary>A Credential Manager call that did not succeed, with the system's description of its error.</summary>
internal sealed class CredentialStoreException(string operation, int error)
    : Exception($"Credential Manager could not {operation}: {new Win32Exception(error).Message}");

/// <summary>An account read from the attributes of its credential, with the time the credential was written.</summary>
internal sealed record ListedAccount(Account Account, DateTime Written);

/// <summary>
/// The accounts as generic credentials of Windows Credential Manager, one per account: the credential's
/// blob is the base32 secret, or the secret of a secret account, and its other fields hold the rest of the
/// account; and the credentials and the kept OIDC tokens of the Vault profiles.
/// </summary>
internal static unsafe class CredentialStore
{
    public const string Service = "pl.waw.koszewscy.WindowsAuthenticator";
    public const string VaultService = Service + ".vault";
    public const string SecretService = Service + ".secret";

    /// <summary>The longest blob a credential holds, CRED_MAX_CREDENTIAL_BLOB_SIZE, in bytes.</summary>
    public const int MaxBlobSize = 5 * 512;

    private const string ParametersKeyword = "Koszewscy_Parameters";

    /// <summary>The attribute of a secret account that says whether it asks to authenticate, 1 or 0; absent means 1.</summary>
    private const string AuthenticateKeyword = "Koszewscy_Authenticate";
    private const string VaultDescription = "Windows Authenticator Vault credential";
    private const string VaultTokenDescription = "Windows Authenticator Vault token";
    private const string SecretDescription = "Windows Authenticator secret";

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
              (ParametersKeyword, account.Account.Parameters), "add the account");

    /// <summary>
    /// Writes a generic credential persisted on this computer, replacing one of the same target, with one attribute
    /// when given.
    /// </summary>
    private static void Write(string target, string userName, string? comment, string blobText,
                              (string Keyword, string Value)? attribute, string operation)
    {
        var blobBytes = Encoding.UTF8.GetBytes(blobText);
        var parameterBytes = attribute is { } named ? Encoding.Unicode.GetBytes(named.Value) : [];
        try
        {
            fixed (char* targetName = target)
            fixed (char* user = userName)
            fixed (char* commentText = comment)
            fixed (char* keyword = attribute?.Keyword)
            fixed (byte* value = parameterBytes)
            fixed (byte* blob = blobBytes)
            {
                var fields = new CredentialAttribute
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
                    AttributeCount = attribute is null ? 0u : 1u,
                    Attributes = attribute is null ? null : &fields,
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

    /// <summary>Deletes the credential of the Vault profile and its kept token; ones already gone are no failure.</summary>
    public static void DeleteVaultCredential(Guid profile)
    {
        DeleteTarget(VaultTargetName(profile), "remove the Vault credential");
        DeleteVaultToken(profile);
    }

    /// <summary>
    /// The tokens of OIDC sign-ins are the credentials of a target prefix of their own, one per profile, so a
    /// profile's credential is never taken for a token.
    /// </summary>
    private static string VaultTokenTargetName(Guid profile) => $"{VaultService}.token:{profile}";

    /// <summary>The token kept for the profile; null when none is kept or the kept one cannot be read.</summary>
    public static VaultToken? VaultToken(Guid profile)
    {
        var json = ReadBlob(VaultTokenTargetName(profile), "read the Vault token");
        if (json is null)
        {
            return null;
        }
        try
        {
            return JsonSerializer.Deserialize<VaultToken>(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Keeps the token as the profile's token credential, replacing the one kept.</summary>
    public static void SetVaultToken(Guid profile, string profileName, VaultToken token) =>
        Write(VaultTokenTargetName(profile), profileName, VaultTokenDescription, JsonSerializer.Serialize(token), null,
              "keep the Vault token");

    /// <summary>Deletes the profile's token credential; one already gone is no failure.</summary>
    public static void DeleteVaultToken(Guid profile) => DeleteTarget(VaultTokenTargetName(profile), "forget the Vault token");

    /// <summary>
    /// The secret accounts are the credentials of a target prefix of their own, so a build that knows only OTP
    /// accounts does not read a secret as a TOTP secret.
    /// </summary>
    private static string SecretTargetName(Guid id) => $"{SecretService}:{id}";

    /// <summary>
    /// The secret accounts of all credentials, read from their target and user name alone; the secrets that come
    /// with the listing are cleared before the buffer is freed.
    /// </summary>
    public static List<ListedAccount> SecretAccounts()
    {
        if (!CredEnumerate($"{SecretService}:*", 0, out var count, out var credentials))
        {
            var error = Marshal.GetLastPInvokeError();
            if (error == ErrorNotFound)
            {
                return [];
            }
            throw new CredentialStoreException("list the secrets", error);
        }
        try
        {
            var listed = new List<ListedAccount>();
            for (var i = 0; i < count; i++)
            {
                var credential = credentials[i];
                new Span<byte>(credential->CredentialBlob, (int)credential->CredentialBlobSize).Clear();
                var target = new string(credential->TargetName);
                if (target.StartsWith(SecretService + ":", StringComparison.Ordinal)
                    && Guid.TryParse(target.AsSpan(SecretService.Length + 1), out var id)
                    && credential->UserName is not null)
                {
                    var written = DateTime.FromFileTimeUtc(
                        ((long)credential->LastWritten.dwHighDateTime << 32) | (uint)credential->LastWritten.dwLowDateTime);
                    var asks = true;
                    for (var j = 0; j < credential->AttributeCount; j++)
                    {
                        var attribute = credential->Attributes[j];
                        if (new string(attribute.Keyword) == AuthenticateKeyword)
                        {
                            asks = Encoding.Unicode.GetString(attribute.Value, (int)attribute.ValueSize) != "0";
                        }
                    }
                    listed.Add(new ListedAccount(Account.Secret(id, new string(credential->UserName), asks), written));
                }
            }
            return listed;
        }
        finally
        {
            CredFree(credentials);
        }
    }

    /// <summary>The text of the secret account's credential.</summary>
    public static string SecretValue(Guid id) =>
        ReadBlob(SecretTargetName(id), "read the secret") ?? throw new CredentialStoreException("read the secret", ErrorNotFound);

    /// <summary>Writes the secret account's credential, named after the account, with whether it asks to authenticate.</summary>
    public static void AddSecret(Guid id, string name, string value, bool requiresAuthentication) =>
        Write(SecretTargetName(id), name, SecretDescription, value, (AuthenticateKeyword, requiresAuthentication ? "1" : "0"),
              "add the secret");

    /// <summary>Writes the secret account's credential again with its secret, setting whether it asks to authenticate.</summary>
    public static void SetSecretAuthentication(Guid id, string name, bool required) =>
        Write(SecretTargetName(id), name, SecretDescription, SecretValue(id), (AuthenticateKeyword, required ? "1" : "0"),
              "change the secret");

    /// <summary>Deletes the secret account's credential; one already gone is no failure.</summary>
    public static void DeleteSecret(Guid id) => DeleteTarget(SecretTargetName(id), "remove the secret");
}
