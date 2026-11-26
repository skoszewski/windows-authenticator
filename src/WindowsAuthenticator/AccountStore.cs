using System.Security;
using System.Text;
using Microsoft.Win32;
using Totp;
using Vault;

namespace WindowsAuthenticator;

/// <summary>Why the account list was not changed.</summary>
internal sealed class StoreException(string message) : Exception(message);

/// <summary>The profile and the name of the key an account whose codes Vault makes is read from.</summary>
internal sealed record VaultKey(Guid Profile, string Key);

/// <summary>The profile and the reference of the KV secret field a secret account is read from.</summary>
internal sealed record VaultSecret(Guid Profile, SecretReference Reference);

/// <summary>A vault that needs the user's attention, and why.</summary>
internal sealed record VaultIssue(VaultSession Session, VaultProblem Problem);

/// <summary>A vault call that runs and is shown, with its vault.</summary>
internal sealed record VaultActivity(VaultSession Session, VaultOperation Operation);

/// <summary>A short message about what just worked, shown until the time given.</summary>
internal sealed record Notice(string Text, DateTimeOffset Until);

/// <summary>
/// The registered accounts, OTP and secret accounts kept in Credential Manager or taken from a vault, the Vault
/// sessions, and the secrets and Vault codes of the OTP accounts whose codes are shown. A secret account is never
/// shown; its secret is read when it is revealed or copied, and kept nowhere.
/// </summary>
internal sealed class AccountStore : IDisposable
{
    /// <summary>The secrets of the accounts whose code windows are open, and of no other.</summary>
    private readonly Dictionary<Guid, string> secrets = [];
    private readonly Dictionary<Guid, string> secretErrors = [];
    private readonly HashSet<Guid> openWindowIds = [];
    private readonly Dictionary<Guid, VaultKey> vaultKeys = [];
    private readonly Dictionary<Guid, VaultSecret> vaultSecrets = [];

    /// <summary>The secret accounts whose stored record holds no complete KV reference, with their profile.</summary>
    private readonly Dictionary<Guid, Guid> brokenSecrets = [];

    /// <summary>The codes fetched from Vault, with the period count each is valid for.</summary>
    private readonly Dictionary<Guid, (string Code, long Counter)> vaultCodes = [];

    /// <summary>The accounts being fetched, and the period count of the last failed fetch of each.</summary>
    private readonly HashSet<Guid> vaultFetching = [];
    private readonly Dictionary<Guid, long> vaultFailures = [];
    private List<VaultRecord> vaultRecords = [];
    private List<VaultSession> vaults = [];

    /// <summary>
    /// When the user last verified with Windows Hello; forgotten when the computer resumes and when the session
    /// switches, locked or unlocked included, so that the next secret asks again.
    /// </summary>
    private DateTimeOffset? lastAuthentication;

    public AccountStore()
    {
        Reload();
        SystemEvents.PowerModeChanged += ForgetOnResume;
        SystemEvents.SessionSwitch += ForgetOnSessionSwitch;
    }

    private void ForgetOnResume(object? sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode == PowerModes.Resume)
        {
            lastAuthentication = null;
        }
    }

    private void ForgetOnSessionSwitch(object? sender, SessionSwitchEventArgs e) => lastAuthentication = null;

    /// <summary>Detaches the handlers of the system's static events.</summary>
    public void Dispose()
    {
        SystemEvents.PowerModeChanged -= ForgetOnResume;
        SystemEvents.SessionSwitch -= ForgetOnSessionSwitch;
    }

    /// <summary>Raised when the accounts, the vaults, a vault's state or the load error change.</summary>
    public event EventHandler? Changed;

    /// <summary>Raised when a vault that worked fails.</summary>
    public event EventHandler<VaultIssue>? VaultProblemRaised;

    /// <summary>Raised when a shown vault call starts or ends, and when a notice is shown.</summary>
    public event EventHandler? ActivityChanged;

    /// <summary>The newest shown vault call that runs, or null.</summary>
    public VaultActivity? Activity =>
        vaults.Select(s => s.Activity is { } operation ? new VaultActivity(s, operation) : null).OfType<VaultActivity>()
              .MaxBy(a => a.Operation.Since);

    public bool IsBusy => Activity is not null;

    /// <summary>The notice of what was copied last, while it is shown, for 2 seconds.</summary>
    public Notice? CurrentNotice => notice is { } shown && shown.Until > DateTimeOffset.Now ? shown : null;

    private Notice? notice;

    /// <summary>Cancels the running calls of every vault.</summary>
    public void CancelActivity()
    {
        foreach (var session in vaults)
        {
            session.CancelOperations();
        }
    }

    /// <summary>Whether the vault the account is kept in has a shown call running.</summary>
    public bool IsVaultBusy(Account account) => VaultProfileOf(account) is { } profile && Vault(profile)?.Activity is not null;

    private void ShowNotice(string text)
    {
        notice = new Notice(text, DateTimeOffset.Now.AddSeconds(2));
        ActivityChanged?.Invoke(this, EventArgs.Empty);
    }

    public IReadOnlyList<Account> Accounts { get; private set; } = [];

    /// <summary>The sessions of the Vault profiles, in the order the profiles were added.</summary>
    public IReadOnlyList<VaultSession> Vaults => vaults;

    /// <summary>Why the accounts could not be listed; changes are refused while it is set.</summary>
    public string? LoadError { get; private set; }

    /// <summary>Whether the error is a failure of Credential Manager or of the registry.</summary>
    public static bool IsStorageFailure(Exception error) =>
        error is CredentialStoreException or UnauthorizedAccessException or SecurityException or IOException;

    /// <summary>
    /// Lists the Vault profiles and the accounts again, in the stored menu order; accounts missing from the
    /// order follow by the time they were written. The session of a profile that is still there is kept, with
    /// its token.
    /// </summary>
    public void Reload()
    {
        try
        {
            vaults = Settings.VaultProfiles().Select(profile =>
            {
                if (vaults.FirstOrDefault(s => s.Profile.Id == profile.Id) is { } kept)
                {
                    if (kept.Profile != profile)
                    {
                        kept.Update(profile);
                    }
                    return kept;
                }
                var session = new VaultSession(profile);
                session.Changed += (_, _) => Changed?.Invoke(this, EventArgs.Empty);
                session.ProblemRaised += (_, problem) => VaultProblemRaised?.Invoke(this, new VaultIssue(session, problem));
                session.ActivityChanged += (_, _) => ActivityChanged?.Invoke(this, EventArgs.Empty);
                return session;
            }).ToList();
            vaultRecords = Settings.VaultAccounts();
            vaultKeys.Clear();
            vaultSecrets.Clear();
            brokenSecrets.Clear();
            var listed = CredentialStore.Accounts();
            listed.AddRange(CredentialStore.SecretAccounts());
            foreach (var record in vaultRecords)
            {
                if (record.IsSecret)
                {
                    listed.Add(new ListedAccount(Account.Secret(record.Id, record.Name, record.SecretSettings), record.Added));
                    if (record.Reference is { } reference)
                    {
                        vaultSecrets[record.Id] = new VaultSecret(record.Profile, reference);
                    }
                    else
                    {
                        brokenSecrets[record.Id] = record.Profile;
                    }
                    continue;
                }
                try
                {
                    var account = Account.FromParameters(record.Id, record.Name, record.Issuer, record.Parameters);
                    listed.Add(new ListedAccount(account, record.Added));
                    vaultKeys[record.Id] = new VaultKey(record.Profile, record.Key);
                }
                catch (TotpException)
                {
                    // An entry whose parameters cannot be read is left out.
                }
            }
            var order = Settings.AccountOrder;
            Accounts = listed
                .OrderBy(entry => Array.IndexOf(order, entry.Account.Id.ToString()) is var index and >= 0 ? index : int.MaxValue)
                .ThenBy(entry => entry.Written)
                .Select(entry => entry.Account)
                .ToList();
            LoadError = null;
            SaveOrder();
        }
        catch (Exception error) when (IsStorageFailure(error))
        {
            Accounts = [];
            LoadError = error.Message;
        }
        UpdateSecrets();
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Writes the account's credential and appends it to the list, refusing a name already in it.</summary>
    public void Add(NewAccount account)
    {
        CheckCanAdd(account.Account.Name);
        CredentialStore.Add(account);
        Accounts = [.. Accounts, account.Account];
        SaveOrder();
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Adds an account whose codes the Vault profile makes from the key; nothing secret is kept for it.</summary>
    public void AddVaultAccount(Account account, string key, Guid profile)
    {
        CheckCanAdd(account.Name);
        Settings.SaveVaultAccount(new VaultRecord(account.Id, profile, account.Name, account.Issuer, account.Parameters,
                                                  key, DateTime.UtcNow));
        vaultKeys[account.Id] = new VaultKey(profile, key);
        Accounts = [.. Accounts, account];
        SaveOrder();
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Adds a secret account whose secret is kept in Credential Manager.</summary>
    public void AddSecret(string name, string value, SecretSettings settings)
    {
        name = name.Trim();
        if (name.Length == 0)
        {
            throw new StoreException("Give the account a name.");
        }
        if (value.Length == 0)
        {
            throw new StoreException("The secret is empty.");
        }
        if (Encoding.UTF8.GetByteCount(value) > CredentialStore.MaxBlobSize)
        {
            throw new StoreException($"The secret is longer than Credential Manager keeps, {CredentialStore.MaxBlobSize} bytes.");
        }
        CheckCanAdd(name);
        var account = Account.Secret(Guid.NewGuid(), name, settings);
        CredentialStore.AddSecret(account.Id, name, value, settings);
        Accounts = [.. Accounts, account];
        SaveOrder();
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Adds a secret account read from a field of a KV secret of the Vault profile; nothing secret is kept for it.</summary>
    public void AddVaultSecret(string name, SecretReference reference, Guid profile, SecretSettings settings)
    {
        name = name.Trim();
        if (name.Length == 0)
        {
            throw new StoreException("Give the account a name.");
        }
        CheckCanAdd(name);
        var account = Account.Secret(Guid.NewGuid(), name, settings);
        var record = new VaultRecord(account.Id, profile, name, null, "", "", DateTime.UtcNow, IsSecret: true, reference,
                                     settings);
        Settings.SaveVaultAccount(record);
        vaultRecords.Add(record);
        vaultSecrets[account.Id] = new VaultSecret(profile, reference);
        Accounts = [.. Accounts, account];
        SaveOrder();
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>The Vault key of an account whose codes Vault makes; null for an account of Credential Manager.</summary>
    public VaultKey? VaultKeyOf(Account account) => vaultKeys.GetValueOrDefault(account.Id);

    /// <summary>The KV field of a secret account kept in Vault; null for any other account.</summary>
    public VaultSecret? VaultSecretOf(Account account) => vaultSecrets.GetValueOrDefault(account.Id);

    /// <summary>The Vault profile an account is kept in: the one that makes its codes or holds its secret.</summary>
    public Guid? VaultProfileOf(Account account) =>
        vaultKeys.GetValueOrDefault(account.Id)?.Profile ?? vaultSecrets.GetValueOrDefault(account.Id)?.Profile
        ?? (brokenSecrets.TryGetValue(account.Id, out var profile) ? profile : null);

    /// <summary>The session of the Vault profile, or null when it is gone.</summary>
    public VaultSession? Vault(Guid profile) => vaults.FirstOrDefault(s => s.Profile.Id == profile);

    /// <summary>Where the account's secret is kept: Credential Manager, or the vault that makes its codes or holds it.</summary>
    public string Source(Account account) => VaultProfileOf(account) is { } profile
        ? $"Vault: {Vault(profile)?.Profile.Name ?? "removed"}"
        : "Credential Manager";

    /// <summary>Refuses an empty name, and one another profile has.</summary>
    private void CheckProfileName(string name, Guid? excluding)
    {
        if (name.Length == 0)
        {
            throw new StoreException("Give the vault a name.");
        }
        if (vaults.Any(s => s.Profile.Id != excluding && string.Equals(s.Profile.Name, name, StringComparison.CurrentCultureIgnoreCase)))
        {
            throw new StoreException($"A vault named {name} exists already.");
        }
    }

    /// <summary>Writes the profile and its credential, and makes its session. An OIDC profile keeps no credential.</summary>
    public VaultSession AddVaultProfile(string name, VaultConfiguration configuration, string credential)
    {
        EnsureLoaded();
        CheckProfileName(name, null);
        var profile = new VaultProfile(Guid.NewGuid(), name, configuration);
        if (configuration.AuthMethod != AuthMethod.Oidc && credential.Length > 0)
        {
            CredentialStore.SetVaultCredential(profile.Id, name, credential);
        }
        Settings.SaveVaultProfile(profile);
        Reload();
        return Vault(profile.Id) ?? throw new StoreException($"The vault {name} was not read back.");
    }

    /// <summary>
    /// Replaces the profile's name and settings, and its credential when one is given; an OIDC profile's
    /// credential is deleted. The token of an OIDC sign-in is kept, unless the user chose to delete it.
    /// </summary>
    public void UpdateVaultProfile(VaultSession session, string name, VaultConfiguration configuration, string? credential,
                                   bool deleteToken = false)
    {
        EnsureLoaded();
        CheckProfileName(name, session.Profile.Id);
        var profile = session.Profile with { Name = name, Configuration = configuration };
        if (configuration.AuthMethod == AuthMethod.Oidc)
        {
            CredentialStore.DeleteVaultCredential(profile.Id);
        }
        else if ((credential ?? (name != session.Profile.Name ? CredentialStore.VaultCredential(profile.Id) : null)) is { } stored)
        {
            CredentialStore.SetVaultCredential(profile.Id, name, stored);
        }
        Settings.SaveVaultProfile(profile);
        session.Update(profile);
        if (deleteToken)
        {
            session.SignOut();
        }
        VaultConnectionChanged();
        Reload();
    }

    /// <summary>The accounts kept in the Vault profile: those whose codes it makes and those whose secret it holds.</summary>
    public IReadOnlyList<Account> AccountsOf(Guid profile) => Accounts.Where(a => VaultProfileOf(a) == profile).ToList();

    /// <summary>Deletes the profile, its credential and its accounts; their keys stay in Vault.</summary>
    public void RemoveVaultProfile(VaultSession session)
    {
        EnsureLoaded();
        var id = session.Profile.Id;
        CredentialStore.DeleteVaultCredential(id);
        foreach (var record in vaultRecords.Where(r => r.Profile == id))
        {
            Settings.DeleteVaultAccount(record.Id);
        }
        Settings.DeleteVaultProfile(id);
        session.SignOut();
        Reload();
        openWindowIds.IntersectWith(Accounts.Select(a => a.Id));
    }

    /// <summary>Refuses a change while the accounts are not listed, and a name an account has already.</summary>
    public void CheckCanAdd(string name)
    {
        EnsureLoaded();
        if (Accounts.Any(a => string.Equals(a.Name, name, StringComparison.CurrentCultureIgnoreCase)))
        {
            throw new StoreException($"An account named {name} exists already.");
        }
    }

    /// <summary>
    /// Deletes the account's credential, and with it its secret; a Vault account's key or secret stays in Vault.
    /// </summary>
    public void Remove(Account account)
    {
        EnsureLoaded();
        if (vaultKeys.Remove(account.Id) || vaultSecrets.Remove(account.Id) || brokenSecrets.Remove(account.Id))
        {
            Settings.DeleteVaultAccount(account.Id);
            vaultRecords.RemoveAll(r => r.Id == account.Id);
            vaultCodes.Remove(account.Id);
        }
        else if (account.Kind == AccountKind.Secret)
        {
            CredentialStore.DeleteSecret(account.Id);
        }
        else
        {
            CredentialStore.Delete(account.Id);
        }
        Accounts = Accounts.Where(a => a.Id != account.Id).ToList();
        SaveOrder();
        openWindowIds.Remove(account.Id);
        UpdateSecrets();
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Records that the account's code window was opened or closed.</summary>
    public void SetWindowOpen(Guid id, bool open)
    {
        if (open)
        {
            openWindowIds.Add(id);
        }
        else
        {
            openWindowIds.Remove(id);
        }
        UpdateSecrets();
    }

    private static long Counter(Account account, DateTimeOffset time) => time.ToUnixTimeSeconds() / account.Period;

    /// <summary>
    /// The current code of a shown account, or null when its secret is not held or its code is not yet fetched
    /// from Vault.
    /// </summary>
    public string? Code(Account account, DateTimeOffset time)
    {
        if (vaultKeys.ContainsKey(account.Id))
        {
            return vaultCodes.TryGetValue(account.Id, out var fetched) && fetched.Counter == Counter(account, time)
                ? fetched.Code
                : null;
        }
        return secrets.TryGetValue(account.Id, out var secret) ? account.Code(secret, time) : null;
    }

    /// <summary>Why the secret of a shown account could not be read.</summary>
    public string? SecretError(Guid id) => secretErrors.GetValueOrDefault(id);

    /// <summary>
    /// Puts the account's current code in the clipboard: a code computed from the secret, which is read and not
    /// kept, or one fetched from Vault.
    /// </summary>
    public async Task CopyCodeAsync(Account account)
    {
        string code;
        if (vaultKeys.TryGetValue(account.Id, out var vaultKey))
        {
            var session = Vault(vaultKey.Profile) ?? throw new StoreException("The vault of this account was removed.");
            code = await session.AuthorizedAsync("Fetching the code", (client, cancel) => client.CodeAsync(vaultKey.Key, cancel));
        }
        else
        {
            var secret = secrets.TryGetValue(account.Id, out var held) ? held : CredentialStore.Secret(account.Id);
            code = account.Code(secret, DateTimeOffset.Now);
        }
        Clipboard.SetText(code);
        ShowNotice($"Copied the code of {account.Name}");
    }

    /// <summary>The text of a secret account, read from its credential or from its field in Vault; nothing is kept of it.</summary>
    private async Task<string> SecretValueAsync(Account account)
    {
        if (brokenSecrets.ContainsKey(account.Id))
        {
            throw new StoreException("The record of this account holds no reference to a secret.");
        }
        if (!vaultSecrets.TryGetValue(account.Id, out var vaultSecret))
        {
            return CredentialStore.SecretValue(account.Id);
        }
        var session = Vault(vaultSecret.Profile) ?? throw new StoreException("The vault of this account was removed.");
        return await session.AuthorizedAsync("Reading the secret",
                                             (client, cancel) => client.ReadSecretAsync(vaultSecret.Reference, cancel));
    }

    /// <summary>Sets how a secret account's secret is protected and shown.</summary>
    public void SetSecretSettings(Account account, SecretSettings settings)
    {
        EnsureLoaded();
        if (vaultRecords.FindIndex(r => r.Id == account.Id) is var index and >= 0)
        {
            var record = vaultRecords[index] with { SecretSettings = settings };
            Settings.SaveVaultAccount(record);
            vaultRecords[index] = record;
        }
        else
        {
            CredentialStore.SetSecretSettings(account.Id, account.Name, settings);
        }
        Accounts = [.. Accounts.Select(a => a.Id == account.Id ? a with { Settings = settings } : a)];
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Whether the user must verify to see or copy the secret: the account asks, and the user has not verified
    /// within the seconds it allows.
    /// </summary>
    public bool NeedsAuthentication(Account account) =>
        account.Settings.RequiresAuthentication
        && !(account.Settings.AuthenticationSeconds > 0 && lastAuthentication is { } last
             && DateTimeOffset.Now - last < TimeSpan.FromSeconds(account.Settings.AuthenticationSeconds));

    /// <summary>Asks for Windows Hello when the account needs it; false when the user cancels. A success is remembered.</summary>
    private async Task<bool> AuthenticatedAsync(Account account, IWin32Window owner, string message)
    {
        if (!NeedsAuthentication(account))
        {
            return true;
        }
        if (!await WindowsHello.VerifyAsync(owner, message))
        {
            return false;
        }
        lastAuthentication = DateTimeOffset.Now;
        return true;
    }

    /// <summary>
    /// The text of a secret account, for the user to look at, after the user verifies with Windows Hello when the
    /// account needs it; null when the user cancels. Nothing is kept of it.
    /// </summary>
    public async Task<string?> RevealSecretAsync(Account account, IWin32Window owner)
    {
        if (!await AuthenticatedAsync(account, owner, $"Show the secret {account.Name}"))
        {
            return null;
        }
        return await SecretValueAsync(account);
    }

    /// <summary>
    /// Puts the text of a secret account in the clipboard, after the user verifies with Windows Hello when the
    /// account needs it, kept out of the clipboard history, and empties the clipboard after 30 seconds, or when
    /// the app quits, if it still holds that copy; false when the user cancels, and nothing is copied. Without an
    /// owner the account must need no verification.
    /// </summary>
    public async Task<bool> CopySecretAsync(Account account, IWin32Window? owner)
    {
        if (NeedsAuthentication(account))
        {
            if (owner is null)
            {
                throw new InvalidOperationException("A secret that asks to authenticate is copied from a window.");
            }
            if (!await AuthenticatedAsync(account, owner, $"Copy the secret {account.Name}"))
            {
                return false;
            }
        }
        await CopySecretValueAsync(account, await SecretValueAsync(account));
        return true;
    }

    /// <summary>Puts a secret read for the account in the clipboard, and tells what was copied.</summary>
    private async Task CopySecretValueAsync(Account account, string value)
    {
        await ConcealedClipboard.CopyAsync(value);
        ShowNotice($"Copied the secret {account.Name}");
    }

    /// <summary>Fetches the codes of the shown Vault accounts that have none for the present period.</summary>
    public void Tick(DateTimeOffset now)
    {
        foreach (var account in Accounts.Where(a => openWindowIds.Contains(a.Id)))
        {
            if (!vaultKeys.TryGetValue(account.Id, out var vaultKey) || Vault(vaultKey.Profile) is not { } session)
            {
                continue;
            }
            var counter = Counter(account, now);
            if ((vaultCodes.TryGetValue(account.Id, out var fetched) && fetched.Counter == counter)
                || (vaultFailures.TryGetValue(account.Id, out var failed) && failed == counter)
                || !vaultFetching.Add(account.Id))
            {
                continue;
            }
            _ = FetchAsync(account.Id, session, vaultKey.Key, counter);
        }
    }

    /// <summary>Fetches one code; a failed fetch is not repeated within its period, and the session records why.</summary>
    private async Task FetchAsync(Guid id, VaultSession session, string key, long counter)
    {
        try
        {
            vaultCodes[id] = (await session.AuthorizedAsync("Fetching the code", (client, cancel) => client.CodeAsync(key, cancel),
                                                            quiet: true), counter);
        }
        catch (Exception)
        {
            vaultFailures[id] = counter;
        }
        finally
        {
            vaultFetching.Remove(id);
        }
    }

    /// <summary>The vaults whose last call failed.</summary>
    public IReadOnlyList<VaultIssue> Problems =>
        vaults.Where(s => s is { State: VaultState.Failed, Problem: not null }).Select(s => new VaultIssue(s, s.Problem!)).ToList();

    /// <summary>Why a Vault account has no code or secret: its vault failed, or is gone.</summary>
    public VaultProblem? Problem(Account account)
    {
        if (brokenSecrets.ContainsKey(account.Id))
        {
            return new VaultProblem(VaultProblemKind.Other, "The secret's reference is missing",
                                    "The stored record of this account holds no reference to a KV field.",
                                    "Remove the account and add it again.");
        }
        if (VaultProfileOf(account) is not { } profile)
        {
            return null;
        }
        if (Vault(profile) is not { } session)
        {
            return new VaultProblem(VaultProblemKind.Other, "The vault of this account was removed",
                                    "The account takes its codes from a vault that is not set up any more.",
                                    "Remove the account, or set the vault up again.");
        }
        return session.State == VaultState.Failed ? session.Problem : null;
    }

    /// <summary>Forgets the Vault codes and failures, so the shown accounts fetch again at once.</summary>
    public void VaultConnectionChanged()
    {
        vaultCodes.Clear();
        vaultFailures.Clear();
        Tick(DateTimeOffset.Now);
    }

    /// <summary>Signs in to the vault, so the shown codes are fetched.</summary>
    public async Task SignInAsync(VaultSession session)
    {
        try
        {
            await session.SignInAsync();
        }
        finally
        {
            VaultConnectionChanged();
        }
    }

    public void SignOut(VaultSession session)
    {
        session.SignOut();
        VaultConnectionChanged();
    }

    private void EnsureLoaded()
    {
        if (LoadError is not null)
        {
            throw new StoreException("The accounts were not read completely, so they are not changed.");
        }
    }

    /// <summary>
    /// Reads the secrets of the accounts newly shown and drops those of the accounts no longer shown, with their
    /// read errors.
    /// </summary>
    private void UpdateSecrets()
    {
        var shown = openWindowIds.Where(id => Accounts.Any(a => a.Id == id && a.Kind == AccountKind.Otp)).ToHashSet();
        foreach (var id in secrets.Keys.Where(id => !shown.Contains(id)).ToList())
        {
            secrets.Remove(id);
        }
        foreach (var id in secretErrors.Keys.Where(id => !shown.Contains(id)).ToList())
        {
            secretErrors.Remove(id);
        }
        foreach (var id in shown.Where(id => !vaultKeys.ContainsKey(id) && !secrets.ContainsKey(id) && !secretErrors.ContainsKey(id)))
        {
            try
            {
                secrets[id] = CredentialStore.Secret(id);
            }
            catch (CredentialStoreException error)
            {
                secretErrors[id] = error.Message;
            }
        }
        Tick(DateTimeOffset.Now);
    }

    private void SaveOrder() => Settings.AccountOrder = [.. Accounts.Select(a => a.Id.ToString())];
}
