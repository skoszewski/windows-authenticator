using Totp;

namespace WindowsAuthenticator;

/// <summary>Why the account list was not changed.</summary>
internal sealed class StoreException(string message) : Exception(message);

/// <summary>The registered accounts and the secrets of those whose codes are shown.</summary>
internal sealed class AccountStore
{
    /// <summary>The secrets of the accounts whose code windows are open, and of no other.</summary>
    private readonly Dictionary<Guid, string> secrets = [];
    private readonly Dictionary<Guid, string> secretErrors = [];
    private readonly HashSet<Guid> openWindowIds = [];

    public AccountStore()
    {
        Reload();
    }

    /// <summary>Raised when the list of accounts or the load error changes.</summary>
    public event EventHandler? AccountsChanged;

    public IReadOnlyList<Account> Accounts { get; private set; } = [];

    /// <summary>Why Credential Manager could not be listed; changes are refused while it is set.</summary>
    public string? LoadError { get; private set; }

    /// <summary>
    /// Lists the accounts from Credential Manager again, in the stored menu order; accounts missing from
    /// the order follow by the time their credentials were written.
    /// </summary>
    public void Reload()
    {
        try
        {
            var order = Settings.AccountOrder;
            Accounts = CredentialStore.Accounts()
                .OrderBy(listed => Array.IndexOf(order, listed.Account.Id.ToString()) is var index and >= 0 ? index : int.MaxValue)
                .ThenBy(listed => listed.Written)
                .Select(listed => listed.Account)
                .ToList();
            LoadError = null;
            SaveOrder();
        }
        catch (CredentialStoreException error)
        {
            Accounts = [];
            LoadError = error.Message;
        }
        UpdateSecrets();
        AccountsChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Writes the account's credential and appends it to the list, refusing a name already in it.</summary>
    public void Add(NewAccount account)
    {
        EnsureLoaded();
        if (Accounts.Any(a => string.Equals(a.Name, account.Account.Name, StringComparison.CurrentCultureIgnoreCase)))
        {
            throw new StoreException($"An account named {account.Account.Name} exists already.");
        }
        CredentialStore.Add(account);
        Accounts = [.. Accounts, account.Account];
        SaveOrder();
        AccountsChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Deletes the account's credential, and with it its secret.</summary>
    public void Remove(Account account)
    {
        EnsureLoaded();
        CredentialStore.Delete(account.Id);
        Accounts = Accounts.Where(a => a.Id != account.Id).ToList();
        SaveOrder();
        openWindowIds.Remove(account.Id);
        UpdateSecrets();
        AccountsChanged?.Invoke(this, EventArgs.Empty);
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

    /// <summary>The current code of a shown account, or null when its secret is not held.</summary>
    public string? Code(Account account, DateTimeOffset time) =>
        secrets.TryGetValue(account.Id, out var secret) ? account.Code(secret, time) : null;

    /// <summary>Why the secret of a shown account could not be read.</summary>
    public string? SecretError(Guid id) => secretErrors.GetValueOrDefault(id);

    /// <summary>Reads the account's secret and puts its current code in the clipboard, keeping no secret.</summary>
    public void CopyCode(Account account)
    {
        var secret = secrets.TryGetValue(account.Id, out var held) ? held : CredentialStore.Secret(account.Id);
        Clipboard.SetText(account.Code(secret, DateTimeOffset.Now));
    }

    private void EnsureLoaded()
    {
        if (LoadError is not null)
        {
            throw new StoreException("The accounts were not read from Credential Manager, so they are not changed.");
        }
    }

    /// <summary>
    /// Reads the secrets of the accounts newly shown and drops those of the accounts no longer shown, with
    /// their read errors.
    /// </summary>
    private void UpdateSecrets()
    {
        var shown = openWindowIds.Where(id => Accounts.Any(a => a.Id == id)).ToHashSet();
        foreach (var id in secrets.Keys.Where(id => !shown.Contains(id)).ToList())
        {
            secrets.Remove(id);
        }
        foreach (var id in secretErrors.Keys.Where(id => !shown.Contains(id)).ToList())
        {
            secretErrors.Remove(id);
        }
        foreach (var id in shown.Where(id => !secrets.ContainsKey(id) && !secretErrors.ContainsKey(id)))
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
    }

    private void SaveOrder() => Settings.AccountOrder = [.. Accounts.Select(a => a.Id.ToString())];
}
