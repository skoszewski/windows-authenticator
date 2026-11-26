using System.Web;
using Vault;

namespace WindowsAuthenticator;

/// <summary>Why the session cannot authenticate.</summary>
internal sealed class SessionException(string message, VaultProblem problem) : Exception(message), IVaultProblemSource
{
    public VaultProblem Problem { get; } = problem;

    public static SessionException MissingCredential() =>
        new("No Vault credential is stored.",
            new VaultProblem(VaultProblemKind.Credential, "No credential is stored",
                             "Credential Manager holds no token, password or SecretID for this vault.",
                             "Store a credential for the vault."));

    public static SessionException MissingSetting(string name) =>
        new($"The Vault setting {name} is empty.",
            new VaultProblem(VaultProblemKind.Address, "A setting is empty", $"{name} is empty.",
                             "Give the vault a value for it."));

    public static SessionException InvalidSetting(string name) =>
        new($"The Vault setting {name} is not valid.",
            new VaultProblem(VaultProblemKind.Address, "A setting is not valid", $"{name} is not valid.",
                             "Give the vault a valid value for it."));

    public static SessionException NoWebView2Runtime() =>
        new("The WebView2 Runtime is not installed.",
            new VaultProblem(VaultProblemKind.Other, "The WebView2 Runtime is not installed",
                             "The OIDC sign-in window needs the Microsoft Edge WebView2 Runtime, which this computer lacks.",
                             "Install the Microsoft Edge WebView2 Runtime, and sign in again."));

    /// <summary>A Credential Manager failure while the credential was read.</summary>
    public static SessionException CredentialStore(CredentialStoreException error) =>
        new(error.Message,
            new VaultProblem(VaultProblemKind.Credential, "Credential Manager refused", error.Message,
                             "Store the credential again."));
}

/// <summary>The authentication state of a vault.</summary>
internal enum VaultState
{
    SignedOut,
    SigningIn,
    SignedIn,
    Failed,
}

/// <summary>
/// A Vault connection: a named profile, kept in the registry with its credential in Credential Manager, and the
/// current token, which for OIDC is also kept in Credential Manager. It runs on the UI thread.
/// </summary>
internal sealed class VaultSession
{
    private bool worked;
    private VaultToken? token;
    private Task? signIn;
    private OidcSignInWindow? signInWindow;

    /// <summary>The session of the profile; an OIDC profile takes up the token kept for it, unless it has ended.</summary>
    public VaultSession(VaultProfile profile)
    {
        Profile = profile;
        if (profile.Configuration.AuthMethod != AuthMethod.Oidc)
        {
            return;
        }
        VaultToken? kept;
        try
        {
            kept = CredentialStore.VaultToken(profile.Id);
        }
        catch (CredentialStoreException error)
        {
            ProblemLog.Write(profile.Name, SessionException.CredentialStore(error).Problem);
            return;
        }
        if (kept is { Expires: { } expires } && expires - DateTimeOffset.Now <= TimeSpan.FromSeconds(5))
        {
            Keep(null);
        }
        else if (kept is not null)
        {
            token = kept;
            State = VaultState.SignedIn;
        }
    }

    public VaultProfile Profile { get; private set; }

    /// <summary>The current token, or null when the vault holds none.</summary>
    public VaultToken? Token => token;

    public VaultState State { get; private set; } = VaultState.SignedOut;

    /// <summary>The problem of the last call, while the state is <see cref="VaultState.Failed"/>.</summary>
    public VaultProblem? Problem { get; private set; }

    /// <summary>When the last call to the vault ended, in success or in failure.</summary>
    public DateTimeOffset? LastAttempt { get; private set; }

    /// <summary>Raised when the state, the problem or the time of the last attempt changes.</summary>
    public event EventHandler? Changed;

    /// <summary>Raised once when a vault that worked fails, until it works again.</summary>
    public event EventHandler<VaultProblem>? ProblemRaised;

    private VaultConfiguration Configuration => Profile.Configuration;

    /// <summary>Takes the new name and settings of the profile, and signs out.</summary>
    public void Update(VaultProfile updated)
    {
        Profile = updated;
        SignOut();
    }

    /// <summary>Drops the token, and the one kept in Credential Manager, and closes a sign-in window that is open.</summary>
    public void SignOut()
    {
        signInWindow?.Cancel();
        Keep(null);
        worked = false;
        SetState(VaultState.SignedOut);
    }

    /// <summary>
    /// Makes the token the current one, or none; an OIDC token is kept in Credential Manager, and a token dropped
    /// is forgotten there. A Credential Manager that refuses is logged, and the token still works.
    /// </summary>
    private void Keep(VaultToken? value)
    {
        token = value;
        if (value is not null && Configuration.AuthMethod != AuthMethod.Oidc)
        {
            return;
        }
        try
        {
            if (value is null)
            {
                CredentialStore.DeleteVaultToken(Profile.Id);
            }
            else
            {
                CredentialStore.SetVaultToken(Profile.Id, Profile.Name, value);
            }
        }
        catch (CredentialStoreException error)
        {
            ProblemLog.Write(Profile.Name, SessionException.CredentialStore(error).Problem);
        }
    }

    private void SetState(VaultState state, VaultProblem? problem = null)
    {
        State = state;
        Problem = problem;
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Records a failed call: the state shows its problem, and a vault that worked is reported once.</summary>
    private void Report(Exception error)
    {
        if (error is OperationCanceledException)
        {
            return;
        }
        var problem = VaultProblem.From(error, Configuration.AuthMethod);
        LastAttempt = DateTimeOffset.Now;
        if (State == VaultState.Failed && Problem == problem)
        {
            Changed?.Invoke(this, EventArgs.Empty);
            return;
        }
        SetState(VaultState.Failed, problem);
        ProblemLog.Write(Profile.Name, problem);
        if (worked)
        {
            worked = false;
            ProblemRaised?.Invoke(this, problem);
        }
    }

    /// <summary>Records a call that worked; a failed state returns to signed in.</summary>
    private void Succeeded()
    {
        worked = true;
        LastAttempt = DateTimeOffset.Now;
        if (State != VaultState.SignedIn)
        {
            SetState(VaultState.SignedIn);
        }
    }

    /// <summary>Signs in with the configured method; calls made while a sign-in runs wait for it.</summary>
    public async Task SignInAsync()
    {
        if (signIn is { } running)
        {
            await running;
            return;
        }
        var task = PerformSignInAsync();
        signIn = task;
        try
        {
            await task;
        }
        finally
        {
            if (signIn == task)
            {
                signIn = null;
            }
        }
    }

    private async Task PerformSignInAsync()
    {
        SetState(VaultState.SigningIn);
        try
        {
            Keep(await LoginAsync());
            Succeeded();
        }
        catch (OperationCanceledException)
        {
            SetState(VaultState.SignedOut);
            throw;
        }
        catch (Exception error)
        {
            Report(error);
            throw;
        }
    }

    private async Task<VaultToken> LoginAsync()
    {
        string Credential()
        {
            try
            {
                return CredentialStore.VaultCredential(Profile.Id) ?? throw SessionException.MissingCredential();
            }
            catch (CredentialStoreException error)
            {
                throw SessionException.CredentialStore(error);
            }
        }

        static string Setting(string? value, string name) =>
            string.IsNullOrEmpty(value) ? throw SessionException.MissingSetting(name) : value;

        var client = new VaultClient(Configuration);
        return Configuration.AuthMethod switch
        {
            AuthMethod.Token => await new VaultClient(Configuration, Credential()).LookupSelfAsync(),
            AuthMethod.Userpass => await client.LoginUserpassAsync(Setting(Configuration.Username, "Username"), Credential()),
            AuthMethod.Approle => await client.LoginAppRoleAsync(Setting(Configuration.RoleId, "RoleID"), Credential()),
            _ => await OidcLoginAsync(client),
        };
    }

    /// <summary>Signs in in a window of the app, which takes the redirect of the identity provider itself.</summary>
    private async Task<VaultToken> OidcLoginAsync(VaultClient client)
    {
        var clientNonce = Guid.NewGuid().ToString("D");
        var url = await client.OidcAuthUrlAsync(Configuration.OidcRole, Configuration.OidcRedirectUri, clientNonce);
        var query = HttpUtility.ParseQueryString(url.Query);
        if (query["state"] is not { } state || query["nonce"] is not { } nonce)
        {
            throw VaultException.Oidc("Vault's authorisation URL holds no state or nonce.");
        }

        var window = new OidcSignInWindow();
        signInWindow = window;
        OidcCallback callback;
        try
        {
            callback = await window.RunAsync(url, new Uri(Configuration.OidcRedirectUri), $"Sign in to {Profile.Name}");
        }
        finally
        {
            signInWindow = null;
        }
        if (callback.Error is { } error)
        {
            throw VaultException.Oidc(error);
        }
        if (callback.Code is not { } code || callback.State != state)
        {
            throw VaultException.Oidc("The identity provider's answer does not belong to this sign-in.");
        }
        return await client.OidcCallbackAsync(state, nonce, code, clientNonce);
    }

    /// <summary>
    /// The token to use: the current one, renewed when half of its lease is gone, or a new sign-in. An OIDC
    /// sign-in is never started here.
    /// </summary>
    private async Task<VaultToken> ValidTokenAsync()
    {
        if (token is { Expires: { } expires } current)
        {
            var left = expires - DateTimeOffset.Now;
            if (left <= TimeSpan.FromSeconds(5))
            {
                Keep(null);
            }
            else if (current is { Renewable: true, Lease: { } lease } && left < lease / 2)
            {
                try
                {
                    Keep(await new VaultClient(Configuration, current.Token).RenewSelfAsync());
                    SetState(VaultState.SignedIn);
                }
                catch (VaultException)
                {
                    // The current token stays in use until it ends.
                }
            }
        }
        if (token is { } valid)
        {
            return valid;
        }
        if (Configuration.AuthMethod == AuthMethod.Oidc)
        {
            SetState(VaultState.SignedOut);
            throw VaultException.NotSignedIn();
        }
        await SignInAsync();
        return token ?? throw VaultException.NotSignedIn();
    }

    /// <summary>Runs a call with a valid token, and records its outcome in the state.</summary>
    public async Task<T> AuthorizedAsync<T>(Func<VaultClient, Task<T>> call)
    {
        try
        {
            var result = await PerformAsync(call);
            Succeeded();
            return result;
        }
        catch (Exception error)
        {
            Report(error);
            throw;
        }
    }

    /// <summary>
    /// A token Vault refuses is replaced once by a new sign-in, unless the token itself is the credential or the
    /// sign-in is OIDC.
    /// </summary>
    private async Task<T> PerformAsync<T>(Func<VaultClient, Task<T>> call)
    {
        var first = await ValidTokenAsync();
        try
        {
            return await call(new VaultClient(Configuration, first.Token));
        }
        catch (VaultException error) when (error.IsDenied && Configuration.AuthMethod != AuthMethod.Token)
        {
            Keep(null);
            if (Configuration.AuthMethod == AuthMethod.Oidc)
            {
                SetState(VaultState.SignedOut);
                throw VaultException.NotSignedIn();
            }
            await SignInAsync();
            var second = token ?? throw VaultException.NotSignedIn();
            return await call(new VaultClient(Configuration, second.Token));
        }
    }
}
