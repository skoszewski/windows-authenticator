using System.Globalization;
using Vault;

namespace WindowsAuthenticator;

/// <summary>
/// The page of a vault: its settings, its authentication and Test Connection, with Save and Revert; the session
/// is null for a vault not yet made.
/// </summary>
internal sealed class VaultEditor : UserControl
{
    private static readonly (AuthMethod Method, string Title)[] Methods =
    [
        (AuthMethod.Token, "Token"),
        (AuthMethod.Userpass, "Username and password"),
        (AuthMethod.Approle, "AppRole"),
        (AuthMethod.Oidc, "OIDC"),
    ];

    private readonly AccountStore store;
    private readonly TableLayoutPanel layout = new()
    {
        AutoSize = true,
        AutoSizeMode = AutoSizeMode.GrowAndShrink,
        ColumnCount = 2,
        Dock = DockStyle.Top,
        Padding = new Padding(8),
    };
    private readonly TextBox name = new() { PlaceholderText = "For example Work or Lab" };
    private readonly TextBox address = new() { PlaceholderText = "https://vault.example.com:8200" };
    private readonly TextBox vaultNamespace = new() { PlaceholderText = "Optional, Vault Enterprise" };
    private readonly TextBox totpMount = new();
    private readonly ComboBox method = new() { DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly TextBox authMount = new();
    private readonly TextBox username = new();
    private readonly TextBox roleId = new();
    private readonly TextBox oidcRole = new() { PlaceholderText = "Empty for the default role" };
    private readonly TextBox oidcPort = new();
    private readonly TextBox credential = new() { UseSystemPasswordChar = true };
    private readonly Label credentialLabel = new() { AutoSize = true, Anchor = AnchorStyles.Left };
    private readonly Label status = new() { AutoSize = true, Anchor = AnchorStyles.Left };
    private readonly Label problem = new() { AutoSize = true };
    private readonly Label lastAttempt = new() { AutoSize = true };
    private readonly Button copyDetails = new() { Text = "Copy Details", AutoSize = true };
    private readonly Button signIn = new() { Text = "Sign In", AutoSize = true };
    private readonly Button signOut = new() { Text = "Sign Out", AutoSize = true };
    private readonly Button test = new() { Text = "Test Connection", AutoSize = true };
    private readonly Button setup = new() { Text = "Vault Setup...", AutoSize = true };
    private readonly TextBox checks = new()
    {
        Multiline = true,
        ReadOnly = true,
        ScrollBars = ScrollBars.Both,
        WordWrap = false,
        Dock = DockStyle.Fill,
        Visible = false,
    };
    private readonly Label message = new() { AutoSize = true, ForeColor = Color.Firebrick };
    private readonly Dictionary<Control, Label> labels = [];
    private readonly Font bold;
    private readonly Font fixedWidth = new("Consolas", 9f);

    public VaultEditor(AccountStore store, VaultSession? session)
    {
        this.store = store;
        bold = new Font(Font, FontStyle.Bold);
        checks.Font = fixedWidth;
        checks.Height = LogicalToDeviceUnits(170);
        Session = session;
        AutoScroll = true;
        Dock = DockStyle.Fill;
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        Heading("Vault");
        Row("Name", name);
        Row("Vault address", address);
        Row("Namespace", vaultNamespace);
        Row("TOTP engine mount", totpMount);
        Heading("Authentication");
        method.Items.AddRange([.. Methods.Select(m => m.Title)]);
        Row("Method", method);
        Row("Auth method mount", authMount);
        Row("Username", username);
        Row("RoleID", roleId);
        Row("OIDC role", oidcRole);
        Row("Redirect URI port", oidcPort);
        layout.Controls.Add(credentialLabel);
        layout.Controls.Add(Fill(credential));
        if (session is not null)
        {
            credential.PlaceholderText = "Empty keeps the stored one";
            Row("Status", status);
            Wide(problem);
            Wide(lastAttempt);
            Wide(Buttons(signIn, signOut, copyDetails));
        }
        Wide(Buttons(test, setup));
        Wide(checks);
        Wide(message);
        Wide(Buttons(MakeButton("Save", Save), MakeButton("Revert", Revert)));
        Controls.Add(layout);

        method.SelectedIndexChanged += (_, _) => MethodChanged();
        signIn.Click += async (_, _) => await SignInAsync();
        signOut.Click += (_, _) =>
        {
            if (Session is { } current)
            {
                store.SignOut(current);
            }
        };
        copyDetails.Click += (_, _) =>
        {
            if (Session is { Problem: { } current } vault)
            {
                Dialogs.CopyText($"{vault.Profile.Name}\n{current.Report}");
            }
        };
        test.Click += async (_, _) => await TestAsync();
        setup.Click += (_, _) => OpenSetup();
        address.TextChanged += (_, _) => setup.Enabled = address.Text.Trim().Length > 0;
        ClientSizeChanged += (_, _) => WrapLabels();
        WrapLabels();
        Revert();
        setup.Enabled = address.Text.Trim().Length > 0;
    }

    /// <summary>The vault of the page; null until a new one is saved.</summary>
    public VaultSession? Session { get; private set; }

    /// <summary>Raised when the vault is saved.</summary>
    public event EventHandler? Saved;

    /// <summary>Wraps the problem and the message at the width of the page less its margins.</summary>
    private void WrapLabels()
    {
        var width = Math.Max(ClientSize.Width - LogicalToDeviceUnits(40), LogicalToDeviceUnits(160));
        problem.MaximumSize = message.MaximumSize = new Size(width, 0);
    }

    private static Control Fill(Control control)
    {
        control.Dock = DockStyle.Fill;
        return control;
    }

    private static Button MakeButton(string text, Action action)
    {
        var button = new Button { Text = text, AutoSize = true };
        button.Click += (_, _) => action();
        return button;
    }

    private static FlowLayoutPanel Buttons(params Control[] controls)
    {
        var panel = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 4, 0, 4) };
        panel.Controls.AddRange(controls);
        return panel;
    }

    private void Heading(string text)
    {
        var label = new Label
        {
            Text = text,
            AutoSize = true,
            Font = bold,
            Margin = new Padding(3, 12, 3, 4),
        };
        layout.Controls.Add(label);
        layout.SetColumnSpan(label, 2);
    }

    private void Row(string text, Control field)
    {
        var label = new Label { Text = text, AutoSize = true, Anchor = AnchorStyles.Left };
        labels[field] = label;
        layout.Controls.Add(label);
        layout.Controls.Add(Fill(field));
    }

    private void Wide(Control control)
    {
        layout.Controls.Add(control);
        layout.SetColumnSpan(control, 2);
    }

    private AuthMethod SelectedMethod => Methods[Math.Max(method.SelectedIndex, 0)].Method;

    /// <summary>Shows the fields of the chosen method, and names its mount after it unless another mount was typed.</summary>
    private void MethodChanged()
    {
        var chosen = SelectedMethod;
        if (authMount.Text.Trim().Length == 0 || AuthMethodNames.FromName(authMount.Text.Trim()) is not null)
        {
            authMount.Text = chosen.Name();
        }
        ShowField(authMount, chosen != AuthMethod.Token);
        ShowField(username, chosen == AuthMethod.Userpass);
        ShowField(roleId, chosen == AuthMethod.Approle);
        ShowField(oidcRole, chosen == AuthMethod.Oidc);
        ShowField(oidcPort, chosen == AuthMethod.Oidc);
        credential.Visible = credentialLabel.Visible = chosen != AuthMethod.Oidc;
        credentialLabel.Text = chosen switch
        {
            AuthMethod.Userpass => "Password",
            AuthMethod.Approle => "SecretID",
            _ => "Token",
        };
    }

    private void ShowField(Control field, bool visible) => field.Visible = labels[field].Visible = visible;

    /// <summary>Fills the fields from the saved vault, or empties them for a new one.</summary>
    private void Revert()
    {
        var configuration = Session?.Profile.Configuration ?? new VaultConfiguration("");
        name.Text = Session?.Profile.Name ?? "";
        address.Text = configuration.Address;
        vaultNamespace.Text = configuration.Namespace ?? "";
        totpMount.Text = configuration.TotpMount;
        authMount.Text = configuration.AuthMount;
        method.SelectedIndex = Array.FindIndex(Methods, m => m.Method == configuration.AuthMethod);
        username.Text = configuration.Username ?? "";
        roleId.Text = configuration.RoleId ?? "";
        oidcRole.Text = configuration.OidcRole ?? "";
        oidcPort.Text = configuration.OidcPort.ToString(CultureInfo.InvariantCulture);
        credential.Text = "";
        message.Text = "";
        MethodChanged();
        RefreshStatus();
    }

    /// <summary>The settings in the fields, or why they cannot be used.</summary>
    private VaultConfiguration Configuration()
    {
        static string? Text(TextBox field) => field.Text.Trim() is { Length: > 0 } text ? text : null;

        var chosen = SelectedMethod;
        var url = Text(address) ?? throw SessionException.MissingSetting("Vault address");
        if (!int.TryParse(oidcPort.Text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            || port is < 1 or > 65535)
        {
            throw SessionException.InvalidSetting("Redirect URI port");
        }
        if (chosen == AuthMethod.Userpass && Text(username) is null)
        {
            throw SessionException.MissingSetting("Username");
        }
        if (chosen == AuthMethod.Approle && Text(roleId) is null)
        {
            throw SessionException.MissingSetting("RoleID");
        }
        return new VaultConfiguration(url, Text(vaultNamespace), Text(totpMount) ?? "totp", chosen,
                                      chosen == AuthMethod.Token ? null : Text(authMount), Text(username), Text(roleId),
                                      Text(oidcRole), port);
    }

    /// <summary>Writes the vault, and signs in at once, except for OIDC, which is signed in on request.</summary>
    private void Save()
    {
        try
        {
            var configuration = Configuration();
            var typedName = name.Text.Trim();
            var typedCredential = credential.Text;
            if (Session is { } current)
            {
                store.UpdateVaultProfile(current, typedName, configuration, typedCredential.Length == 0 ? null : typedCredential);
            }
            else
            {
                Session = store.AddVaultProfile(typedName, configuration, typedCredential);
            }
            message.Text = "";
            credential.Text = "";
            Saved?.Invoke(this, EventArgs.Empty);
            if (configuration.AuthMethod != AuthMethod.Oidc)
            {
                _ = SignInAsync();
            }
        }
        catch (Exception error) when (error is SessionException or StoreException || AccountStore.IsStorageFailure(error))
        {
            message.Text = Dialogs.Describe(error);
        }
    }

    /// <summary>Signs in; the vault's status shows the outcome.</summary>
    private async Task SignInAsync()
    {
        if (Session is not { } current)
        {
            return;
        }
        try
        {
            await store.SignInAsync(current);
        }
        catch (Exception)
        {
            // The session records the problem, and the status shows it.
        }
    }

    /// <summary>Tests the vault as the fields describe it, with the stored credential when none is typed.</summary>
    private async Task TestAsync()
    {
        test.Enabled = false;
        checks.Visible = true;
        checks.Text = "Testing...";
        IReadOnlyList<VaultCheck> results;
        try
        {
            var configuration = Configuration();
            var typed = credential.Text;
            var used = typed.Length > 0 || Session is null ? typed : CredentialStore.VaultCredential(Session.Profile.Id);
            // The token of the vault's sign-in goes to the address of the vault alone.
            var saved = Session?.Profile.Configuration;
            var sameServer = saved is not null && saved.Address == configuration.Address && saved.Namespace == configuration.Namespace;
            results = await VaultDiagnostics.RunAsync(configuration, used, sameServer ? Session?.Token : null);
        }
        catch (Exception error) when (error is SessionException || AccountStore.IsStorageFailure(error))
        {
            results = [new VaultCheck("Settings", VaultCheckOutcome.Failed, "The settings cannot be tested.",
                                      error is SessionException session ? session.Problem : VaultProblem.From(error))];
        }
        if (IsDisposed)
        {
            return;
        }
        checks.Text = Dialogs.FormatChecks(results);
        test.Enabled = true;
    }

    /// <summary>
    /// Opens Vault Setup with the vault as the fields describe it, and the credential as typed or, when none is
    /// typed, as stored.
    /// </summary>
    private void OpenSetup()
    {
        VaultConfiguration configuration;
        string? used;
        try
        {
            configuration = Configuration();
            var typed = credential.Text;
            used = typed.Length > 0 || Session is null ? typed : CredentialStore.VaultCredential(Session.Profile.Id);
        }
        catch (Exception error) when (error is SessionException || AccountStore.IsStorageFailure(error))
        {
            message.Text = Dialogs.Describe(error);
            return;
        }
        message.Text = "";
        using var dialog = new VaultSetupDialog(configuration, used, Session);
        dialog.ShowDialog(FindForm());
    }

    /// <summary>
    /// Shows the state of the saved vault's authentication and its problem, and names the buttons, in the words of
    /// its method: a token is checked, a password or an AppRole is logged in, and only OIDC signs in.
    /// </summary>
    public void RefreshStatus()
    {
        if (Session is not { } current)
        {
            return;
        }
        var (signedOut, signingIn, signedIn, start, stop) = current.Profile.Configuration.AuthMethod switch
        {
            AuthMethod.Token => ("Token not checked", "Checking the token...", "Token accepted", "Check Token", "Forget Token"),
            AuthMethod.Userpass or AuthMethod.Approle => ("Not logged in", "Logging in...", "Logged in", "Log In", "Log Out"),
            _ => ("Signed out", "Signing in...", "Signed in", "Sign In", "Sign Out"),
        };
        (status.Text, status.ForeColor) = current.State switch
        {
            VaultState.SignedIn => (signedIn, Color.ForestGreen),
            VaultState.SigningIn => (signingIn, Color.DarkGoldenrod),
            VaultState.Failed => (current.Problem?.Title ?? "Failed", Color.Firebrick),
            _ => (signedOut, SystemColors.GrayText),
        };
        signIn.Text = start;
        signOut.Text = stop;
        var failed = current is { State: VaultState.Failed, Problem: not null };
        problem.Visible = lastAttempt.Visible = copyDetails.Visible = failed;
        problem.Text = failed ? $"{current.Problem!.Detail}{Environment.NewLine}{current.Problem.Suggestion}" : "";
        lastAttempt.Text = current.LastAttempt is { } last ? $"Last attempt: {last.ToLocalTime():T}" : "";
        signIn.Enabled = current.State != VaultState.SigningIn;
        signOut.Enabled = current.State != VaultState.SignedOut;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            bold.Dispose();
            fixedWidth.Dispose();
        }
        base.Dispose(disposing);
    }
}
