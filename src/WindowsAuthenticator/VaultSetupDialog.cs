using Vault;

namespace WindowsAuthenticator;

/// <summary>
/// The Vault Setup dialog: the engine mount and the policy names, the texts of the policies as they will be
/// written, and the run, as the identity the vault's page describes. It stays open after a run, to show its steps.
/// </summary>
internal sealed class VaultSetupDialog : FieldsDialog
{
    private readonly Font fixedWidth = new("Consolas", 9f);

    /// <param name="configuration">The vault as its page describes it.</param>
    /// <param name="credential">The token, password or SecretID typed on the page, or stored for the vault.</param>
    /// <param name="session">The saved vault, whose sign-in an OIDC vault runs the setup with.</param>
    public VaultSetupDialog(VaultConfiguration configuration, string? credential, VaultSession? session)
        : base("Vault Setup",
               "Enables the TOTP engine and writes the two policies, as the identity the vault's page describes. " +
               "The policies are not assigned to anyone; a Vault administrator assigns them to users, roles or tokens.",
               "Run")
    {
        var mount = AddField("TOTP engine mount", new TextBox { Text = configuration.TotpMount.Length == 0 ? "totp" : configuration.TotpMount });
        var description = AddField("Description", new TextBox { Text = "TOTP secrets engine" });
        var engineExists = new CheckBox { Text = "The engine is already enabled", AutoSize = true };
        AddControl(engineExists);
        var creator = AddField("Creator policy", new TextBox { Text = "totp_creator" });
        var user = AddField("User policy", new TextBox { Text = "totp_user" });
        var overwrite = new CheckBox { Text = "Replace policies that exist", AutoSize = true };
        AddControl(overwrite);
        var creatorText = AddField("Creator policy text", PolicyBox());
        var userText = AddField("User policy text", PolicyBox());
        userText.Height = LogicalToDeviceUnits(160);
        var result = AddField("Result", new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            WordWrap = false,
            ScrollBars = ScrollBars.Both,
            Font = fixedWidth,
            Height = LogicalToDeviceUnits(110),
            Visible = false,
        });

        void ShowPolicies()
        {
            creatorText.Text = VaultSetup.CreatorPolicy(mount.Text).ReplaceLineEndings(Environment.NewLine);
            userText.Text = VaultSetup.UserPolicy(mount.Text).ReplaceLineEndings(Environment.NewLine);
        }
        mount.TextChanged += (_, _) => ShowPolicies();
        ShowPolicies();
        InitialFocus = mount;

        Accepting = async () =>
        {
            var options = new VaultSetupOptions(mount.Text, description.Text, creator.Text.Trim(), user.Text.Trim(),
                                                overwrite.Checked, engineExists.Checked);
            result.Visible = true;
            result.Text = "Running...";
            IReadOnlyList<VaultCheck> checks;
            try
            {
                checks = await RunAsync(configuration, credential, session, options);
            }
            catch (Exception error)
            {
                checks = [new VaultCheck("Authentication", VaultCheckOutcome.Failed, "The setup was not started.",
                                         VaultProblem.From(error, configuration.AuthMethod))];
            }
            result.Text = Dialogs.FormatChecks(checks);
            RenameButtons("Run Again", "Close");
            return false;
        };
    }

    /// <summary>A read-only box of a policy's text, in a fixed-width font.</summary>
    private TextBox PolicyBox() => new()
    {
        Multiline = true,
        ReadOnly = true,
        WordWrap = false,
        ScrollBars = ScrollBars.Both,
        Font = fixedWidth,
        Height = LogicalToDeviceUnits(110),
    };

    /// <summary>
    /// Signs in as the page describes, which for OIDC is the saved vault's current sign-in, and runs the setup.
    /// </summary>
    private static async Task<IReadOnlyList<VaultCheck>> RunAsync(VaultConfiguration configuration, string? credential,
                                                                 VaultSession? session, VaultSetupOptions options)
    {
        if (configuration.AuthMethod == AuthMethod.Oidc)
        {
            var signedIn = session ?? throw VaultException.NotSignedIn();
            return await signedIn.AuthorizedAsync(client => VaultSetup.RunAsync(client, options));
        }
        var token = await VaultClient.SignInAsync(configuration, credential) ?? throw VaultException.NotSignedIn();
        return await VaultSetup.RunAsync(new VaultClient(configuration, token.Token), options);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            fixedWidth.Dispose();
        }
        base.Dispose(disposing);
    }
}
