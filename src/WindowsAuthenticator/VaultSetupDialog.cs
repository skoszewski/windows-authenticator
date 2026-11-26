using Vault;

namespace WindowsAuthenticator;

/// <summary>
/// The Vault Setup dialog: the TOTP engine and KV v2 and v1 engines for secrets, each switched on or off with its
/// mount and policy names, the texts of the policies as they will be written, and the run, as the identity the
/// vault's page describes. The parts scroll when they are taller than the screen leaves room for. It stays open
/// after a run, to show its steps.
/// </summary>
internal sealed class VaultSetupDialog : FieldsDialog
{
    /// <summary>The fields of one engine; the grid holds those after the switch, shown while it is on.</summary>
    private sealed record Part(CheckBox On, TextBox Mount, TextBox Description, CheckBox Exists, TextBox Creator,
                               TextBox User, Control Grid);

    private readonly Font fixedWidth = new("Consolas", 9f);
    private readonly Font bold;
    private readonly Panel scroller = new() { AutoScroll = true, Margin = new Padding(0, 6, 0, 0) };
    private readonly TableLayoutPanel parts = new()
    {
        AutoSize = true,
        AutoSizeMode = AutoSizeMode.GrowAndShrink,
        ColumnCount = 1,
        Dock = DockStyle.Top,
        Margin = new Padding(0),
    };

    /// <param name="configuration">The vault as its page describes it.</param>
    /// <param name="credential">The token, password or SecretID typed on the page, or stored for the vault.</param>
    /// <param name="session">The saved vault, whose sign-in an OIDC vault runs the setup with.</param>
    public VaultSetupDialog(VaultConfiguration configuration, string? credential, VaultSession? session)
        : base("Vault Setup",
               "Enables the engines and writes their policies, as the identity the vault's page describes. " +
               "The policies are not assigned to anyone; a Vault administrator assigns them to users, roles or tokens.",
               "Run")
    {
        bold = new Font(Font, FontStyle.Bold);
        var kvDefaults = KvSetupOptions.Default(KvVersion.V2);
        var kv1Defaults = KvSetupOptions.Default(KvVersion.V1);
        var totp = AddPart("Set up the TOTP engine", true,
                           configuration.TotpMount.Length == 0 ? "totp" : configuration.TotpMount, "TOTP secrets engine",
                           "totp_creator", "totp_user");
        var kv = AddPart("Set up a KV v2 engine for secrets", false, kvDefaults.Mount, kvDefaults.Description,
                         kvDefaults.CreatorPolicy, kvDefaults.UserPolicy);
        var kv1 = AddPart("Set up a KV v1 engine for secrets", false, kv1Defaults.Mount, kv1Defaults.Description,
                          kv1Defaults.CreatorPolicy, kv1Defaults.UserPolicy);
        scroller.Controls.Add(parts);
        scroller.Width = FieldWidth + SystemInformation.VerticalScrollBarWidth;
        AddControl(scroller);
        var overwrite = new CheckBox { Text = "Replace policies that exist", AutoSize = true };
        AddControl(overwrite);
        var policies = AddField("Policy texts", TextArea(LogicalToDeviceUnits(150)));
        var result = AddField("Result", TextArea(LogicalToDeviceUnits(110)));
        result.Visible = false;

        void ShowPolicies()
        {
            var texts = new List<(string Name, string Text)>();
            if (totp.On.Checked)
            {
                texts.Add((totp.Creator.Text, VaultSetup.CreatorPolicy(totp.Mount.Text)));
                texts.Add((totp.User.Text, VaultSetup.UserPolicy(totp.Mount.Text)));
            }
            if (kv.On.Checked)
            {
                texts.Add((kv.Creator.Text, VaultSetup.KvCreatorPolicy(kv.Mount.Text)));
                texts.Add((kv.User.Text, VaultSetup.KvUserPolicy(kv.Mount.Text)));
            }
            if (kv1.On.Checked)
            {
                texts.Add((kv1.Creator.Text, VaultSetup.KvCreatorPolicy(kv1.Mount.Text, KvVersion.V1)));
                texts.Add((kv1.User.Text, VaultSetup.KvUserPolicy(kv1.Mount.Text, KvVersion.V1)));
            }
            policies.Text = string.Join(Environment.NewLine, texts.Select(t => $"# {t.Name}\n{t.Text}"))
                .ReplaceLineEndings(Environment.NewLine);
        }
        foreach (var part in new[] { totp, kv, kv1 })
        {
            part.On.CheckedChanged += (_, _) =>
            {
                part.Grid.Visible = part.On.Checked;
                ShowPolicies();
                FitParts();
            };
            foreach (var field in new[] { part.Mount, part.Creator, part.User })
            {
                field.TextChanged += (_, _) => ShowPolicies();
            }
        }
        ShowPolicies();
        Shown += (_, _) => FitParts();
        InitialFocus = totp.Mount;

        Accepting = async () =>
        {
            static KvSetupOptions? Kv(Part part, KvVersion version) => part.On.Checked
                ? new KvSetupOptions(version, part.Mount.Text, part.Description.Text, part.Creator.Text.Trim(),
                                     part.User.Text.Trim(), part.Exists.Checked)
                : null;

            var options = new VaultSetupOptions(totp.Mount.Text, totp.Description.Text, totp.Creator.Text.Trim(),
                                                totp.User.Text.Trim(), overwrite.Checked, totp.Exists.Checked,
                                                totp.On.Checked, Kv(kv, KvVersion.V2), Kv(kv1, KvVersion.V1));
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

    /// <summary>Adds an engine's switch and, under it, its fields as labelled rows.</summary>
    private Part AddPart(string title, bool on, string mount, string description, string creator, string user)
    {
        var toggle = new CheckBox { Text = title, AutoSize = true, Checked = on, Font = bold, Margin = new Padding(3, 10, 3, 2) };
        var grid = new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 2,
            Visible = on,
            Margin = new Padding(16, 0, 0, 0),
        };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, FieldWidth - 160));
        TextBox Row(string label, string text)
        {
            grid.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left });
            var field = new TextBox { Text = text, Dock = DockStyle.Fill };
            grid.Controls.Add(field);
            return field;
        }
        var mountField = Row("Mount", mount);
        var descriptionField = Row("Description", description);
        var exists = new CheckBox { Text = "The engine is already enabled", AutoSize = true };
        grid.Controls.Add(exists);
        grid.SetColumnSpan(exists, 2);
        var creatorField = Row("Creator policy", creator);
        var userField = Row("User policy", user);
        parts.Controls.Add(toggle);
        parts.Controls.Add(grid);
        return new Part(toggle, mountField, descriptionField, exists, creatorField, userField, grid);
    }

    /// <summary>A read-only box of text in a fixed-width font.</summary>
    private TextBox TextArea(int height) => new()
    {
        Multiline = true,
        ReadOnly = true,
        WordWrap = false,
        ScrollBars = ScrollBars.Both,
        Font = fixedWidth,
        Height = height,
    };

    /// <summary>Sizes the parts to their height, or to the room the screen leaves, beyond which they scroll.</summary>
    private void FitParts()
    {
        var room = Screen.FromControl(this).WorkingArea.Height - LogicalToDeviceUnits(480);
        scroller.Height = Math.Max(LogicalToDeviceUnits(120), Math.Min(parts.PreferredSize.Height, room));
    }

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
            bold.Dispose();
        }
        base.Dispose(disposing);
    }
}
