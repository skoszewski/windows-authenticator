using Totp;
using Vault;

namespace WindowsAuthenticator;

/// <summary>
/// The Settings window, made once and hidden when closed: the Accounts tab, a list of all accounts with the
/// details of the selected one, the Vaults tab, a list of the vaults with the page of the selected one, and a
/// status bar that says what the app waits for from a vault, with Cancel, or what was just copied.
/// </summary>
internal sealed class SettingsWindow : Form
{
    private const string WarningImage = "warning";
    private const string BusyImage = "busy";

    private readonly AccountStore store;
    private readonly Action<Account> showWindow;
    private readonly TabControl tabs = new() { Dock = DockStyle.Fill };
    private readonly TabPage accountsTab = new("Accounts");
    private readonly TabPage vaultsTab = new("Vaults");
    private readonly ImageList images = new() { ImageSize = new Size(16, 16), ColorDepth = ColorDepth.Depth32Bit };
    private readonly ListView accounts = List();
    private readonly ListView vaults = List();
    private readonly Panel accountDetails = new() { Dock = DockStyle.Fill, AutoScroll = true };
    private readonly Panel vaultPage = new() { Dock = DockStyle.Fill };
    private readonly ContextMenuStrip addMenu = new();
    private readonly Button removeAccount = new() { Text = "Remove", AutoSize = true, Enabled = false };
    private readonly Button removeVault = new() { Text = "Remove", AutoSize = true, Enabled = false };
    private readonly Font bold;
    private readonly Font fixedWidth = new("Consolas", 10f);
    private readonly List<(Label Label, bool Wide)> wrapping = [];
    private readonly StatusStrip statusBar = new() { SizingGrip = false };
    private readonly ToolStripProgressBar activityProgress = new() { Style = ProgressBarStyle.Marquee, Visible = false };
    private readonly ToolStripStatusLabel activityText = new() { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
    private readonly ToolStripDropDownButton cancelActivity = new() { Text = "Cancel", ShowDropDownArrow = false, Visible = false };
    private readonly System.Windows.Forms.Timer activityTimer = new() { Interval = 1000 };
    private readonly Bitmap checkImage = Check();

    /// <summary>The buttons of the shown account that call its vault, disabled while the vault has a call running.</summary>
    private readonly List<(Button Button, bool WhileRevealed)> vaultActions = [];

    /// <summary>The secret shown on the page of its account until it is hidden or another account is selected.</summary>
    private (Guid Account, string Value)? revealed;
    private VaultEditor? editor;
    private bool refreshing;
    private bool quitting;

    public SettingsWindow(AccountStore store, Action<Account> showWindow)
    {
        this.store = store;
        this.showWindow = showWindow;
        Text = $"{Dialogs.AppName} Settings";
        Icon = AppIcon.Load(SystemInformation.IconSize);
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;
        Size = new Size(860, 600);
        MinimumSize = new Size(640, 440);
        bold = new Font(Font, FontStyle.Bold);

        using (var warning = new Icon(SystemIcons.Warning, 16, 16))
        {
            images.Images.Add(WarningImage, warning.ToBitmap());
        }
        foreach (var (state, color) in new[]
                 {
                     (VaultState.SignedIn, Color.ForestGreen), (VaultState.SigningIn, Color.Goldenrod),
                     (VaultState.Failed, Color.Firebrick), (VaultState.SignedOut, Color.Gray),
                 })
        {
            images.Images.Add(state.ToString(), Dot(color));
        }
        images.Images.Add(BusyImage, Busy());
        accounts.SmallImageList = images;
        vaults.SmallImageList = images;
        accounts.Columns.Add("Account");
        accounts.Columns.Add("Kind");
        accounts.Columns.Add("Store");
        vaults.Columns.Add("Vault");
        foreach (var list in new[] { accounts, vaults })
        {
            list.ClientSizeChanged += (_, _) => FitColumns(list);
        }

        addMenu.Items.Add("Account...", null, (_, _) => Dialogs.AddAccount(store, this));
        addMenu.Items.Add("From QR Code in Clipboard", null, (_, _) => Dialogs.AddAccountFromClipboard(store, this));
        addMenu.Items.Add(new ToolStripSeparator());
        var fromVault = addMenu.Items.Add("From Vault...", null, (_, _) => Dialogs.AddFromVault(store, this));
        var generate = addMenu.Items.Add("Generate in Vault...", null, async (_, _) => await Dialogs.GenerateAccountAsync(store, this));
        var import = addMenu.Items.Add("Import to Vault...", null, async (_, _) => await Dialogs.ImportAccountAsync(store, this));
        addMenu.Items.Add(new ToolStripSeparator());
        addMenu.Items.Add("Secret...", null, (_, _) => Dialogs.AddSecret(store, this));
        var secretFrom = addMenu.Items.Add("Secret from Vault...", null, (_, _) => Dialogs.AddVaultSecret(store, writing: false, this));
        var secretIn = addMenu.Items.Add("Secret in Vault...", null, (_, _) => Dialogs.AddVaultSecret(store, writing: true, this));
        addMenu.Opening += (_, _) =>
            fromVault.Enabled = generate.Enabled = import.Enabled = secretFrom.Enabled = secretIn.Enabled = store.Vaults.Count > 0;
        var addAccount = new Button { Text = "Add...", AutoSize = true };
        addAccount.Click += (_, _) => addMenu.Show(addAccount, new Point(0, addAccount.Height));
        removeAccount.Click += (_, _) =>
        {
            if (SelectedAccount is { } account)
            {
                Dialogs.RemoveAccount(account, store, this);
            }
        };
        accountsTab.Controls.Add(Split(accounts, addAccount, removeAccount, accountDetails));

        var addVault = new Button { Text = "Add...", AutoSize = true };
        addVault.Click += (_, _) =>
        {
            vaults.SelectedItems.Clear();
            ShowVaultPage(null);
        };
        removeVault.Click += (_, _) =>
        {
            if (editor?.Session is { } session && Dialogs.RemoveVault(session, store, this))
            {
                ShowVaultPage(null, placeholder: true);
            }
        };
        vaultsTab.Controls.Add(Split(vaults, addVault, removeVault, vaultPage));

        tabs.TabPages.Add(accountsTab);
        tabs.TabPages.Add(vaultsTab);
        Controls.Add(tabs);
        statusBar.Items.AddRange([activityProgress, activityText, cancelActivity]);
        Controls.Add(statusBar);
        cancelActivity.Click += (_, _) => store.CancelActivity();
        activityTimer.Tick += (_, _) => ShowActivity();
        store.ActivityChanged += (_, _) => ShowActivity();
        Deactivate += (_, _) => HideSecret();
        VisibleChanged += (_, _) =>
        {
            if (!Visible)
            {
                HideSecret();
            }
        };

        accounts.ItemSelectionChanged += (_, _) =>
        {
            if (!refreshing)
            {
                ShowAccountDetails();
            }
        };
        vaults.ItemSelectionChanged += (_, e) =>
        {
            if (!refreshing && e.IsSelected && e.Item?.Tag is VaultSession session)
            {
                ShowVaultPage(session);
            }
        };
        accountDetails.ClientSizeChanged += (_, _) =>
        {
            foreach (var (label, wide) in wrapping)
            {
                WrapLabel(label, wide);
            }
        };
        store.Changed += (_, _) => RefreshLists();
        RefreshLists();
        ShowAccountDetails();
        ShowVaultPage(null, placeholder: true);
    }

    private static ListView List() => new()
    {
        Dock = DockStyle.Fill,
        View = View.Details,
        FullRowSelect = true,
        MultiSelect = false,
        HideSelection = false,
        HeaderStyle = ColumnHeaderStyle.Nonclickable,
    };

    /// <summary>Three grey dots, beside an account whose vault has a call running.</summary>
    private static Bitmap Busy()
    {
        var bitmap = new Bitmap(16, 16);
        using var graphics = Graphics.FromImage(bitmap);
        using var brush = new SolidBrush(Color.Gray);
        graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        for (var i = 0; i < 3; i++)
        {
            graphics.FillEllipse(brush, 1 + i * 5, 6, 4, 4);
        }
        return bitmap;
    }

    /// <summary>A white check mark on a green dot, beside the notice of what was copied.</summary>
    private static Bitmap Check()
    {
        var bitmap = new Bitmap(16, 16);
        using var graphics = Graphics.FromImage(bitmap);
        using var brush = new SolidBrush(Color.ForestGreen);
        using var pen = new Pen(Color.White, 2);
        graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        graphics.FillEllipse(brush, 1, 1, 14, 14);
        graphics.DrawLines(pen, [new Point(4, 8), new Point(7, 11), new Point(12, 5)]);
        return bitmap;
    }

    /// <summary>
    /// Shows the call the app waits for, with how long once it is 5 seconds, and Cancel, or the notice of what was
    /// copied, or nothing; marks the accounts of busy vaults and disables their actions.
    /// </summary>
    private void ShowActivity()
    {
        if (store.Activity is { } activity)
        {
            var waited = (int)(DateTimeOffset.Now - activity.Operation.Since).TotalSeconds;
            activityText.Image = null;
            activityText.Text = $"{activity.Session.Profile.Name}: {activity.Operation.Label}..."
                                + (waited >= 5 ? $" Still waiting, {waited} s." : "");
            activityProgress.Visible = cancelActivity.Visible = true;
        }
        else
        {
            activityProgress.Visible = cancelActivity.Visible = false;
            var notice = store.CurrentNotice;
            activityText.Image = notice is null ? null : checkImage;
            activityText.Text = notice?.Text ?? "";
        }
        activityTimer.Enabled = store.Activity is not null || store.CurrentNotice is not null;

        foreach (ListViewItem item in accounts.Items)
        {
            if (item.Tag is Account account)
            {
                item.ImageKey = store.Problem(account) is not null ? WarningImage : store.IsVaultBusy(account) ? BusyImage : "";
            }
        }
        if (SelectedAccount is { } selected)
        {
            var busy = store.IsVaultBusy(selected);
            foreach (var (button, whileRevealed) in vaultActions)
            {
                button.Enabled = !busy || whileRevealed;
            }
        }
    }

    /// <summary>Hides a revealed secret, when the window loses the keyboard or is hidden.</summary>
    private void HideSecret()
    {
        if (revealed is null)
        {
            return;
        }
        revealed = null;
        ShowAccountDetails();
    }

    /// <summary>A coloured dot showing the state of a vault.</summary>
    private static Bitmap Dot(Color color)
    {
        var bitmap = new Bitmap(16, 16);
        using var graphics = Graphics.FromImage(bitmap);
        using var brush = new SolidBrush(color);
        graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        graphics.FillEllipse(brush, 4, 4, 8, 8);
        return bitmap;
    }

    /// <summary>Shares the width of the list among its columns: the first takes 55% of two, a single one all of it.</summary>
    private static void FitColumns(ListView list)
    {
        var width = list.ClientSize.Width;
        if (width <= 0)
        {
            return;
        }
        if (list.Columns.Count == 1)
        {
            list.Columns[0].Width = width;
            return;
        }
        list.Columns[0].Width = width * 45 / 100;
        list.Columns[1].Width = width * 15 / 100;
        list.Columns[2].Width = width - list.Columns[0].Width - list.Columns[1].Width;
    }

    /// <summary>
    /// The list with its buttons under it on the left, and the details on the right. The list gets two fifths of
    /// the width once the window is laid out, and keeps its width when the window is resized.
    /// </summary>
    private SplitContainer Split(ListView list, Button add, Button remove, Control details)
    {
        var split = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel1 };
        var minimum = LogicalToDeviceUnits(220);
        var placed = false;
        split.SizeChanged += (_, _) =>
        {
            if (placed || split.Width < minimum * 2)
            {
                return;
            }
            placed = true;
            split.Panel1MinSize = minimum;
            split.Panel2MinSize = minimum;
            split.SplitterDistance = Math.Max(minimum, split.Width * 2 / 5);
        };
        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Bottom, Padding = new Padding(0, 4, 0, 4) };
        buttons.Controls.Add(add);
        buttons.Controls.Add(remove);
        split.Panel1.Controls.Add(list);
        split.Panel1.Controls.Add(buttons);
        split.Panel2.Controls.Add(details);
        return split;
    }

    private Account? SelectedAccount => accounts.SelectedItems.Count == 1 ? accounts.SelectedItems[0].Tag as Account : null;

    /// <summary>Brings the window to the front, showing the page of a vault when one is given.</summary>
    public void Present(Guid? vault = null)
    {
        if (vault is { } id && store.Vault(id) is { } session)
        {
            tabs.SelectedTab = vaultsTab;
            SelectVault(session);
            ShowVaultPage(session);
        }
        Show();
        if (WindowState == FormWindowState.Minimized)
        {
            WindowState = FormWindowState.Normal;
        }
        Activate();
    }

    /// <summary>Closes the window for good, when the app quits.</summary>
    public void Quit()
    {
        quitting = true;
        Close();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (!quitting && e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            Hide();
        }
        base.OnFormClosing(e);
    }

    private void SelectVault(VaultSession session)
    {
        refreshing = true;
        foreach (ListViewItem item in vaults.Items)
        {
            item.Selected = item.Tag == session;
        }
        refreshing = false;
    }

    /// <summary>Fills both lists from the store, keeping the selections, and refreshes the shown details.</summary>
    private void RefreshLists()
    {
        refreshing = true;
        var selectedAccount = SelectedAccount?.Id;
        accounts.BeginUpdate();
        accounts.Items.Clear();
        if (store.LoadError is { } loadError)
        {
            accounts.Items.Add(new ListViewItem(loadError, WarningImage));
        }
        foreach (var account in store.Accounts)
        {
            var item = new ListViewItem(account.Name) { Tag = account };
            item.ImageKey = store.Problem(account) is not null ? WarningImage : store.IsVaultBusy(account) ? BusyImage : "";
            item.SubItems.Add(account.Kind == AccountKind.Secret ? "Secret" : "TOTP");
            item.SubItems.Add(store.Source(account));
            accounts.Items.Add(item);
            item.Selected = account.Id == selectedAccount;
        }
        accounts.EndUpdate();

        vaults.BeginUpdate();
        vaults.Items.Clear();
        foreach (var session in store.Vaults)
        {
            vaults.Items.Add(new ListViewItem(session.Profile.Name, session.State.ToString()) { Tag = session }).Selected =
                session == editor?.Session;
        }
        vaults.EndUpdate();
        refreshing = false;

        ShowAccountDetails();
        if (editor?.Session is { } shown)
        {
            if (store.Vaults.Contains(shown))
            {
                editor.RefreshStatus();
            }
            else
            {
                ShowVaultPage(null, placeholder: true);
            }
        }
        removeVault.Enabled = editor?.Session is not null;
    }

    /// <summary>The parameters of the selected account and what can be done with it.</summary>
    private void ShowAccountDetails()
    {
        var account = SelectedAccount is { } selected ? store.Accounts.FirstOrDefault(a => a.Id == selected.Id) : null;
        if (revealed?.Account != account?.Id)
        {
            revealed = null;
        }
        removeAccount.Enabled = account is not null;
        vaultActions.Clear();
        accountDetails.SuspendLayout();
        foreach (Control control in accountDetails.Controls.Cast<Control>().ToList())
        {
            control.Dispose();
        }
        wrapping.Clear();
        if (account is null)
        {
            accountDetails.Controls.Add(Placeholder("Select an account, or add one."));
            accountDetails.ResumeLayout();
            return;
        }
        var layout = new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 2,
            Dock = DockStyle.Top,
            Padding = new Padding(8),
        };
        void Heading(string text)
        {
            var label = new Label { Text = text, AutoSize = true, Font = bold, Margin = new Padding(3, 12, 3, 4) };
            layout.Controls.Add(label);
            layout.SetColumnSpan(label, 2);
        }
        void Row(string name, string value)
        {
            layout.Controls.Add(new Label { Text = name, AutoSize = true });
            layout.Controls.Add(Wrapped(new Label { Text = value, AutoSize = true }, wide: false));
        }
        void Wide(Control control)
        {
            layout.Controls.Add(control);
            layout.SetColumnSpan(control, 2);
        }

        var vaultKey = store.VaultKeyOf(account);
        var vaultProfile = store.VaultProfileOf(account);
        if (store.Problem(account) is { } problem)
        {
            Heading("Problem");
            Wide(new Label { Text = problem.Title, AutoSize = true, ForeColor = Color.Firebrick });
            Wide(Wrapped(new Label { Text = problem.Detail, AutoSize = true }, wide: true));
            Wide(Wrapped(new Label { Text = problem.Suggestion, AutoSize = true, ForeColor = SystemColors.GrayText }, wide: true));
            if (vaultProfile is { } profile && store.Vault(profile) is not null)
            {
                var showVault = new Button { Text = "Show Vault", AutoSize = true };
                showVault.Click += (_, _) => Present(profile);
                Wide(showVault);
            }
        }
        Heading("Account");
        Row("Name", account.Name);
        if (account.Issuer is { } issuer)
        {
            Row("Issuer", issuer);
        }
        Row("Store", store.Source(account));
        if (vaultKey is not null)
        {
            Row("Vault key", vaultKey.Key);
        }
        if (store.VaultSecretOf(account)?.Reference is { } reference)
        {
            Row("KV version", $"v{(int)reference.Version}");
            Row("Mount", reference.Mount);
            Row("Secret name", reference.Name);
            Row("Field", reference.Field);
        }
        var vaultBusy = store.IsVaultBusy(account);
        if (account.Kind == AccountKind.Secret)
        {
            Heading("Secret");
            var authenticate = new CheckBox
            {
                Text = "Ask to authenticate before it is shown or copied",
                Checked = account.RequiresAuthentication,
                AutoSize = true,
            };
            // The change is made after the event, since it rebuilds the page and the box with it.
            authenticate.CheckedChanged += (_, _) => BeginInvoke(() =>
            {
                try
                {
                    store.SetRequiresAuthentication(account, authenticate.Checked);
                }
                catch (Exception error) when (error is StoreException || AccountStore.IsStorageFailure(error))
                {
                    Dialogs.ShowError("The setting was not changed", error.Message, this);
                    ShowAccountDetails();
                }
            });
            Wide(authenticate);
            if (revealed is { } shown)
            {
                Wide(new TextBox { Text = shown.Value, ReadOnly = true, Font = fixedWidth, Dock = DockStyle.Fill });
            }
            var secretButtons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 12, 0, 0) };
            var reveal = new Button { Text = revealed is null ? "Reveal" : "Hide", AutoSize = true };
            reveal.Click += async (_, _) =>
            {
                if (revealed is not null)
                {
                    revealed = null;
                    ShowAccountDetails();
                    return;
                }
                try
                {
                    if (await store.RevealSecretAsync(account, this) is { } value)
                    {
                        revealed = (account.Id, value);
                    }
                }
                catch (OperationCanceledException)
                {
                    // The user cancelled the request.
                }
                catch (Exception error)
                {
                    Dialogs.ShowProblem("The secret was not read", error, this);
                }
                ShowAccountDetails();
            };
            var copySecret = new Button { Text = "Copy Secret", AutoSize = true, Enabled = !vaultBusy };
            copySecret.Click += async (_, _) => await Dialogs.CopySecretAsync(store, account, this);
            reveal.Enabled = !vaultBusy || revealed is not null;
            vaultActions.Add((reveal, revealed is not null));
            vaultActions.Add((copySecret, false));
            secretButtons.Controls.Add(reveal);
            secretButtons.Controls.Add(copySecret);
            Wide(secretButtons);
            accountDetails.Controls.Add(layout);
            accountDetails.ResumeLayout();
            return;
        }
        Heading("Code");
        Row("Algorithm", account.Algorithm.Name());
        Row("Digits", account.Digits.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Row("Period", $"{account.Period} s");

        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 12, 0, 0) };
        var show = new Button { Text = "Show Window", AutoSize = true };
        show.Click += (_, _) => showWindow(account);
        var copy = new Button { Text = "Copy Code", AutoSize = true, Enabled = !vaultBusy };
        vaultActions.Add((copy, false));
        copy.Click += async (_, _) =>
        {
            try
            {
                await store.CopyCodeAsync(account);
            }
            catch (OperationCanceledException)
            {
                // The user cancelled the request.
            }
            catch (Exception error)
            {
                Dialogs.ShowProblem("The code was not copied", error, this);
            }
        };
        buttons.Controls.Add(show);
        buttons.Controls.Add(copy);
        Wide(buttons);
        accountDetails.Controls.Add(layout);
        accountDetails.ResumeLayout();
    }

    /// <summary>The label, wrapped at the width of the account's page, and kept wrapped at it when the page is resized.</summary>
    private Label Wrapped(Label label, bool wide)
    {
        wrapping.Add((label, wide));
        WrapLabel(label, wide);
        return label;
    }

    /// <summary>
    /// Wraps a label at the width of the account's page: a label over both columns at the page less its margins, a
    /// value at the page less the column of names.
    /// </summary>
    private void WrapLabel(Label label, bool wide)
    {
        var width = accountDetails.ClientSize.Width - LogicalToDeviceUnits(wide ? 40 : 160);
        label.MaximumSize = new Size(Math.Max(width, LogicalToDeviceUnits(120)), 0);
    }

    private static Label Placeholder(string text) => new()
    {
        Text = text,
        Dock = DockStyle.Fill,
        TextAlign = ContentAlignment.MiddleCenter,
        ForeColor = SystemColors.GrayText,
    };

    /// <summary>Shows the page of the vault, a page for a new one, or the placeholder.</summary>
    private void ShowVaultPage(VaultSession? session, bool placeholder = false)
    {
        if (!placeholder && editor is not null && editor.Session == session && session is not null)
        {
            return;
        }
        vaultPage.SuspendLayout();
        foreach (Control control in vaultPage.Controls.Cast<Control>().ToList())
        {
            control.Dispose();
        }
        editor = null;
        if (placeholder)
        {
            vaultPage.Controls.Add(Placeholder("Select a vault, or add one."));
        }
        else
        {
            editor = new VaultEditor(store, session);
            editor.Saved += (_, _) =>
            {
                RefreshLists();
                if (editor?.Session is { } saved)
                {
                    SelectVault(saved);
                }
            };
            vaultPage.Controls.Add(editor);
        }
        removeVault.Enabled = editor?.Session is not null;
        vaultPage.ResumeLayout();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Icon?.Dispose();
            images.Dispose();
            addMenu.Dispose();
            bold.Dispose();
            fixedWidth.Dispose();
            activityTimer.Dispose();
            checkImage.Dispose();
        }
        base.Dispose(disposing);
    }
}
