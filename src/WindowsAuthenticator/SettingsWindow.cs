using Totp;
using Vault;

namespace WindowsAuthenticator;

/// <summary>
/// The Settings window, made once and hidden when closed: the Accounts tab, a list of all accounts with the
/// details of the selected one, and the Vaults tab, a list of the vaults with the page of the selected one.
/// </summary>
internal sealed class SettingsWindow : Form
{
    private const string WarningImage = "warning";

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
        accounts.SmallImageList = images;
        vaults.SmallImageList = images;
        accounts.Columns.Add("Account", 170);
        accounts.Columns.Add("Store", 130);
        vaults.Columns.Add("Vault", 200);

        addMenu.Items.Add("Account...", null, (_, _) => Dialogs.AddAccount(store, this));
        addMenu.Items.Add("From QR Code in Clipboard", null, (_, _) => Dialogs.AddAccountFromClipboard(store, this));
        addMenu.Items.Add(new ToolStripSeparator());
        var fromVault = addMenu.Items.Add("From Vault...", null, async (_, _) => await Dialogs.AddFromVaultAsync(store, this));
        var generate = addMenu.Items.Add("Generate in Vault...", null, async (_, _) => await Dialogs.GenerateAccountAsync(store, this));
        var import = addMenu.Items.Add("Import to Vault...", null, async (_, _) => await Dialogs.ImportAccountAsync(store, this));
        addMenu.Opening += (_, _) => fromVault.Enabled = generate.Enabled = import.Enabled = store.Vaults.Count > 0;
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

    /// <summary>The list with its buttons under it on the left, and the details on the right.</summary>
    private static SplitContainer Split(ListView list, Button add, Button remove, Control details)
    {
        var split = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel1, SplitterDistance = 300 };
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
            item.ImageKey = store.Problem(account) is null ? "" : WarningImage;
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
        removeAccount.Enabled = account is not null;
        accountDetails.SuspendLayout();
        foreach (Control control in accountDetails.Controls.Cast<Control>().ToList())
        {
            control.Dispose();
        }
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
            layout.Controls.Add(new Label { Text = value, AutoSize = true, MaximumSize = new Size(380, 0) });
        }
        void Wide(Control control)
        {
            layout.Controls.Add(control);
            layout.SetColumnSpan(control, 2);
        }

        var vaultKey = store.VaultKeyOf(account);
        if (store.Problem(account) is { } problem)
        {
            Heading("Problem");
            Wide(new Label { Text = problem.Title, AutoSize = true, ForeColor = Color.Firebrick });
            Wide(new Label { Text = problem.Detail, AutoSize = true, MaximumSize = new Size(480, 0) });
            Wide(new Label { Text = problem.Suggestion, AutoSize = true, MaximumSize = new Size(480, 0), ForeColor = SystemColors.GrayText });
            if (vaultKey is not null && store.Vault(vaultKey.Profile) is not null)
            {
                var showVault = new Button { Text = "Show Vault", AutoSize = true };
                showVault.Click += (_, _) => Present(vaultKey.Profile);
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
        Heading("Code");
        Row("Algorithm", account.Algorithm.Name());
        Row("Digits", account.Digits.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Row("Period", $"{account.Period} s");

        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 12, 0, 0) };
        var show = new Button { Text = "Show Window", AutoSize = true };
        show.Click += (_, _) => showWindow(account);
        var copy = new Button { Text = "Copy Code", AutoSize = true };
        copy.Click += async (_, _) =>
        {
            try
            {
                await store.CopyCodeAsync(account);
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
        }
        base.Dispose(disposing);
    }
}
