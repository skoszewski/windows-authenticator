using System.Runtime.InteropServices;
using Totp;

namespace WindowsAuthenticator;

/// <summary>
/// The app: its icon in the notification area, whose menu lists the accounts, and the code windows. The
/// menu holds no codes; the open code windows are refreshed at each whole second.
/// </summary>
internal sealed class TrayContext : ApplicationContext
{
    private readonly AccountStore store = new();
    private readonly ContextMenuStrip menu = new();
    private readonly NotifyIcon icon;
    private readonly Dictionary<Guid, CodeWindow> windows = [];
    private readonly System.Windows.Forms.Timer timer = new();

    public TrayContext()
    {
        icon = new NotifyIcon
        {
            Icon = AppIcon.Load(SystemInformation.SmallIconSize),
            Text = Dialogs.AppName,
            ContextMenuStrip = menu,
        };
        menu.Opening += (_, _) => BuildMenu();
        store.AccountsChanged += (_, _) => CloseRemovedWindows();
        BuildMenu();
        icon.Visible = true;

        timer.Tick += (_, _) =>
        {
            var now = DateTimeOffset.Now;
            timer.Interval = 1000 - now.Millisecond;
            foreach (var window in windows.Values)
            {
                window.ShowCode(now);
            }
        };
        timer.Interval = 1000 - DateTimeOffset.Now.Millisecond;
        timer.Start();
    }

    /// <summary>Fills the menu from the store; called each time it opens.</summary>
    private void BuildMenu()
    {
        menu.Items.Clear();
        if (store.LoadError is { } loadError)
        {
            menu.Items.Add(new ToolStripMenuItem(loadError) { Enabled = false });
            menu.Items.Add("Retry", null, (_, _) => store.Reload());
        }
        else if (store.Accounts.Count == 0)
        {
            menu.Items.Add(new ToolStripMenuItem("No Accounts") { Enabled = false });
        }
        else
        {
            foreach (var account in store.Accounts)
            {
                var submenu = new ToolStripMenuItem(account.Name.Replace("&", "&&"));
                submenu.DropDownItems.Add("Copy Code", null, (_, _) => CopyCode(account));
                submenu.DropDownItems.Add("Show", null, (_, _) => Show(account));
                submenu.DropDownItems.Add("Remove", null, (_, _) => Dialogs.RemoveAccount(account, store));
                menu.Items.Add(submenu);
            }
        }

        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Add Account...", null, (_, _) => Dialogs.AddAccount(store));
        menu.Items.Add("Add Account from QR Code in Clipboard", null, (_, _) => Dialogs.AddAccountFromClipboard(store));

        menu.Items.Add(new ToolStripSeparator());
        var launch = new ToolStripMenuItem("Launch at Login") { Checked = Settings.LaunchesAtLogin };
        launch.Click += (_, _) => SetLaunchesAtLogin(!launch.Checked);
        menu.Items.Add(launch);
        menu.Items.Add($"About {Dialogs.AppName}", null, (_, _) => Dialogs.ShowAbout());
        menu.Items.Add($"Quit {Dialogs.AppName}", null, (_, _) => ExitThread());
    }

    private void CopyCode(Account account)
    {
        try
        {
            store.CopyCode(account);
        }
        catch (Exception failure) when (failure is CredentialStoreException or ExternalException)
        {
            Dialogs.ShowError("The code was not copied", failure.Message);
        }
    }

    /// <summary>Brings the account's code window to the front, making it if it is not open.</summary>
    private void Show(Account account)
    {
        if (windows.TryGetValue(account.Id, out var open))
        {
            open.TopMost = true;
            open.BringToFront();
            return;
        }
        store.SetWindowOpen(account.Id, true);
        var window = new CodeWindow(store, account);
        window.FormClosed += (_, _) =>
        {
            windows.Remove(account.Id);
            store.SetWindowOpen(account.Id, false);
            window.Dispose();
        };
        windows[account.Id] = window;
        window.Show();
    }

    /// <summary>Closes the windows of accounts no longer registered.</summary>
    private void CloseRemovedWindows()
    {
        var ids = store.Accounts.Select(a => a.Id).ToHashSet();
        foreach (var window in windows.Values.Where(w => !ids.Contains(w.AccountId)).ToList())
        {
            window.Close();
        }
    }

    private static void SetLaunchesAtLogin(bool enabled)
    {
        try
        {
            Settings.LaunchesAtLogin = enabled;
        }
        catch (Exception failure) when (failure is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            Dialogs.ShowError("Launch at Login was not changed", failure.Message);
        }
    }

    protected override void ExitThreadCore()
    {
        timer.Stop();
        foreach (var window in windows.Values.ToList())
        {
            window.Close();
        }
        icon.Visible = false;
        base.ExitThreadCore();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            timer.Dispose();
            icon.Icon?.Dispose();
            icon.Dispose();
            menu.Dispose();
        }
        base.Dispose(disposing);
    }
}
