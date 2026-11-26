using Totp;
using Vault;

namespace WindowsAuthenticator;

/// <summary>
/// The app: its icon in the notification area, whose menu lists the accounts and the vaults with a problem, the
/// code windows and the Settings window. The menu holds no codes; the open code windows are refreshed at each
/// whole second, which also fetches the codes of Vault accounts.
/// </summary>
internal sealed class TrayContext : ApplicationContext
{
    /// <summary>The longest text of a notification area icon's tooltip.</summary>
    private const int TooltipLength = 127;

    private readonly AccountStore store = new();
    private readonly ContextMenuStrip menu = new();
    private readonly NotifyIcon icon;
    private readonly Icon plainIcon;
    private readonly Icon warningIcon;
    private readonly Bitmap warningImage;
    private readonly Dictionary<Guid, CodeWindow> windows = [];
    private readonly System.Windows.Forms.Timer timer = new();
    private readonly SettingsWindow settings;
    private Guid? balloonVault;

    public TrayContext()
    {
        plainIcon = AppIcon.Load(SystemInformation.SmallIconSize);
        warningIcon = AppIcon.LoadWithWarning(SystemInformation.SmallIconSize);
        using (var warning = new Icon(SystemIcons.Warning, SystemInformation.SmallIconSize))
        {
            warningImage = warning.ToBitmap();
        }
        settings = new SettingsWindow(store, Show);
        icon = new NotifyIcon
        {
            Icon = plainIcon,
            Text = Dialogs.AppName,
            ContextMenuStrip = menu,
        };
        menu.Opening += (_, _) => BuildMenu();
        icon.DoubleClick += (_, _) => settings.Present();
        icon.BalloonTipClicked += (_, _) => settings.Present(balloonVault);
        store.Changed += (_, _) =>
        {
            CloseRemovedWindows();
            ShowProblems();
        };
        store.VaultProblemRaised += (_, issue) => Notify(issue);
        BuildMenu();
        ShowProblems();
        icon.Visible = true;

        timer.Tick += (_, _) =>
        {
            var now = DateTimeOffset.Now;
            timer.Interval = 1000 - now.Millisecond;
            store.Tick(now);
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
        var problems = store.Problems;
        foreach (var issue in problems)
        {
            var id = issue.Session.Profile.Id;
            menu.Items.Add(Escaped($"Vault {issue.Session.Profile.Name}: {issue.Problem.Title}"), warningImage,
                           (_, _) => settings.Present(id));
        }
        if (problems.Count > 0)
        {
            menu.Items.Add(new ToolStripSeparator());
        }
        if (store.LoadError is { } loadError)
        {
            menu.Items.Add(new ToolStripMenuItem(Escaped(loadError)) { Enabled = false });
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
                var submenu = new ToolStripMenuItem(Escaped(account.Name));
                if (account.Kind == AccountKind.Secret)
                {
                    submenu.DropDownItems.Add("Copy Secret", null, async (_, _) => await Dialogs.CopySecretAsync(store, account));
                }
                else
                {
                    submenu.DropDownItems.Add("Copy Code", null, async (_, _) => await CopyCodeAsync(account));
                    submenu.DropDownItems.Add("Show", null, (_, _) => Show(account));
                }
                menu.Items.Add(submenu);
            }
        }

        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Settings...", null, (_, _) => settings.Present());
        var launch = new ToolStripMenuItem("Launch at Login") { Checked = Settings.LaunchesAtLogin };
        launch.Click += (_, _) => SetLaunchesAtLogin(!launch.Checked);
        menu.Items.Add(launch);
        menu.Items.Add($"About {Dialogs.AppName}", null, (_, _) => Dialogs.ShowAbout());
        menu.Items.Add($"Quit {Dialogs.AppName}", null, (_, _) => ExitThread());
    }

    /// <summary>The text with its ampersands doubled, so a menu shows them.</summary>
    private static string Escaped(string text) => text.Replace("&", "&&");

    /// <summary>Shows the warning sign on the icon, and the first problem in its tooltip, while a vault has a problem.</summary>
    private void ShowProblems()
    {
        var problems = store.Problems;
        icon.Icon = problems.Count == 0 ? plainIcon : warningIcon;
        var text = problems.Count == 0
            ? Dialogs.AppName
            : $"{Dialogs.AppName}\nVault {problems[0].Session.Profile.Name}: {problems[0].Problem.Title}";
        icon.Text = text.Length > TooltipLength ? text[..TooltipLength] : text;
    }

    /// <summary>Tells of a vault that worked and fails; clicking the notification opens the vault in Settings.</summary>
    private void Notify(VaultIssue issue)
    {
        static string Cut(string text, int length) => text.Length > length ? text[..(length - 3)] + "..." : text;

        balloonVault = issue.Session.Profile.Id;
        icon.ShowBalloonTip(10000, Cut($"Vault {issue.Session.Profile.Name}: {issue.Problem.Title}", 63),
                            Cut(issue.Problem.Suggestion, 200), ToolTipIcon.Warning);
    }

    private async Task CopyCodeAsync(Account account)
    {
        try
        {
            await store.CopyCodeAsync(account);
        }
        catch (Exception failure)
        {
            Dialogs.ShowProblem("The code was not copied", failure);
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
        settings.Quit();
        foreach (var session in store.Vaults)
        {
            session.SignOut();
        }
        icon.Visible = false;
        base.ExitThreadCore();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            timer.Dispose();
            icon.Dispose();
            plainIcon.Dispose();
            warningIcon.Dispose();
            warningImage.Dispose();
            settings.Dispose();
            menu.Dispose();
        }
        base.Dispose(disposing);
    }
}
