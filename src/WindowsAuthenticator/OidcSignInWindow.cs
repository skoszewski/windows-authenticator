using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using Vault;

namespace WindowsAuthenticator;

/// <summary>
/// One OIDC sign-in, in a window of the app: a WebView2 loads the identity provider's pages, and the redirect to
/// the redirect URI ends the sign-in without being loaded, so nothing listens on its port. The window closes
/// itself when the sign-in ends; a modeless form is disposed when it closes.
/// </summary>
internal sealed class OidcSignInWindow : Form
{
    /// <summary>The WebView2 user data folder, which keeps the identity provider's cookies apart from Edge's.</summary>
    private static readonly string UserDataFolder = Path.Combine(Settings.DataFolder, "WebView2");

    private readonly WebView2 view = new() { Dock = DockStyle.Fill };
    private readonly Label host = new() { AutoSize = true, Margin = new Padding(12, 8, 12, 0) };
    private readonly Label error = new()
    {
        AutoSize = true,
        ForeColor = Color.Firebrick,
        Margin = new Padding(12, 4, 12, 0),
        Visible = false,
    };
    private readonly System.Windows.Forms.Timer timeout = new() { Interval = (int)TimeSpan.FromMinutes(5).TotalMilliseconds };
    private readonly TaskCompletionSource<OidcCallback> result = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Font bold;
    private OidcSignInPolicy? policy;

    public OidcSignInWindow()
    {
        Icon = AppIcon.Load(SystemInformation.IconSize);
        ShowInTaskbar = true;
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;
        Size = LogicalToDeviceUnits(new Size(520, 700));
        bold = new Font(Font, FontStyle.Bold);
        host.Font = bold;

        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        // Fixed cells keep the view in the filling row while the error line is hidden.
        layout.Controls.Add(host, 0, 0);
        layout.Controls.Add(error, 0, 1);
        view.Margin = new Padding(0, 8, 0, 0);
        layout.Controls.Add(view, 0, 2);
        Controls.Add(layout);

        ClientSizeChanged += (_, _) => error.MaximumSize = new Size(Math.Max(ClientSize.Width - 24, 1), 0);
        timeout.Tick += (_, _) => End(() => result.TrySetException(VaultException.Oidc("The sign-in did not finish in time.")));
        FormClosed += (_, _) =>
        {
            timeout.Stop();
            result.TrySetCanceled();
        };
    }

    /// <summary>
    /// Opens the window on the authorisation URL and returns what the identity provider sent to the redirect URI;
    /// closing the window cancels the sign-in.
    /// </summary>
    public async Task<OidcCallback> RunAsync(Uri url, Uri redirect, string title)
    {
        try
        {
            CoreWebView2Environment.GetAvailableBrowserVersionString();
        }
        catch (WebView2RuntimeNotFoundException)
        {
            Dispose();
            throw SessionException.NoWebView2Runtime();
        }
        policy = new OidcSignInPolicy(redirect);
        Text = title;
        Show();
        Activate();
        timeout.Start();
        try
        {
            var environment = await CoreWebView2Environment.CreateAsync(null, UserDataFolder);
            await view.EnsureCoreWebView2Async(environment);
            if (!result.Task.IsCompleted)
            {
                var core = view.CoreWebView2;
                core.NavigationStarting += Decide;
                core.FrameNavigationStarting += Decide;
                // A page that opens a window, such as a provider's multi-factor step, loads in the same view.
                core.NewWindowRequested += (_, e) =>
                {
                    e.Handled = true;
                    core.Navigate(e.Uri);
                };
                core.SourceChanged += (_, _) =>
                    host.Text = Uri.TryCreate(core.Source, UriKind.Absolute, out var page) ? page.Host : "";
                // A certificate the Windows store does not trust fails the load, which the error line explains.
                core.ServerCertificateErrorDetected += (_, e) => e.Action = CoreWebView2ServerCertificateErrorAction.Cancel;
                core.NavigationCompleted += ShowLoadError;
                core.Navigate(url.AbsoluteUri);
            }
        }
        catch (Exception failure) when (!result.Task.IsCompleted)
        {
            End(() => result.TrySetException(failure));
        }
        return await result.Task;
    }

    /// <summary>Closes the window and ends the sign-in as cancelled.</summary>
    public void Cancel() => End(() => result.TrySetCanceled());

    /// <summary>Ends the sign-in once with the outcome, and closes the window after the current event.</summary>
    private void End(Action complete)
    {
        timeout.Stop();
        complete();
        if (IsHandleCreated && !IsDisposed)
        {
            BeginInvoke(() =>
            {
                if (!IsDisposed)
                {
                    Close();
                }
            });
        }
    }

    /// <summary>Lets a navigation of the page or of a frame happen, ends the sign-in with it, or refuses it.</summary>
    private void Decide(object? sender, CoreWebView2NavigationStartingEventArgs e)
    {
        if (result.Task.IsCompleted || policy is null)
        {
            e.Cancel = true;
            return;
        }
        switch (policy.Decide(e.Uri))
        {
            case OidcNavigation.Callback callback:
                e.Cancel = true;
                End(() => result.TrySetResult(callback.Value));
                break;
            case OidcNavigation.Allow:
                error.Visible = false;
                break;
            case OidcNavigation.Block block:
                e.Cancel = true;
                error.Text = block.Reason;
                error.Visible = true;
                break;
        }
    }

    /// <summary>Shows what went wrong with a load, in words; a navigation that was cancelled or asks for a login is not one.</summary>
    private void ShowLoadError(object? sender, CoreWebView2NavigationCompletedEventArgs e)
    {
        if (e.IsSuccess || e.WebErrorStatus is CoreWebView2WebErrorStatus.OperationCanceled
                                             or CoreWebView2WebErrorStatus.ValidAuthenticationCredentialsRequired
                                             or CoreWebView2WebErrorStatus.ValidProxyAuthenticationRequired)
        {
            return;
        }
        var (title, suggestion) = e.WebErrorStatus switch
        {
            CoreWebView2WebErrorStatus.CertificateCommonNameIsIncorrect =>
                ("The page's certificate is for another name", "Check the address of the identity provider."),
            CoreWebView2WebErrorStatus.CertificateExpired =>
                ("The page's certificate is expired or not yet valid", "Renew the certificate; check the date of this computer."),
            CoreWebView2WebErrorStatus.CertificateIsInvalid or CoreWebView2WebErrorStatus.CertificateRevoked
                or CoreWebView2WebErrorStatus.ClientCertificateContainsErrors =>
                ("The page's certificate is not trusted", "Trust the issuing CA in the Windows certificate store."),
            CoreWebView2WebErrorStatus.HostNameNotResolved =>
                ("The page's name does not resolve", "Check the network and the VPN."),
            CoreWebView2WebErrorStatus.CannotConnect or CoreWebView2WebErrorStatus.ServerUnreachable
                or CoreWebView2WebErrorStatus.ConnectionAborted or CoreWebView2WebErrorStatus.ConnectionReset =>
                ("Nothing answers at the page's address", "Check the network, any firewall and the VPN."),
            CoreWebView2WebErrorStatus.Timeout =>
                ("The page did not answer in time", "Check that the identity provider is reachable, and the VPN."),
            CoreWebView2WebErrorStatus.Disconnected =>
                ("The network is down", "Connect to the network or the VPN."),
            _ => ("The page could not be loaded", "Try again; check the OIDC role and the identity provider."),
        };
        error.Text = $"{title}. {suggestion}";
        error.Visible = true;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            timeout.Dispose();
            bold.Dispose();
            Icon?.Dispose();
        }
        base.Dispose(disposing);
    }
}
