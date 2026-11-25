using Totp;

namespace WindowsAuthenticator;

/// <summary>
/// A small window over the others showing one account's code, the time left of it and a Copy button, or
/// why the code cannot be shown. It does not take activation, so Copy leaves the other app in front.
/// </summary>
internal sealed class CodeWindow : Form
{
    private readonly AccountStore store;
    private readonly Account account;
    private readonly Label code = new()
    {
        AutoSize = true,
        Anchor = AnchorStyles.None,
        Font = new Font("Consolas", 22f),
        Margin = new Padding(0, 0, 0, 6),
    };
    private readonly ProgressBar bar = new() { Dock = DockStyle.Fill, Style = ProgressBarStyle.Continuous };
    private readonly Label seconds = new()
    {
        AutoSize = true,
        Anchor = AnchorStyles.Right,
        TextAlign = ContentAlignment.MiddleRight,
        MinimumSize = new Size(36, 0),
    };
    private readonly Button copy = new() { Text = "Copy", AutoSize = true, Anchor = AnchorStyles.Right };
    private readonly Label error = new() { AutoSize = true, MaximumSize = new Size(260, 0), Visible = false };

    public CodeWindow(AccountStore store, Account account)
    {
        this.store = store;
        this.account = account;
        Text = account.Name;
        FormBorderStyle = FormBorderStyle.FixedToolWindow;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        TopMost = true;
        StartPosition = FormStartPosition.CenterScreen;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        AutoScaleMode = AutoScaleMode.Dpi;
        Padding = new Padding(12);

        var layout = new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 3,
            Dock = DockStyle.Fill,
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        layout.Controls.Add(code, 0, 0);
        layout.SetColumnSpan(code, 3);
        layout.Controls.Add(bar, 0, 1);
        layout.Controls.Add(seconds, 1, 1);
        layout.Controls.Add(copy, 2, 1);
        layout.Controls.Add(error, 0, 2);
        layout.SetColumnSpan(error, 3);
        Controls.Add(layout);

        copy.Click += async (_, _) =>
        {
            try
            {
                await store.CopyCodeAsync(account);
            }
            catch (Exception failure)
            {
                Dialogs.ShowProblem("The code was not copied", failure);
            }
        };
        bar.Maximum = account.Period;
        ShowCode(DateTimeOffset.Now);
    }

    public Guid AccountId => account.Id;

    protected override bool ShowWithoutActivation => true;

    protected override CreateParams CreateParams
    {
        get
        {
            var parameters = base.CreateParams;
            parameters.ExStyle |= NativeMethods.WsExNoActivate;
            return parameters;
        }
    }

    /// <summary>
    /// Shows the code of the given time, or why there is none: the problem of the account's vault, a code not
    /// yet fetched, or a secret not read.
    /// </summary>
    public void ShowCode(DateTimeOffset now)
    {
        var current = store.Code(account, now);
        var shown = current is not null;
        code.Visible = bar.Visible = seconds.Visible = copy.Visible = shown;
        error.Visible = !shown;
        if (current is null)
        {
            error.Text = store.Problem(account) is { } problem
                ? $"{problem.Title}{Environment.NewLine}{problem.Suggestion}"
                : store.VaultKeyOf(account) is not null
                    ? "The code is fetched from Vault."
                    : store.SecretError(account.Id) ?? "The secret is not read.";
            return;
        }
        var left = account.SecondsLeft(now);
        code.Text = Grouped(current);
        bar.Value = left;
        seconds.Text = $"{left}s";
    }

    /// <summary>The code in two groups of digits, the second one the longer for an odd count.</summary>
    private static string Grouped(string code) => $"{code[..(code.Length / 2)]} {code[(code.Length / 2)..]}";
}
