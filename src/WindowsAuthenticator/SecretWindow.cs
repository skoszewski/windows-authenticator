using Totp;

namespace WindowsAuthenticator;

/// <summary>
/// A small window over the others for one secret account. The secret is masked until it is clicked; the click
/// reads it, after the Windows Hello verification its settings ask for, and shows it on one line with a bar and
/// the seconds left until it is masked again, or a Hide button when it is never hidden. A click on the shown
/// secret masks it again. Copy copies it, and a line says what happened, or why the secret is not shown. A secret
/// longer than <see cref="MaxShownLength"/> characters is not shown, only copied. The window can be resized; the
/// secret is fitted to its width with a smaller font, and showing a secret widens the window to it until the user
/// resizes it. The secret is dropped when it is masked and when the window closes.
/// </summary>
/// <remarks>
/// This window intentionally differs from Mac Authenticator, where Copy Secret in the menu copies at once: when the
/// secret asks for Windows Hello, Copy Secret in the tray menu copies here, since the Windows Hello prompt of a
/// desktop app needs a shown and active window of the app as its owner, and the tray menu has none.
/// </remarks>
internal sealed class SecretWindow : Form
{
    /// <summary>The secrets longer than this many characters are not shown in the window.</summary>
    public const int MaxShownLength = 64;

    private const float FontSize = 22f;
    private const float SmallestFontSize = 12f;
    private const int MinWidth = 240;
    private const int MaxAutoWidth = 520;

    private readonly AccountStore store;
    private readonly Guid accountId;
    private readonly Account opened;
    private readonly Font maskFont = new("Consolas", FontSize);
    private readonly Label masked = new()
    {
        Text = "********",
        AutoSize = true,
        Anchor = AnchorStyles.None,
        Cursor = Cursors.Hand,
        Margin = new Padding(0, 0, 0, 4),
    };
    private readonly TextBox field = new()
    {
        ReadOnly = true,
        ShortcutsEnabled = false,
        BorderStyle = BorderStyle.None,
        TextAlign = HorizontalAlignment.Center,
        Cursor = Cursors.Hand,
        Dock = DockStyle.Fill,
        Visible = false,
        Margin = new Padding(0, 4, 0, 8),
    };
    private readonly Label status = new() { AutoSize = true, Anchor = AnchorStyles.None, ForeColor = SystemColors.GrayText };
    private readonly ProgressBar bar = new() { Dock = DockStyle.Fill, Style = ProgressBarStyle.Continuous };
    private readonly Label seconds = new() { AutoSize = true, Anchor = AnchorStyles.Right, MinimumSize = new Size(36, 0), TextAlign = ContentAlignment.MiddleRight };
    private readonly Button hide = new() { Text = "Hide", AutoSize = true, Anchor = AnchorStyles.Right };
    private readonly Button copy = new() { Text = "Copy", AutoSize = true, Anchor = AnchorStyles.Right };
    private readonly TableLayoutPanel layout = new() { ColumnCount = 4, Dock = DockStyle.Fill };
    private readonly System.Windows.Forms.Timer countdown = new() { Interval = 1000 };
    private Font? valueFont;
    private string? value;
    private DateTimeOffset? hideAt;
    private int total;
    private bool tooLong;
    private bool busy;
    private bool userResized;
    private Size resizeStart;

    /// <param name="copyWhenShown">Whether the window copies the secret once it is shown, for Copy Secret.</param>
    public SecretWindow(AccountStore store, Account account, bool copyWhenShown)
    {
        this.store = store;
        accountId = account.Id;
        opened = account;
        Text = account.Name;
        FormBorderStyle = FormBorderStyle.SizableToolWindow;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        TopMost = true;
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;
        Padding = new Padding(12);
        masked.Font = maskFont;

        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (var i = 0; i < 3; i++)
        {
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        }
        // Fixed cells keep each control in its row while others are hidden.
        layout.Controls.Add(masked, 0, 0);
        layout.SetColumnSpan(masked, 4);
        layout.Controls.Add(field, 0, 1);
        layout.SetColumnSpan(field, 4);
        layout.Controls.Add(status, 0, 2);
        layout.SetColumnSpan(status, 4);
        layout.Controls.Add(bar, 0, 3);
        layout.Controls.Add(seconds, 1, 3);
        layout.Controls.Add(hide, 2, 3);
        layout.Controls.Add(copy, 3, 3);
        Controls.Add(layout);

        masked.Click += async (_, _) => await RevealAsync();
        field.Click += (_, _) => Conceal();
        hide.Click += (_, _) => Conceal();
        copy.Click += async (_, _) => await CopyAsync();
        countdown.Tick += (_, _) => ShowTimeLeft();
        ResizeBegin += (_, _) => resizeStart = Size;
        ResizeEnd += (_, _) => userResized |= Size != resizeStart;
        Resize += (_, _) => FitFont();
        store.Changed += StoreChanged;
        FormClosed += (_, _) =>
        {
            store.Changed -= StoreChanged;
            Conceal();
        };
        if (copyWhenShown)
        {
            Shown += async (_, _) => await CopyAsync();
        }
        ClientSize = new Size(LogicalToDeviceUnits(MinWidth), ClientSize.Height);
        ShowState();
        FitHeight();
    }

    public Guid AccountId => accountId;

    /// <summary>The account as the store holds it now, with its current settings.</summary>
    private Account Account => store.Accounts.FirstOrDefault(a => a.Id == accountId) ?? opened;

    private void StoreChanged(object? sender, EventArgs e) => ShowState();

    /// <summary>Reads the secret, after the verification its settings ask for, and shows it for its hide time.</summary>
    private async Task RevealAsync()
    {
        if (busy || value is not null)
        {
            return;
        }
        busy = true;
        ShowState();
        Exception? failure = null;
        try
        {
            var secret = await store.RevealSecretAsync(Account, this);
            if (secret is { Length: > MaxShownLength })
            {
                tooLong = true;
            }
            else if (secret is not null && !IsDisposed)
            {
                value = secret;
                field.Text = secret;
                total = Account.Settings.HideSeconds;
                hideAt = total > 0 ? DateTimeOffset.Now.AddSeconds(total) : null;
                countdown.Enabled = total > 0;
            }
        }
        catch (OperationCanceledException)
        {
            // The user cancelled the request.
        }
        catch (Exception error)
        {
            failure = error;
        }
        finally
        {
            busy = false;
        }
        if (IsDisposed)
        {
            return;
        }
        ShowState();
        FitWindow();
        if (failure is not null)
        {
            Say(failure);
        }
    }

    /// <summary>Copies the secret, after the verification its settings ask for; nothing happens when the user cancels.</summary>
    public async Task CopyAsync()
    {
        if (busy)
        {
            return;
        }
        busy = true;
        copy.Enabled = false;
        try
        {
            if (await store.CopySecretAsync(Account, this) && !IsDisposed)
            {
                status.ForeColor = SystemColors.GrayText;
                status.Text = "Copied; the clipboard is emptied after 30 seconds.";
            }
        }
        catch (OperationCanceledException)
        {
            // The user cancelled the request.
        }
        catch (Exception error)
        {
            Say(error);
        }
        finally
        {
            busy = false;
            if (!IsDisposed)
            {
                copy.Enabled = true;
            }
        }
    }

    /// <summary>Masks the secret again and drops it; the size of the window stays as it is.</summary>
    private void Conceal()
    {
        countdown.Enabled = false;
        value = null;
        field.Text = "";
        hideAt = null;
        total = 0;
        tooLong = false;
        if (!IsDisposed)
        {
            ShowState();
        }
    }

    /// <summary>Shows why the secret was not read or copied on the line under it.</summary>
    private void Say(Exception error)
    {
        if (IsDisposed)
        {
            return;
        }
        status.ForeColor = Color.Firebrick;
        status.Text = Dialogs.Describe(error);
        status.MaximumSize = new Size(Math.Max(ClientSize.Width - Padding.Horizontal, 120), 0);
        FitHeight();
    }

    /// <summary>Shows the masked or the shown secret, or why there is none, with the controls of that state.</summary>
    private void ShowState()
    {
        var problem = store.Problem(Account);
        var shown = value is not null;
        masked.Visible = !shown && !tooLong && problem is null;
        field.Visible = shown;
        bar.Visible = seconds.Visible = shown && total > 0;
        hide.Visible = shown && total == 0;
        status.MaximumSize = new Size(Math.Max(ClientSize.Width - Padding.Horizontal, 120), 0);
        status.ForeColor = problem is null ? SystemColors.GrayText : Color.Firebrick;
        status.Text = problem is not null ? $"{problem.Title}{Environment.NewLine}{problem.Suggestion}"
            : tooLong ? $"The secret is longer than {MaxShownLength} characters, so it is not shown."
            : busy && !shown ? "Reading the secret..."
            : shown ? ""
            : "Click to show";
        ShowTimeLeft();
        FitFont();
        FitHeight();
    }

    /// <summary>Shows the seconds left of a shown secret, and masks it when they are over.</summary>
    private void ShowTimeLeft()
    {
        if (hideAt is not { } until || total <= 0)
        {
            return;
        }
        var left = (int)Math.Ceiling((until - DateTimeOffset.Now).TotalSeconds);
        if (left <= 0)
        {
            Conceal();
            return;
        }
        bar.Maximum = total;
        bar.Value = Math.Min(left, total);
        seconds.Text = $"{left}s";
    }

    /// <summary>The width of the text on one line in Consolas of the size, in pixels.</summary>
    private static int LineWidth(string text, float size)
    {
        using var font = new Font("Consolas", size);
        return TextRenderer.MeasureText(text, font).Width;
    }

    /// <summary>Shows the secret in the largest font from the code's size down to the smallest that fits the width on one line.</summary>
    private void FitFont()
    {
        if (value is null)
        {
            return;
        }
        var room = Math.Max(field.ClientSize.Width, 1);
        var size = FontSize;
        while (size > SmallestFontSize && LineWidth(value, size) > room)
        {
            size -= 1f;
        }
        if (valueFont?.Size != size)
        {
            var previous = valueFont;
            valueFont = new Font("Consolas", size);
            field.Font = valueFont;
            previous?.Dispose();
        }
    }

    /// <summary>
    /// Widens the window to a shown secret on one line, up to a maximum, unless the user resized it, and keeps it
    /// from becoming narrower than the secret needs in the smallest font.
    /// </summary>
    private void FitWindow()
    {
        if (value is null)
        {
            return;
        }
        var chrome = Padding.Horizontal + LogicalToDeviceUnits(8);
        var smallest = Math.Max(LineWidth(value, SmallestFontSize) + chrome, LogicalToDeviceUnits(200));
        MinimumSize = SizeFromClientSize(new Size(smallest, 0)) with { Height = 0 };
        if (!userResized)
        {
            var ideal = Math.Clamp(LineWidth(value, FontSize) + chrome, LogicalToDeviceUnits(MinWidth), LogicalToDeviceUnits(MaxAutoWidth));
            ClientSize = new Size(Math.Max(ideal, smallest), ClientSize.Height);
        }
        FitFont();
        FitHeight();
    }

    /// <summary>Makes the window as tall as its contents, unless the user resized it.</summary>
    private void FitHeight()
    {
        if (userResized)
        {
            return;
        }
        var width = ClientSize.Width - Padding.Horizontal;
        var height = layout.GetPreferredSize(new Size(width, 0)).Height + Padding.Vertical;
        ClientSize = new Size(ClientSize.Width, height);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            countdown.Dispose();
            maskFont.Dispose();
            valueFont?.Dispose();
        }
        base.Dispose(disposing);
    }
}
