namespace WindowsAuthenticator;

/// <summary>
/// A dialog of labelled fields under a line of information, with an accept button and Cancel. It stays open
/// until the accept action succeeds or Cancel is chosen, and shows why the action failed in place of the
/// information. While the action runs the accept button is disabled, Cancel reads Cancel Request and cancels it,
/// and a line with a progress bar says what is done.
/// </summary>
internal class FieldsDialog : Form
{
    protected const int FieldWidth = 360;

    private readonly TableLayoutPanel layout = new()
    {
        AutoSize = true,
        AutoSizeMode = AutoSizeMode.GrowAndShrink,
        ColumnCount = 1,
        Dock = DockStyle.Fill,
    };
    private readonly FlowLayoutPanel buttons = new()
    {
        AutoSize = true,
        FlowDirection = FlowDirection.RightToLeft,
        Dock = DockStyle.Fill,
        Margin = new Padding(0, 12, 0, 0),
    };
    private readonly Button accept;
    private readonly Button? cancel;
    private readonly FlowLayoutPanel progressRow = new() { AutoSize = true, Visible = false, Margin = new Padding(0, 10, 0, 0) };
    private readonly Label progressLabel = new() { AutoSize = true, Anchor = AnchorStyles.Left };
    private readonly string idleInformation;
    private CancellationTokenSource? running;
    private string cancelText = "Cancel";

    protected FieldsDialog(string title, string information, string acceptText, bool cancellable = true)
    {
        Text = title;
        Icon = AppIcon.Load(SystemInformation.IconSize);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = true;
        StartPosition = FormStartPosition.CenterScreen;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        AutoScaleMode = AutoScaleMode.Dpi;
        Padding = new Padding(12);

        idleInformation = information;
        Information = new Label { Text = information, AutoSize = true, MaximumSize = new Size(FieldWidth, 0) };
        layout.Controls.Add(Information);
        Controls.Add(layout);

        accept = new Button { Text = acceptText, AutoSize = true };
        accept.Click += async (_, _) => await AcceptAsync();
        if (cancellable)
        {
            cancel = new Button { Text = "Cancel", AutoSize = true };
            cancel.Click += (_, _) =>
            {
                if (running is { } call)
                {
                    call.Cancel();
                }
                else
                {
                    DialogResult = DialogResult.Cancel;
                }
            };
            buttons.Controls.Add(cancel);
            CancelButton = cancel;
        }
        buttons.Controls.Add(accept);
        AcceptButton = accept;
        Shown += (_, _) =>
        {
            Activate();
            InitialFocus?.Focus();
        };
    }

    /// <summary>The line above the fields: the purpose of the dialog, or why the last attempt failed.</summary>
    protected Label Information { get; }

    /// <summary>The action of the accept button, cancelled by Cancel Request; true closes the dialog.</summary>
    protected Func<CancellationToken, Task<bool>>? Accepting { get; set; }

    /// <summary>The field that has the keyboard when the dialog opens.</summary>
    protected Control? InitialFocus { get; set; }

    /// <summary>Adds the field under its label.</summary>
    protected T AddField<T>(string label, T field) where T : Control
    {
        layout.Controls.Add(new Label { Text = label, AutoSize = true, Margin = new Padding(3, 10, 3, 0) });
        field.Width = FieldWidth;
        layout.Controls.Add(field);
        return field;
    }

    /// <summary>Adds a grey line of text under the last field.</summary>
    protected Label AddHint(string text)
    {
        var hint = new Label { Text = text, AutoSize = true, ForeColor = SystemColors.GrayText, MaximumSize = new Size(FieldWidth, 0) };
        layout.Controls.Add(hint);
        return hint;
    }

    /// <summary>Says what the running action does now, on the line with the progress bar.</summary>
    protected void Progress(string text)
    {
        progressLabel.Text = text + "...";
        progressRow.Visible = true;
    }

    /// <summary>Leaves the dialog open with a question, which the accept button, renamed, answers.</summary>
    protected void Ask(string text, string acceptText)
    {
        Information.Text = text;
        accept.Text = acceptText;
    }

    /// <summary>Adds a control under the fields.</summary>
    protected void AddControl(Control control) => layout.Controls.Add(control);

    /// <summary>Renames the accept button and the Cancel button.</summary>
    protected void RenameButtons(string acceptText, string cancelText)
    {
        accept.Text = acceptText;
        this.cancelText = cancelText;
        if (cancel is not null && running is null)
        {
            cancel.Text = cancelText;
        }
    }

    /// <summary>Adds a button left of the accept button.</summary>
    protected Button AddButton(string text)
    {
        var button = new Button { Text = text, AutoSize = true };
        buttons.Controls.Add(button);
        return button;
    }

    protected override void OnLoad(EventArgs e)
    {
        progressRow.Controls.Add(new ProgressBar
        {
            Style = ProgressBarStyle.Marquee,
            Width = LogicalToDeviceUnits(80),
            Height = LogicalToDeviceUnits(14),
            Anchor = AnchorStyles.Left,
        });
        progressRow.Controls.Add(progressLabel);
        layout.Controls.Add(progressRow);
        layout.Controls.Add(buttons);
        base.OnLoad(e);
    }

    /// <summary>A window closed while the action runs cancels the action.</summary>
    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        running?.Cancel();
        base.OnFormClosing(e);
    }

    /// <summary>Runs the accept action with the button disabled, and shows why it failed.</summary>
    private async Task AcceptAsync()
    {
        if (Accepting is null)
        {
            DialogResult = DialogResult.OK;
            return;
        }
        if (running is not null)
        {
            return;
        }
        using var source = new CancellationTokenSource();
        running = source;
        accept.Enabled = false;
        if (cancel is not null)
        {
            cancel.Text = "Cancel Request";
        }
        try
        {
            if (await Accepting(source.Token))
            {
                DialogResult = DialogResult.OK;
            }
        }
        catch (OperationCanceledException) when (source.IsCancellationRequested && !IsDisposed)
        {
            Information.Text = idleInformation;
        }
        catch (Exception error) when (!IsDisposed)
        {
            Information.Text = Dialogs.Describe(error);
        }
        catch (Exception)
        {
            // The dialog was cancelled while the action ran; nobody is left to tell.
        }
        finally
        {
            running = null;
            if (!IsDisposed)
            {
                accept.Enabled = true;
                progressRow.Visible = false;
                if (cancel is not null)
                {
                    cancel.Text = cancelText;
                }
            }
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Icon?.Dispose();
        }
        base.Dispose(disposing);
    }
}
