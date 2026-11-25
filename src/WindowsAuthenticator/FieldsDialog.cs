namespace WindowsAuthenticator;

/// <summary>
/// A dialog of labelled fields under a line of information, with an accept button and Cancel. It stays open
/// until the accept action succeeds or Cancel is chosen, and shows why the action failed in place of the
/// information.
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

        Information = new Label { Text = information, AutoSize = true, MaximumSize = new Size(FieldWidth, 0) };
        layout.Controls.Add(Information);
        Controls.Add(layout);

        accept = new Button { Text = acceptText, AutoSize = true };
        accept.Click += async (_, _) => await AcceptAsync();
        if (cancellable)
        {
            var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
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

    /// <summary>The action of the accept button; true closes the dialog.</summary>
    protected Func<Task<bool>>? Accepting { get; set; }

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

    /// <summary>Adds a control under the fields.</summary>
    protected void AddControl(Control control) => layout.Controls.Add(control);

    /// <summary>Adds a button left of the accept button.</summary>
    protected Button AddButton(string text)
    {
        var button = new Button { Text = text, AutoSize = true };
        buttons.Controls.Add(button);
        return button;
    }

    protected override void OnLoad(EventArgs e)
    {
        layout.Controls.Add(buttons);
        base.OnLoad(e);
    }

    /// <summary>Runs the accept action with the button disabled, and shows why it failed.</summary>
    private async Task AcceptAsync()
    {
        if (Accepting is null)
        {
            DialogResult = DialogResult.OK;
            return;
        }
        accept.Enabled = false;
        UseWaitCursor = true;
        try
        {
            if (await Accepting())
            {
                DialogResult = DialogResult.OK;
            }
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
            if (!IsDisposed)
            {
                accept.Enabled = true;
                UseWaitCursor = false;
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
