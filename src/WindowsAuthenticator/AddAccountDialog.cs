using Totp;

namespace WindowsAuthenticator;

/// <summary>Asks for a name and a secret or otpauth URI until an account is added or Cancel is chosen.</summary>
internal sealed class AddAccountDialog : Form
{
    private const string Hint = "The secret is kept in Windows Credential Manager.";

    public AddAccountDialog(AccountStore store, string name = "", string input = "")
    {
        Text = "Add Account";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = true;
        TopMost = true;
        StartPosition = FormStartPosition.CenterScreen;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        AutoScaleMode = AutoScaleMode.Dpi;
        Padding = new Padding(12);

        var nameField = new TextBox
        {
            Text = name,
            Width = 340,
            PlaceholderText = "Name, or empty to take it from the URI",
        };
        var secretField = new TextBox
        {
            Text = input,
            Width = 340,
            UseSystemPasswordChar = true,
            PlaceholderText = "Base32 secret or otpauth://totp/... URI",
        };
        var information = new Label { Text = Hint, AutoSize = true, MaximumSize = new Size(340, 0) };
        var add = new Button { Text = "Add", AutoSize = true };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        var buttons = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
            Margin = new Padding(0, 8, 0, 0),
        };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(add);

        var layout = new TableLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 1,
            Dock = DockStyle.Fill,
        };
        layout.Controls.Add(information);
        layout.Controls.Add(new Label { Text = "Name", AutoSize = true, Margin = new Padding(3, 10, 3, 0) });
        layout.Controls.Add(nameField);
        layout.Controls.Add(new Label { Text = "Secret or otpauth URI", AutoSize = true, Margin = new Padding(3, 10, 3, 0) });
        layout.Controls.Add(secretField);
        layout.Controls.Add(buttons);
        Controls.Add(layout);
        AcceptButton = add;
        CancelButton = cancel;

        add.Click += (_, _) =>
        {
            try
            {
                store.Add(OtpAuth.Parse(nameField.Text, secretField.Text));
                DialogResult = DialogResult.OK;
            }
            catch (Exception failure) when (failure is TotpException or StoreException or CredentialStoreException)
            {
                information.Text = failure.Message;
            }
        };
        Shown += (_, _) =>
        {
            Activate();
            (name.Length == 0 && input.Length == 0 ? nameField : secretField).Focus();
        };
    }
}
