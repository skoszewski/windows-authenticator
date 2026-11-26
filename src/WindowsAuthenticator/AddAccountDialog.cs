using Totp;

namespace WindowsAuthenticator;

/// <summary>Asks for a name and a secret or otpauth URI until an account is added or Cancel is chosen.</summary>
internal sealed class AddAccountDialog : FieldsDialog
{
    public AddAccountDialog(AccountStore store, string input = "")
        : base("Add Account", "The secret is kept in Windows Credential Manager.", "Add")
    {
        var name = AddField("Name", new TextBox { PlaceholderText = "Name, or empty to take it from the URI" });
        var secret = AddField("Secret or otpauth URI", new TextBox
        {
            Text = input,
            UseSystemPasswordChar = true,
            PlaceholderText = "Base32 secret or otpauth://totp/... URI",
        });
        InitialFocus = input.Length == 0 ? name : secret;
        Accepting = _ =>
        {
            store.Add(OtpAuth.Parse(name.Text, secret.Text));
            return Task.FromResult(true);
        };
    }
}
