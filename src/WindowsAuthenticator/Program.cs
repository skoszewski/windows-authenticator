namespace WindowsAuthenticator;

internal static class Program
{
    /// <summary>Starts the tray app, unless it runs already in this session.</summary>
    [STAThread]
    private static void Main()
    {
        using var instance = new Mutex(true, $@"Local\{CredentialStore.Service}", out var first);
        if (!first)
        {
            return;
        }
        ApplicationConfiguration.Initialize();
        Application.Run(new TrayContext());
    }
}
