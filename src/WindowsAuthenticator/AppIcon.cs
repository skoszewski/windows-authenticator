namespace WindowsAuthenticator;

/// <summary>The app icon, Resources/AppIcon.ico, embedded in the assembly as AppIcon.ico.</summary>
internal static class AppIcon
{
    /// <summary>The image of the icon closest to the given size.</summary>
    public static Icon Load(Size size)
    {
        using var stream = typeof(AppIcon).Assembly.GetManifestResourceStream("AppIcon.ico")
                           ?? throw new InvalidOperationException("The app icon is missing from the assembly.");
        return new Icon(stream, size);
    }
}
