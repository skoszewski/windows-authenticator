using System.Globalization;

namespace Totp;

/// <summary>
/// How a secret account's secret is protected and shown: whether showing or copying it asks the user to
/// authenticate, the seconds after an authentication during which it is not asked for again (0 asks every time),
/// and the seconds after which a shown secret is hidden again (0 never hides it). Negative numbers are raised to 0.
/// </summary>
public sealed record SecretSettings
{
    public const int DefaultHideSeconds = 30;

    public SecretSettings(bool requiresAuthentication = true, int authenticationSeconds = 0,
                          int hideSeconds = DefaultHideSeconds)
    {
        RequiresAuthentication = requiresAuthentication;
        AuthenticationSeconds = Math.Max(0, authenticationSeconds);
        HideSeconds = Math.Max(0, hideSeconds);
    }

    public bool RequiresAuthentication { get; }
    public int AuthenticationSeconds { get; }
    public int HideSeconds { get; }

    /// <summary>The stored text of the settings, <c>authenticate=1&amp;seconds=60&amp;hide=30</c>.</summary>
    public string Text => string.Create(CultureInfo.InvariantCulture,
                                        $"authenticate={(RequiresAuthentication ? 1 : 0)}&seconds={AuthenticationSeconds}&hide={HideSeconds}");

    /// <summary>
    /// The settings from their stored text; a key that is left out takes its default, and so does an empty text.
    /// A text that is not <c>key=value</c> pairs, or holds a value that is not valid, is null. The form
    /// <c>authenticate=0</c> is read as well.
    /// </summary>
    public static SecretSettings? FromText(string text)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in text.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            if (parts.Length != 2)
            {
                return null;
            }
            values[parts[0]] = parts[1];
        }
        bool requires;
        switch (values.GetValueOrDefault("authenticate"))
        {
            case null or "1":
                requires = true;
                break;
            case "0":
                requires = false;
                break;
            default:
                return null;
        }
        if (Seconds(values, "seconds", 0) is not { } authentication || Seconds(values, "hide", DefaultHideSeconds) is not { } hide)
        {
            return null;
        }
        return new SecretSettings(requires, authentication, hide);
    }

    /// <summary>The whole number of 0 or more under the key, the default when it is left out, or null when it is not valid.</summary>
    private static int? Seconds(Dictionary<string, string> values, string key, int fallback)
    {
        if (!values.TryGetValue(key, out var text))
        {
            return fallback;
        }
        return int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var number) ? number : null;
    }
}
