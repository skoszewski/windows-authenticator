using Windows.Security.Credentials.UI;

namespace WindowsAuthenticator;

/// <summary>Asks the user to verify with Windows Hello, by face, fingerprint or PIN, before a secret is shown or copied.</summary>
internal static class WindowsHello
{
    /// <summary>
    /// Shows the Windows Hello prompt with the message over the owner, a shown and active window of the app; true
    /// when the user verified, false when the user cancelled. Every other outcome fails as
    /// <see cref="StoreException"/> that says why.
    /// </summary>
    public static async Task<bool> VerifyAsync(IWin32Window owner, string message)
    {
        var result = await UserConsentVerifierInterop.RequestVerificationForWindowAsync(owner.Handle, message);
        return result switch
        {
            UserConsentVerificationResult.Verified => true,
            UserConsentVerificationResult.Canceled => false,
            UserConsentVerificationResult.DeviceNotPresent =>
                throw new StoreException("This computer has no Windows Hello device; set up a Windows Hello PIN, or turn off the secret's setting to authenticate."),
            UserConsentVerificationResult.NotConfiguredForUser =>
                throw new StoreException("Windows Hello is not set up for this user; set it up, or turn off the secret's setting to authenticate."),
            UserConsentVerificationResult.DisabledByPolicy =>
                throw new StoreException("Windows Hello is disabled by policy; turn off the secret's setting to authenticate, or ask the administrator."),
            UserConsentVerificationResult.DeviceBusy =>
                throw new StoreException("The Windows Hello device is busy; try again."),
            UserConsentVerificationResult.RetriesExhausted =>
                throw new StoreException("Windows Hello was not verified after too many attempts; try again later."),
            _ => throw new StoreException("Windows Hello is not available; try again."),
        };
    }
}
