using System.Runtime.InteropServices;
using Windows.Security.Credentials.UI;

namespace WindowsAuthenticator;

/// <summary>Asks the user to verify with Windows Hello, by face, fingerprint or PIN, before a secret is shown or copied.</summary>
internal static class WindowsHello
{
    /// <summary>
    /// <c>WINBIO_E_INVALID_TICKET</c>, which the prompt sometimes fails with after it matched the user's face; it is
    /// not in the documented biometric error codes.
    /// </summary>
    private const int InvalidTicket = unchecked((int)0x80098044);

    /// <summary>
    /// Shows the Windows Hello prompt with the message over the owner, a shown and active window of the app; true
    /// when the user verified, false when the user cancelled. A prompt that fails with
    /// <see cref="InvalidTicket"/> is shown once more. Every other outcome fails as <see cref="StoreException"/>
    /// that says why.
    /// </summary>
    public static async Task<bool> VerifyAsync(IWin32Window owner, string message)
    {
        UserConsentVerificationResult result;
        try
        {
            result = await UserConsentVerifierInterop.RequestVerificationForWindowAsync(owner.Handle, message);
        }
        catch (COMException error) when (error.HResult == InvalidTicket)
        {
            try
            {
                result = await UserConsentVerifierInterop.RequestVerificationForWindowAsync(owner.Handle, message);
            }
            catch (COMException again) when (again.HResult == InvalidTicket)
            {
                throw new StoreException("Windows Hello did not confirm the verification; try again, or choose the PIN under More choices.");
            }
        }
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
