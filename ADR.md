# Architectural Decision Records

## The app is Windows Forms on .NET 10 with a NotifyIcon

The app targets `net10.0-windows` with Windows Forms. Of the .NET desktop stacks only Windows
Forms has a notification area icon, `NotifyIcon`, with a `ContextMenuStrip` whose items take
submenus and ticks; WPF and WinUI 3 have none and would need a third-party package or a second
UI framework. The app is an `ApplicationContext` with no main form, so it has no taskbar button.
A named mutex in the `Local\` namespace keeps one instance per sign-in session, since nothing
else stops a second tray icon from appearing.

The project sets `EnableWindowsTargeting`, so the .NET SDK on macOS and Linux downloads the
Windows Desktop targeting pack and builds the app; it cannot run there. The target is the plain
`net10.0-windows` (Windows API level 7.0): the app uses no WinRT API, and a versioned Windows
target framework would bring in the Windows SDK projections for nothing.

## The menu holds no codes

The menu lists the accounts as submenus and is rebuilt from the store each time it opens, which
also refreshes the Launch at Login tick from the registry. It reads no clock: the codes are shown
by the code windows alone, refreshed by one Windows Forms timer re-armed at each whole second.

Mac Authenticator's Show in Menu Bar has no counterpart. The notification area shows an icon and
no text, a 16-pixel icon cannot hold 6 to 10 readable digits, and a tooltip is seen only while
the pointer rests on the icon.

## The code windows stay on top and do not take activation

A code window is a `TopMost` tool window that is not in the taskbar. It returns true from
`ShowWithoutActivation` and adds `WS_EX_NOACTIVATE` to its extended style, so neither showing it
nor clicking Copy takes the focus from the window the code is typed into. There is at most one
window per account; Show brings an open one forward, closing it disposes it, and removing the
account closes it.

## Each account is a generic credential of Credential Manager

Each account is one `CRED_TYPE_GENERIC` credential persisted with `CRED_PERSIST_LOCAL_MACHINE`,
so it stays on this computer and does not roam with a roaming profile. Its blob is the secret
alone, as the base32 text it was given in, and no serialised structure holds a secret. The rest
of the account is in the credential's other fields: the id in the target name after the
`pl.waw.koszewscy.WindowsAuthenticator:` prefix, the name as the user name, the issuer as the
comment, and the parameters as one application attribute in the `<CompanyName>_<Name>` keyword
form that `CREDENTIAL_ATTRIBUTE` asks for, its value UTF-16 text without a trailing zero. The
Credential Manager functions are called through `LibraryImport`; `System.Security` has no
managed API for them.

`CredEnumerate` returns each credential whole, its blob included, so listing the accounts
brings every secret into the process's memory. The listing copies the other fields, clears each
blob in the returned buffer and frees it with `CredFree`; the secrets are never copied into
managed memory there. `CredRead` reads one secret when its code is needed, and its blob is
cleared the same way once copied. A secret is held in memory only while its code window is open;
Copy Code reads it for that one copy. A secret held as a .NET string cannot be cleared, which is
accepted as it is on macOS.

Credential Manager protects the credentials with the user's sign-in, not per application: any
process of the same user can read them, and no prompt is shown. This is the trade for having no
password of the app's own.

Credentials have no order, so the menu order is a list of ids in the registry under
`HKEY_CURRENT_USER\Software\pl.waw.koszewscy\WindowsAuthenticator`, the place of a desktop app's
per-user settings; a credential missing from it follows by the time it was last written.

## Launch at Login is the Run key

`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` starts a program at each sign-in
of the user and needs no administrator rights or package. `StartupTask` needs the app to be an
MSIX package, which this app is not. The value holds the quoted path of the running executable,
and the item is ticked only when the value names that path.

## The code is a library with its own tests

The TOTP code, the base32 decoding and the otpauth URI reading are the library `Totp`, which
targets plain `net10.0` and uses `System.Security.Cryptography` alone, so its tests run on any OS.
`Totp.Tests` uses MSTest through `MSTest.Sdk` and Microsoft.Testing.Platform, with `DataRow` cases:
the RFC 6238 Appendix B vectors, codes printed by `otp.py` of linux-cloud-router for one secret,
as a second implementation to agree with, and the secret and URI cases. The messages are those of
Mac Authenticator, and the tests compare them as its tests do.

The otpauth query is split by hand and each part decoded with `Uri.UnescapeDataString`, which
leaves `+` as it is, as `URLComponents` does on macOS; `HttpUtility.ParseQueryString` would turn
it into a space.

## QR codes are read with ZXing.Net

Windows has no API that decodes a QR code from a still image: its barcode decoder works only on
camera frames through `Windows.Devices.PointOfService.BarcodeScanner`. ZXing.Net (Apache-2.0)
reads the clipboard image instead. The image is copied to a 32-bit ARGB bitmap, whose bytes are
blue, green, red and alpha in memory, and passed to `BarcodeReaderGeneric` limited to QR codes as
`BGRA32` pixels, so no ZXing bindings package for `System.Drawing` is needed. The first payload
starting with `otpauth://` fills the Add Account dialog rather than being added at once, so the
name can be changed and a duplicate or invalid code is reported the way a typed one is.

## The dialogs are task dialogs

Errors, the Remove question and About are `TaskDialog` pages, whose heading and text match the
message and informative text of the alerts on macOS. Add Account is a form that stays open and
shows the reason when the input is refused, as the alert loop does on macOS.

## The icon is drawn in code

The notification area icon is drawn at the small icon size with `System.Drawing` from the
shapes of Mac Authenticator's icon layers: a blue gradient square, a countdown ring, a shield and
a keyhole, on the same 1024-unit canvas. The quadratic curves of the shield are drawn as the
equivalent cubic Beziers, and the ring is drawn thicker than on macOS so that it shows at 16
pixels. The executable has no icon resource.
