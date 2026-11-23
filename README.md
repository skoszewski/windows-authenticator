# Windows Authenticator

A Windows notification area (tray) app holding TOTP accounts and showing their current codes in
small windows that stay over the others. The codes follow RFC 6238 and refresh as their period
passes. It is the Windows version of Mac Authenticator.

## Requirements

- Windows 10 or 11, x64 or Arm64, with the .NET 10 Desktop Runtime
  (Microsoft.WindowsDesktop.App 10.0).
- To build: the .NET 10 SDK, on Windows, macOS or Linux. The Windows Desktop targeting pack is
  downloaded on the first restore (`EnableWindowsTargeting`).

## Building

```sh
dotnet test                       # run the tests of the TOTP library
dotnet build -c Release           # build the library, the app and the tests
dotnet publish src/WindowsAuthenticator -c Release -r win-x64 --self-contained false -o dist/win-x64
dotnet publish src/WindowsAuthenticator -c Release -r win-arm64 --self-contained false -o dist/win-arm64
```

`dotnet test` runs the tests in `tests/Totp.Tests` with MSTest: they compare the codes with the
test vectors of RFC 6238 Appendix B for SHA-1, SHA-256 and SHA-512 and with codes printed by
`otp.py` of linux-cloud-router, and check the reading of secrets and otpauth URIs. The library
has no Windows dependency, so the tests also run on macOS and Linux.

The projects are:

- `src/Totp`: the TOTP code, base32 decoding and otpauth URI reading;
- `src/WindowsAuthenticator`: the Windows Forms app;
- `tests/Totp.Tests`: the tests of `src/Totp`.

## Installing and running

Copy the folder `dist/win-x64` (or `dist/win-arm64`) to a folder of your choice, for example
`%LOCALAPPDATA%\Programs\Windows Authenticator`, and run `WindowsAuthenticator.exe`. The app shows
an icon in the notification area and no taskbar button; Windows may put the icon in the overflow
area, from which it can be dragged next to the clock. A second start while the app runs does
nothing.

## The menu

The menu opens with a right click on the icon:

- one submenu for each account, named after it, with:
  - **Copy Code** puts the current code in the clipboard;
  - **Show** opens the account's window: the code in two groups of digits, a bar and the
    seconds until it changes, and a **Copy** button. The window stays over the windows of other
    apps until it is closed, and clicking it does not take the focus from the app the code is
    typed into; choosing Show again brings it forward;
  - **Remove** asks before the account and its secret are deleted, and closes its window;
- **Add Account...** asks for a name and a secret or an otpauth URI;
- **Add Account from QR Code in Clipboard** reads the QR code in the image in the clipboard and
  opens the same dialog with its URI filled in;
- **Launch at Login** starts the app when you sign in to Windows;
- **About Windows Authenticator** shows the app's version;
- **Quit Windows Authenticator**.

## Adding an account

The secret field takes either of:

- a base32 secret, such as `JBSWY3DPEHPK3PXP`, in upper or lower case, with or without spaces,
  dashes and `=` padding; the account gets SHA-1, 6 digits and a 30-second period, and needs a
  name;
- an `otpauth://totp/<label>?secret=<secret>&issuer=<issuer>&algorithm=<SHA1|SHA256|SHA512>&digits=<6..10>&period=<seconds>`
  URI, as `otp.py new` prints and sites show as a QR code. Only `secret` is required. The label
  is `<issuer>:<account name>` or `<account name>`; the `issuer` parameter, when given, stands
  above the label's issuer.

An empty name is taken from the URI: `<issuer>: <account name>`, else whichever of the two the
URI holds. Names are unique, regardless of case. Copied codes have no space between the groups.

A QR code in the clipboard is read from a screenshot or a copied image; Windows+Shift+S copies a
selected part of the screen. Only `otpauth://totp/` codes are added: `hotp` accounts and export
codes of other apps, such as `otpauth-migration://`, are refused.

## Where the secrets are kept

Each account is one generic credential of Windows Credential Manager, kept on this computer
(Control Panel > Credential Manager > Windows Credentials lists them):

- its target name is `pl.waw.koszewscy.WindowsAuthenticator:<id>`, the id being a GUID;
- its password (credential blob) is the account's secret, as base32 text;
- its user name is the account's name;
- its comment is the issuer, when the account has one;
- its attribute `Koszewscy_Parameters` holds the algorithm, digits and period, as
  `algorithm=SHA1&digits=6&period=30`.

The order of the accounts in the menu is the `AccountOrder` value, a list of ids, of the registry
key `HKEY_CURRENT_USER\Software\pl.waw.koszewscy\WindowsAuthenticator`. Launch at Login is the
value `Windows Authenticator` of `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`,
holding the path of `WindowsAuthenticator.exe`; after the app is moved, Launch at Login is shown
unticked until it is chosen again.

The menu is built from the credentials' other fields alone. Listing the credentials returns
their secrets too; the app clears them in the returned buffer at once and keeps none. A secret
is read when its code is needed: when the account's Show window opens it is read and kept in
memory while the window is open, and dropped when it closes; Copy Code reads it, copies the
code and keeps nothing. A secret that cannot be read is reported in the code window instead of
the code.

Any program running as the same Windows user can read these credentials; Credential Manager
does not ask.

When the credentials cannot be listed, the menu shows why and a **Retry** item, and refuses
changes until they have been listed.

## License

MIT, see `LICENSE`.
