# Windows Authenticator

A Windows notification area (tray) app holding TOTP accounts and showing their current codes in
small windows that stay over the others. The codes follow RFC 6238 and refresh as their period
passes. It is the Windows version of Mac Authenticator.

## Requirements

- Windows 10 or 11, x64 or Arm64, with the .NET 10 Desktop Runtime.
- To build: the .NET 10 SDK, on Windows, macOS or Linux.

## Building

```sh
dotnet test                       # run the tests of the TOTP library
dotnet build -c Release           # build the library, the app and the tests
dotnet publish src/WindowsAuthenticator -c Release -r win-x64 --self-contained false -o dist/win-x64
dotnet publish src/WindowsAuthenticator -c Release -r win-arm64 --self-contained false -o dist/win-arm64
```

`dotnet test` runs the tests of the TOTP code; they run on any OS.

The projects are:

- `src/Totp`: the TOTP code, base32 decoding and otpauth URI reading;
- `src/WindowsAuthenticator`: the Windows Forms app;
- `tests/Totp.Tests`: the tests of `src/Totp`.

## The app icon

The app icon, `src/WindowsAuthenticator/Resources/AppIcon.ico`, is part of the repository. It is
drawn by `tools/make-windows-icon.swift` of the Mac Authenticator repository, run there:

```sh
swift tools/make-windows-icon.swift <windows-authenticator>/src/WindowsAuthenticator/Resources/AppIcon.ico
```

The script needs macOS. It draws with CoreGraphics and ImageIO, which
[Swift for Windows](https://www.swift.org/install/windows/) does not include, so it does not
build on Windows.

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

Each account is an entry of Windows Credential Manager, listed in Control Panel > Credential
Manager > Windows Credentials. A secret is read only when its code is shown or copied, and kept
in memory only while its code window is open. Any program running as the same Windows user can
read these entries.

## License

MIT, see `LICENSE`.

## Sibling project

Mac Authenticator, the macOS version of this app: <https://github.com/skoszewski/mac-authenticator>.
