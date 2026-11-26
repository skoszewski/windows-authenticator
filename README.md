# Windows Authenticator

A Windows notification area (tray) app for one-time codes and secrets. It keeps them in Windows
Credential Manager or in HashiCorp Vault, and hands them to the person at the computer when they are
needed.

## Documentation

- [docs/Usage.md](docs/Usage.md): the menu, the Settings window, adding accounts, secret accounts
  and where the secrets are kept in Credential Manager;
- [docs/Vault.md](docs/Vault.md): HashiCorp Vault: the vaults and their authentication, accounts and
  secrets kept in Vault, waiting for a vault, problems, Vault Setup and what the administrator
  prepares;
- [docs/Development.md](docs/Development.md): requirements for building, building, testing, the app
  icon and releasing;
- [ADR.md](ADR.md): the decisions behind the code; [CHANGELOG.md](CHANGELOG.md): the history.

## Requirements

Windows 11, x64 or Arm64, with the .NET 10 Desktop Runtime. The OIDC sign-in also needs the
Microsoft Edge WebView2 Runtime, which Windows 11 includes, and a secret that asks to authenticate
needs Windows Hello, a face, a fingerprint or a PIN, set up for the user.

## Installing and running

Build the app as [docs/Development.md](docs/Development.md) describes, copy the folder
`dist/win-x64` (or `dist/win-arm64`) to a folder of your choice, for example
`%LOCALAPPDATA%\Programs\Windows Authenticator`, and run `WindowsAuthenticator.exe`. The app shows
an icon in the notification area and no taskbar button; Windows may put the icon in the overflow
area, from which it can be dragged next to the clock. A second start while the app runs does
nothing.

## License

MIT, see `LICENSE`.

## Sibling project

Mac Authenticator, the macOS version of this app: <https://github.com/skoszewski/mac-authenticator>.
