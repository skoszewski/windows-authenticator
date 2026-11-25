# Changelog

## 0.2.0 - 2026-11-25 10:17:40 +0100

feature: HashiCorp Vault as a TOTP backend with several vaults, a Settings window for the accounts
and the vaults, and vault problems said in words in the tray, in Settings and in a notification.

- A Settings window, opened with Settings... in the tray menu or a double click on the tray icon,
  has the tabs Accounts and Vaults, each a list with Add... and Remove buttons and the details of
  the selected item.
- Accounts lists all accounts, kept in Credential Manager or taken from a vault, with the store of
  each. Add... adds an account by Account..., From QR Code in Clipboard, From Vault...,
  Generate in Vault... or Import to Vault.... The details hold Show Window and Copy Code.
- Vaults lists any number of Vault servers, each with its own settings and sign-in: token,
  username and password, AppRole or OIDC in the browser. The settings are kept in the registry and
  the credential in Credential Manager. Accounts of several vaults show codes together.
- A vault's page holds its status with Sign In and Sign Out, the problem of its last call with the
  time of the attempt and Copy Details, and Test Connection, which checks the address, the server,
  the sign-in and the TOTP engine of the settings as typed.
- While a vault's last call failed, the tray icon shows a warning sign and the tray menu starts
  with a line `Vault <name>: <what is wrong>` that opens Settings on that vault. A vault that
  worked and fails shows a notification, which opens the vault when clicked.
- A Vault account whose vault has a problem shows a warning in the Accounts list, a Problem section
  in its details, and the problem in its code window.
- Each new vault problem is appended, without secrets, to
  `%LOCALAPPDATA%\pl.waw.koszewscy\WindowsAuthenticator\vault.log`.
- The tray menu keeps the accounts with Copy Code and Show, and Settings..., Launch at Login, About
  and Quit. Add Account and Remove are in the Settings window.
- `release.py` releases the newest entry of `CHANGELOG.md`: it commits, and with `--push` tags and
  pushes, with the entry's summary as the message.

## 0.1.0 - 2026-11-23 07:59:01 +0100

- Added Mac ported icon, cleaned up the documentation, and moved ADRs to separate file.
- Added code ported from Mac application by AI Assistant.
