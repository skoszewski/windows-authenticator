# Windows Authenticator

A Windows notification area (tray) app holding TOTP accounts and showing their current codes in
small windows that stay over the others. The codes follow RFC 6238 and refresh as their period
passes. It is the Windows version of Mac Authenticator.

## Requirements

- Windows 10 or 11, x64 or Arm64, with the .NET 10 Desktop Runtime.
- To build: the .NET 10 SDK, on Windows, macOS or Linux.
- To test: the `vault` binary on `PATH`, or named by `VAULT_BINARY`. The Vault tests start an
  in-memory `vault server -dev` on 127.0.0.1, port 18200 or `VAULT_TEST_PORT`, and stop it
  afterwards.

## Building

```sh
dotnet test                       # run the tests of the TOTP and Vault libraries
dotnet build -c Release           # build the library, the app and the tests
dotnet publish src/WindowsAuthenticator -c Release -r win-x64 --self-contained false -o dist/win-x64
dotnet publish src/WindowsAuthenticator -c Release -r win-arm64 --self-contained false -o dist/win-arm64
```

`dotnet test` runs the tests of the two libraries; they run on any OS. The tests in
`tests/Totp.Tests` compare the codes with the test vectors of RFC 6238 Appendix B and with codes
printed by `otp.py` of linux-cloud-router, and check the reading of secrets and otpauth URIs. The
tests in `tests/Vault.Tests` run the Vault client against a dev server they start: the
authentication with a token, a password and an AppRole, renewing, listing, reading, generating and importing
keys, the policy that denies listing, a revoked token, codes that agree with the ones `Totp`
computes for the same secret, Test Connection, the listener that receives the OIDC redirect, and
the words a problem is said in.

The projects are:

- `src/Totp`: the TOTP code, base32 decoding and otpauth URI reading;
- `src/Vault`: the client of the Vault HTTP API, the OIDC redirect listener, the connection test
  and the problems in words;
- `src/WindowsAuthenticator`: the Windows Forms app;
- `tests/Totp.Tests` and `tests/Vault.Tests`: the tests of the libraries.

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

- a line `Vault <name>: <what is wrong>` for each vault whose last call failed; choosing it opens
  Settings on that vault;
- one submenu for each account, named after it, with:
  - **Copy Code** puts the current code in the clipboard;
  - **Show** opens the account's window: the code in two groups of digits, a bar and the
    seconds until it changes, and a **Copy** button. The window stays over the windows of other
    apps until it is closed, and clicking it does not take the focus from the app the code is
    typed into; choosing Show again brings it forward;
- **Settings...** opens the Settings window, as a double click on the icon does;
- **Launch at Login** starts the app when you sign in to Windows;
- **About Windows Authenticator** shows the app's version;
- **Quit Windows Authenticator**.

## Settings

The Settings window has two tabs, each a list on the left with **Add...** and **Remove** under
it, and the details of the selected item on the right. Closing the window hides it.

**Accounts** lists all the accounts, whichever store keeps the secret, with the store of each:
Credential Manager, or "Vault: " and the name of the vault. The details show the account's name,
issuer, store and parameters, and hold **Show Window** and **Copy Code**.

- **Add...** opens a menu of the ways to add an account:
  - **Account...** asks for a name and a secret or an otpauth URI;
  - **From QR Code in Clipboard** reads the QR code in the image in the clipboard and opens the
    same dialog with its URI filled in;
  - **From Vault...** asks for a vault and one of the keys of its TOTP engine, and adds the
    account the key stores;
  - **Generate in Vault...** has a vault make the secret of a new account, keeps it in a key and
    adds the account;
  - **Import to Vault...** stores the secret of an existing account in a key of a vault and adds
    the account;
- **Remove** asks before the selected account and its secret are deleted, and closes its window.

**Vaults** lists the HashiCorp Vault servers the app is set up for, with a dot showing the state
of each vault's authentication: green when it holds a token, yellow while it gets one, red after a
failure and gray when it has none. **Add...** opens the page of a new vault and **Remove** removes
the selected one. The page of a vault holds its settings and authentication, with its state, a
start button and a stop button, **Test Connection**, and **Save** and **Revert** at the bottom.
The words follow the method:

| Method | State | Start | Stop |
|---|---|---|---|
| Token | Token not checked, Checking the token..., Token accepted | **Check Token** | **Forget Token** |
| Username and password, AppRole | Not logged in, Logging in..., Logged in | **Log In** | **Log Out** |
| OIDC | Signed out, Signing in..., Signed in | **Sign In** | **Sign Out** |

The accepted, logged-in or signed-in state names the time its token ends, when it has one. A
token, password or AppRole vault also authenticates by itself when a code is needed; an OIDC
vault is signed in with its button after each start of the app.

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

## HashiCorp Vault

An account can take its codes from the TOTP secrets engine of a Vault server, which then holds
the secret and the app never sees it. The app has any number of vaults, each a connection to one
server with its own authentication, and any number of keys of each. A Vault account looks and works
like any other: it has a window and can be copied; its code is fetched from Vault once for each period
while its window is open.

### The vaults

The page of a vault in Settings asks for:

- the name of the vault, which must be unique;
- the Vault address, such as `https://vault.example.com:8200`; plain `http` is allowed for any
  address, and then the credential and the codes cross the network unencrypted;
- the namespace, for Vault Enterprise;
- the mount of the TOTP engine, `totp` by default;
- the authentication method and its mount, which is named after the method by default:
  - **Token**: the token is kept in Credential Manager;
  - **Username and password**: the user name is a setting and the password is kept in Credential
    Manager;
  - **AppRole**: the RoleID is a setting and the SecretID is kept in Credential Manager;
  - **OIDC (browser)**: the role, and the port of the redirect listener, 8250 by default. Nothing
    is kept in Credential Manager: Sign In opens the browser and the identity provider signs the
    user in. The token lives in memory, so the sign-in is repeated after each start of the app and
    when the token ends.

An empty credential field keeps the credential stored before. The settings of a vault are kept in
the registry under
`HKEY_CURRENT_USER\Software\pl.waw.koszewscy\WindowsAuthenticator\Vaults`, one key per vault, and
its credential is the Credential Manager entry
`pl.waw.koszewscy.WindowsAuthenticator.vault:<id>`, named after the vault. The accounts taken
from Vault are kept under `...\WindowsAuthenticator\VaultAccounts`, each with its vault and key,
and hold nothing secret. Removing a vault deletes its settings, its credential and its accounts;
the keys stay in Vault.

Vaults authenticate independently, so accounts of several servers show codes at once. Two OIDC
vaults with the same callback port cannot sign in at the same moment; give them different ports.

With a token, password or AppRole the app authenticates when a code is needed, and again when
Vault refuses the token; a renewable token is renewed when half of its lease has passed. A code that
cannot be fetched is reported in the code window in place of the code.

### Adding accounts from a vault

A vault stores an account in a key of its TOTP engine. **From Vault...** asks for the vault and
lists its keys, to pick from; the key's algorithm, digits, period and issuer are read once, so the
window can count the seconds. A key can be typed when the policy does not allow listing. The
account is named as typed, or `<issuer>: <account name>` from the key. Removing the account does
not touch the key in the vault.

**Generate in Vault...** asks for a vault, a key name, an issuer and an account name, and has the
vault make the secret. The vault shows the secret once, as a QR code and an `otpauth://` URL; scan
the code into another authenticator, or copy the URL, before choosing Done. **Import to
Vault...** asks for a vault, a key name and a base32 secret or an `otpauth://totp/` URI; Vault
keeps SHA1, SHA256 and SHA512 keys of 6 or 8 digits, and other keys are refused. Neither replaces
a key that exists: the name must be new. Both add the account to the app.

### When a vault does not work

A failure is said in words: what is wrong, what happened, and what to do about it.

- While a vault's last call failed, the tray icon shows a warning sign, its tooltip names the
  problem, and the menu starts with a line `Vault <name>: <what is wrong>`; choosing it opens
  Settings on that vault.
- The vault's page in Settings shows the problem under its status, with the time of the last
  attempt and **Copy Details**, which puts the text of the problem in the clipboard without any
  secret. A call that works clears it.
- A Vault account whose vault has a problem shows a warning in the Accounts list and a Problem
  section in its details, and its code window says what is wrong in place of the code.
- **Test Connection** on the vault's page checks the settings as typed, without saving them: the
  address as typed, whether the server answers and is unsealed, the authentication, and the TOTP
  engine. The authentication step is named after what it does: **Token** checks that the token is
  valid and says when it ends, **Login** logs in with a password or an AppRole and says that Vault
  issued a token, and **Authentication** is not tested for an OIDC vault, which signs in
  interactively, so the engine step is not tested either. Each step shows Passed, Warning, Failed
  or Skipped, and the first failure says what to do.
- When a vault that worked fails, a Windows notification names it; clicking it opens Settings on
  the vault. A vault that keeps failing notifies once, until it works again.
- Each new problem is appended, without secrets, to
  `%LOCALAPPDATA%\pl.waw.koszewscy\WindowsAuthenticator\vault.log`.

### Vault Setup

**Vault Setup...**, beside Test Connection on the vault's page, prepares a vault for the app. It
runs as the identity the page describes, with the address, method and credential as typed, so an
administrator's token can be used without saving it; an OIDC vault uses its current sign-in. The
identity is taken to hold the rights for the calls, and the setup stops at the first call that
fails. The dialog asks for:

- the mount of the TOTP engine, taken from the page, and a description;
- the names of the two policies, `totp_creator` and `totp_user`;
- **The engine is already enabled**, which skips enabling it and writes the policies alone;
- **Replace policies that exist**, without which a policy of the same name stops the setup.

**Run** enables the engine at the mount and writes the policies, and the result lists each step.
The dialog shows the text of both policies as they will be written:

- `totp_creator` lists keys and creates, updates and reads them, which adds and imports a key;
- `totp_user` lists and reads keys, whose answer holds no secret, and reads codes.

The setup assigns no policy: a Vault administrator assigns them to the users, roles or tokens
that need them, both to a user who adds accounts and shows codes.

### What the Vault administrator prepares

- the TOTP engine, with the keys;
- a policy for the user, role or token the app authenticates with:

  ```hcl
  path "totp/keys"   { capabilities = ["list"] }
  path "totp/keys/*" { capabilities = ["read"] }
  path "totp/code/*" { capabilities = ["read"] }
  ```

  The `list` rule is optional, and the `read` rule of `totp/keys/*` is needed to add a key.
  Generating or importing a key needs `create` and `update` on `totp/keys/*` as well;
- for OIDC, a role of the JWT/OIDC method whose `allowed_redirect_uris` holds
  `http://localhost:8250/oidc/callback`, with the port of the settings, and the same URI
  registered with the identity provider.

## Releasing

`release.py` releases the newest entry of `CHANGELOG.md`:

- `./release.py` writes the release time into the entry's heading, and commits everything with
  the summary of the entry as the message;
- `./release.py --push` also tags the entry's version and pushes `main` and the tag;
- `./release.py --no-tag` makes an internal release: with `--push`, `main` is pushed without a
  tag;
- `./release.py -n` prints the heading and the git commands instead of making them.

The commit and the date in the heading mark the entry as released, so the next change needs a new
entry with a new version; write new entries with a plain `## x.y.z` heading. The version the app
reports is the `Version` of `Directory.Build.props`, which is set to the version of the entry
when the entry is written.

## License

MIT, see `LICENSE`.

## Sibling project

Mac Authenticator, the macOS version of this app: <https://github.com/skoszewski/mac-authenticator>.
