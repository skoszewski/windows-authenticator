# Using Windows Authenticator

The tray app, its Settings window, the accounts it holds and where their secrets are kept. The
HashiCorp Vault side is in [Vault.md](Vault.md).

The app has two kinds of accounts: TOTP accounts, which show a current code (RFC 6238) in a small
window that stays over the others, and secret accounts, which hold a plain string, such as a
password or an encryption key, and copy it on demand. The codes refresh as their period passes.

## The menu

The menu opens with a right click on the icon:

- a line `Vault <name>: <what is wrong>` for each vault whose last call failed; choosing it opens
  Settings on that vault;
- one submenu for each account, named after it; a secret account's submenu has **Copy Secret**,
  described under Secret accounts. The submenu of a TOTP account has:
  - **Copy Code** puts the current code in the clipboard;
  - **Show** opens the account's window: the code in two groups of digits, a bar and the
    seconds until it changes, and a **Copy** button. The window stays over the windows of other
    apps until it is closed, and clicking it does not take the focus from the app the code is
    typed into; choosing Show again brings it forward;
- **Settings...** opens the Settings window, as a double click on the icon does;
- **Launch at Login** starts the app when you sign in to Windows;
- **About Windows Authenticator** shows the app's version and, after it, the commit it was built
  from, as `git log --oneline` abbreviates it, for example `Version 0.5.1 (4f686f6)`;
- **Quit Windows Authenticator**.

The icon shows a badge: a blue dot with three white dots while a call to a vault runs, a green
check mark for 2 seconds after a code or a secret was copied, and a warning sign while a vault's
last call failed. Its tooltip says what the app waits for, what was copied, or what is wrong.

## Settings

The Settings window has two tabs, each a list on the left with **Add...** and **Remove** under
it, and the details of the selected item on the right, and a status bar at the bottom. Closing the
window hides it.

**Accounts** lists all the accounts, whichever store keeps the secret, with the kind of each,
TOTP or Secret, and its store: Credential Manager, or "Vault: " and the name of the vault. The
details of a TOTP account show its name, issuer, store and parameters, and hold **Show Window**
and **Copy Code**; those of a secret account are described under Secret accounts.

- **Add...** opens a menu of the ways to add an account:
  - **Account...** asks for a name and a secret or an otpauth URI;
  - **From QR Code in Clipboard** reads the QR code in the image in the clipboard and opens the
    same dialog with its URI filled in;
  - **From Vault...**, **Generate in Vault...** and **Import to Vault...** add accounts whose codes
    a vault makes, as [Vault.md](Vault.md) describes;
  - **Secret...**, **Secret from Vault...** and **Secret in Vault...** add secret accounts;
- **Remove** asks before the selected account and its secret are deleted, and closes its window.

**Vaults** lists the HashiCorp Vault servers the app is set up for; see [Vault.md](Vault.md).

The status bar says what the app waits for from a vault, with a **Cancel** button, or what was just
copied; see Waiting for a vault in [Vault.md](Vault.md).

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

## Secret accounts

An account is one of two kinds: a TOTP account, which shows codes, and a secret account, which
holds a plain string, such as a password or an encryption key, and shows no code. A secret is kept
in Credential Manager, or in a field of a secret of a Vault KV engine. A secret account is listed
with the other accounts, as Secret, and keeps its place in their order.

**Secret...** in the **Add...** menu of the Accounts tab asks for a name and the secret, and keeps
the secret in Credential Manager, which holds at most 2560 bytes of it. For a secret account the
details show, in place of a code:

- **Reveal**, which shows the secret until **Hide** is chosen, another account is selected, or the
  Settings window loses the keyboard or is closed;
- **Copy Secret**, which puts the secret in the clipboard with the formats that keep it out of the
  clipboard history and the cloud clipboard (`ExcludeClipboardContentFromMonitorProcessing`,
  `CanIncludeInClipboardHistory` and `CanUploadToCloudClipboard`), and empties the clipboard after
  30 seconds, or when the app quits, if it still holds that copy.

Each secret account has a setting, **Ask to authenticate before it is shown or copied**, which is
on when the account is added unless it is unticked in the dialog, and can be changed in the
details. When it is on, Reveal and Copy Secret, and Copy Secret in the menu, ask the user to verify
with Windows Hello first, by face, fingerprint or PIN; cancelling the prompt does nothing. When
Windows Hello is not set up for the user, or is disabled by policy, the secret is not shown or
copied, and the message says so; the setting can then be turned off. When it is off they act at
once. An account without the setting, such as one kept by an earlier build, asks.

A secret account has no window, so a secret is never drawn on the screen unasked.

## Where the secrets are kept

Each account is an entry of Windows Credential Manager, listed in Control Panel > Credential
Manager > Windows Credentials. The secret of a TOTP account is read only when its code is shown or
copied, and kept in memory only while its code window is open. Any program running as the same
Windows user can read these entries.

A secret account kept in Credential Manager is the generic credential
`pl.waw.koszewscy.WindowsAuthenticator.secret:<id>`, of a target prefix of its own so that a build
that knows no secret accounts does not read a password as a TOTP secret: its blob is the secret, its
user name the account's name, and its attribute `Koszewscy_Authenticate`, `1` or `0`, its setting.
A secret is read when it is revealed or copied, and kept nowhere.
