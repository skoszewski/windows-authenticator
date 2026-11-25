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

The menu lists the vaults with a problem and the accounts as submenus, and is rebuilt from the
store each time it opens, which also refreshes the Launch at Login tick from the registry. It
reads no clock: the codes are shown by the code windows alone, refreshed by one Windows Forms
timer re-armed at each whole second, whose tick also starts the fetches of Vault codes.

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

## The dialogs are task dialogs and forms of fields

Errors, the Remove questions and About are `TaskDialog` pages, whose heading and text match the
message and informative text of the alerts on macOS; opened from Settings they are owned by it.
Add Account, From Vault, Generate in Vault, Import to Vault and the generated key are forms built
on one base, `FieldsDialog`: labelled fields, an accept button and Cancel. It stays open and shows
the reason when the action fails, as the alert loop does on macOS, and runs a Vault call with the
accept button disabled, so the dialog is not accepted twice.

## Settings is a kept window, and the menu holds what is used with the codes

The menu holds what is used while working with codes: the accounts with Copy Code and Show,
Settings, Launch at Login, About and Quit. Adding, generating, importing and removing accounts,
and the vaults with their sign-in, are in the Settings window, as on macOS, which keeps the menu
short. The window is made once with the app and hidden, not closed, when the user closes it, so
the page and the selection of a vault stay while the app runs; Quit closes it for good. A vault is
signed in and out from its page, since the menu has no sign-in item.

The lists are `ListView`s with an image list: the warning sign of the system for an account whose
vault has a problem, and a coloured dot for the state of a vault. The page of an account is built
again from the store when the store changes; the page of a vault is a `VaultEditor` kept while the
vault is selected, so a change of the vault's state refreshes its status and leaves the typed
fields alone.

## The Vault client is a library on HttpClient, tested against a dev server

The Vault client, the OIDC redirect listener, the connection test and the problem texts are the
library `Vault`, which targets plain `net10.0` and uses no Windows API, so its tests run on any
OS. Requests go through `HttpClient` with `SocketsHttpHandler`, so the system trust store applies,
and plain HTTP works for any address, which is the user's choice for that vault. There is one
client per scheme, host and port, whose certificate validation callback accepts what the system
accepts and keeps the policy errors and chain status of a certificate it refuses: an
`HttpRequestException` of `SecureConnectionError` does not tell an untrusted root from an expired
certificate or a wrong name, and the callback's flags do, without reading localised exception
texts.

A request that gets no HTTP answer becomes a `VaultException` of the kind `Transport`, with the
host and the original exception, and `VaultProblem.From` reads its `HttpRequestError`, its inner
`SocketException` and the certificate errors. Vault's JSON is read with `System.Text.Json` in
snake case into types whose `required` members make a missing field a `JsonException`, which is
reported as an answer that is not from a Vault.

`Vault.Tests` start `vault server -dev`, which keeps its storage in memory, once for the test
assembly in `[AssemblyInitialize]`, and configure it through its HTTP API with a plain
`HttpClient`, apart from the client under test. The `vault` binary is a requirement of the tests,
and a missing one fails them. The exchange of the code with an identity provider needs a browser
sign-in and is checked by hand.

## A vault's settings are in the registry, its credential in Credential Manager

A vault's settings hold no secret and do not fit a credential attribute, whose value is at most
`CRED_MAX_VALUE_SIZE`, 256 bytes, 128 UTF-16 characters: an address, a namespace and the mounts
pass that. They are one key per vault under the app's registry key, named by the vault's id, with
the time it was added for the list order. The credential, a token, password or SecretID, is the
blob of a generic credential whose target is `pl.waw.koszewscy.WindowsAuthenticator.vault:<id>`,
which the accounts' filter `pl.waw.koszewscy.WindowsAuthenticator:*` does not match, so listing
the accounts never reads it. Its user name is the vault's name, so Credential Manager shows which
vault it belongs to; a rename writes it again. An OIDC vault has no credential.

A Vault account holds nothing secret, only its vault and the name of its key, so it is a registry
key under `VaultAccounts` and has no credential. Removing a vault removes its accounts, whose keys
stay in Vault, since they cannot show a code without it.

## The OIDC token is kept in memory and the sign-in is explicit

The identity provider signs the user in, so the app stores no credential for OIDC, and it keeps
the resulting Vault token in memory alone: a sign-in is repeated after each start and when the
token ends. The browser is opened from Sign In only, never because a code was needed, so a window
opening in the background cannot start a login nobody expects. The other methods sign in by
themselves, since they need no user.

The redirect is received as `vault login -method=oidc` does it: the redirect URI is
`http://localhost:<port>/oidc/callback`, 8250 by default, which the role's `allowed_redirect_uris`
must hold. A browser may resolve `localhost` to `::1` or to `127.0.0.1`, so the listener is a
`TcpListener` on both loopback addresses, not `HttpListener`, which works through `http.sys` on
Windows and differently on the systems the tests also run on. It answers each request, 404 for any
but the callback, and stops at the callback. Each connection is served on its own and closed when it
sends no request line within 10 seconds: browsers open connections in advance and send nothing on
some of them, and a listener that waited on such a connection would never read the redirect on the
next one. The state of the authorisation URL is compared with the state of the redirect before the
code is passed to Vault.

## Vault codes are fetched, never computed

An account of the Vault TOTP engine has no secret in the app: the code comes from
`GET <mount>/code/<key>`, once for each period of each account whose window is open, at the whole
second the period changes. The engine's answer holds the code alone, so the algorithm, digits,
period and issuer are read once, when the key is added, from `GET <mount>/keys/<key>`, and kept
with the account in the same `algorithm=...&digits=...&period=...` form as a credential's
attribute. A code is kept with the period count it was fetched for and is shown for that period
alone, so a stale code is never shown; a failed fetch is not repeated within its period. The
calls run on the UI thread's synchronisation context, so the store and the sessions need no locks.

## Vault keys are generated or imported only under a new name

`POST <mount>/keys/<key>` replaces the secret of a key that exists, which would silently break
every account and authenticator using it. The client reads the key first and refuses a name that
is taken. Generated keys answer with `barcode`, a base64 PNG QR code, and `url`, an otpauth URI;
both are shown once and never stored, since Vault does not return the secret again. An import is
limited to what Vault keeps, 6 or 8 digits, and is refused before the call, so no key is stored
that the app could not show. A failure to add the account after Vault holds the key is reported,
and does not repeat the write.

## Problems are classified once and shown where the user looks

Every failure of a Vault call goes through `VaultProblem.From` in the library, which turns a
`VaultException`, a port in use or an app error that states its own problem
(`IVaultProblemSource`) into a title, a detail and a suggestion. The raw system texts name neither
the cause nor the next step, and one mapping keeps every surface saying the same thing.

A `VaultSession` records the problem of its last call: a failed state holds it, and a call that
works returns the state to signed in, so a token vault whose server goes down shows it. The
session reports a vault that worked and then failed once, until it works again; the store retries
once a period, and a notification for each retry would be noise.

The user meets a problem where they look: the warning sign on the tray icon with the problem in
its tooltip, a menu line that opens the vault, the vault's page with the cause and the time of the
attempt, the account in the list and in its window, and the notification. Test Connection runs the
steps of a connection one by one on the settings as typed, without a session or a saved setting,
so a vault can be checked before it is saved and the failing step is named.

The warning icon is the app icon with the system's warning icon drawn over its lower right part,
written as a one-image `.ico` in memory, so the `Icon` owns its data and no icon handle has to be
destroyed by hand.

## The notification is a balloon of the NotifyIcon

`NotifyIcon.ShowBalloonTip` shows as a notification on Windows 10 and 11 and raises
`BalloonTipClicked`, which opens Settings on the vault. The notifications of the Windows App SDK
or of WinRT would need a versioned Windows target framework and an activator registration, for a
message that a balloon carries. The title is kept within the 63 characters of `szInfoTitle` and
the text within 200.

## Problems are logged to a file of the user

Each new problem of a vault is appended to
`%LOCALAPPDATA%\pl.waw.koszewscy\WindowsAuthenticator\vault.log`, one line with the time, the
vault, the title and the detail, none of which holds a secret. The Event Log needs a source that
an administrator registers, which an app copied to a folder does not have. A log that cannot be
written is skipped, since the problem is shown in the app all the same.

## The icon is an .ico file drawn by a Swift script

The icon is `src/WindowsAuthenticator/Resources/AppIcon.ico`, written by
`tools/make-windows-icon.swift` of Mac Authenticator's repository from the shapes of its icon
layers: a countdown ring, a
shield and a keyhole on the same 1024-unit canvas. Windows does not mask or light an icon as macOS
does, so the script draws the rounded square and the blue gradient itself, and the ring is drawn
thicker than on macOS so that it shows at 16 pixels. Each size is drawn from the shapes rather
than scaled from a larger image, so the small sizes stay sharp.

The script runs on macOS with the Swift toolchain and CoreGraphics; neither macOS nor .NET on
macOS has an SVG rasteriser or `System.Drawing`, and Swift on Windows has no CoreGraphics. It
lives beside the Swift sources and icon layers it is drawn from, in Mac Authenticator's
repository, and takes the path of the `.ico` as an argument, so the `.ico` is written into this
repository and never into that one. It writes the `.ico` itself: the sizes Windows asks for up to
64 pixels as 32-bit DIBs with an AND mask, and 256 pixels as PNG, which Windows reads in icons
since Vista. The `.ico` is kept in this repository, so the app builds on any OS without the
script; the script is run again only when the icon changes.

The project uses the `.ico` as `ApplicationIcon`, which puts it in the executable for Explorer
and the Start menu, and embeds it as a resource from which the notification area icon and the Add
Account dialog load the image closest to the size Windows asks for.
