# Architectural Decision Records

## The app is Windows Forms on .NET 10 with a NotifyIcon

The app targets `net10.0-windows10.0.22000.0` with Windows Forms. Of the .NET desktop stacks only
Windows Forms has a notification area icon, `NotifyIcon`, with a `ContextMenuStrip` whose items take
submenus and ticks; WPF and WinUI 3 have none and would need a third-party package or a second
UI framework. The app is an `ApplicationContext` with no main form, so it has no taskbar button.
A named mutex in the `Local\` namespace keeps one instance per sign-in session, since nothing
else stops a second tray icon from appearing.

The project sets `EnableWindowsTargeting`, so the .NET SDK on macOS and Linux downloads the
Windows Desktop targeting pack and the Windows SDK projections, and builds the app; it cannot run
there. The target framework names Windows 11, build 22000, since the Windows Hello prompt of a
desktop app, `UserConsentVerifierInterop`, is a WinRT interop class of the projections and needs
that build; the app uses no other WinRT API.

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

Each OTP account is one `CRED_TYPE_GENERIC` credential persisted with `CRED_PERSIST_LOCAL_MACHINE`,
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

While the call runs the dialog stays open, Cancel reads Cancel Request and cancels the call, and a
line with a marquee progress bar says what is done: the user keeps what was typed, an error appears
where the user is looking, and a dialog that vanished does not look like a fault. The question
before an overwrite is asked in the same dialog, by renaming its accept button, since a second modal
dialog would nest inside the one that waits. The keys and secrets offered are listed after the
dialog opens, and a grey line under the box says when they are listed or why they are not, since a
Windows Forms combo box has no placeholder text.

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

The Vault client, the rules of the OIDC sign-in window, the connection test, Vault Setup and the
problem texts are the library `Vault`, which targets plain `net10.0` and uses no Windows API, so
its tests run on any OS. Requests go through `HttpClient` with `SocketsHttpHandler`, so the system
trust store applies, and plain HTTP works for any address, which is the user's choice for that
vault. There is one client per scheme, host and port, whose certificate validation callback
accepts what the system accepts and keeps the policy errors and chain status of a certificate it
refuses: an `HttpRequestException` of `SecureConnectionError` does not tell an untrusted root from
an expired certificate or a wrong name, and the callback's flags do, without reading localised
exception texts.

A request that gets no HTTP answer becomes a `VaultException` of the kind `Transport`, with the
host and the original exception, and `VaultProblem.From` reads its `HttpRequestError`, its inner
`SocketException` and the certificate errors. Vault's JSON is read with `System.Text.Json` in
snake case into types whose `required` members make a missing field a `JsonException`, which is
reported as an answer that is not from a Vault.

`Vault.Tests` start `vault server -dev`, which keeps its storage in memory, once for the test
assembly in `[AssemblyInitialize]`, and configure it through its HTTP API with a plain
`HttpClient`, apart from the client under test. The `vault` binary is a requirement of the tests,
and a missing one fails them. The exchange of the code with an identity provider needs the sign-in
window and is checked by hand.

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

## The OIDC token is kept in Credential Manager and the sign-in is explicit

The identity provider signs the user in, so the app stores no credential for OIDC. It keeps the
resulting Vault token in Credential Manager, as the generic credential
`pl.waw.koszewscy.WindowsAuthenticator.vault.token:<id>` with the token's JSON as its blob, so an
OIDC vault stays signed in after a start of the app until its token ends, as a browser keeps a
session. The token has the same protection as the other credentials. It is taken up when the
session is made, written whenever a sign-in or a renewal gives a new one, and all of this goes
through one method of the session, so no path can forget the stored copy. A Credential Manager
that refuses is written to the log and the token still works in memory, since losing the kept copy
costs only a sign-in after the next start. The target prefix is of its own, so a profile's
credential is never taken for a token.

Nothing drops the token but the user: Sign Out and the removal of the vault delete it. An error
never does, and neither does a change of the vault's settings nor quitting the app. A change of the
address or the namespace of a vault that holds a token asks the user whether to keep the token,
delete it, or cancel the change, since only the user knows whether the new address is the same
vault moved or another one; the app does not decide it. Vault answers a policy that lacks a path
and a token it does not accept with the same 403, so a refusal says nothing about the token, and
dropping it would sign the user out of every account of the vault, and delete a token that is good,
for one call a policy refuses. A refusal is reported as the problem it is; a password or AppRole
vault logs in once more and repeats the call, since a new login costs the user nothing. A token
that has ended is kept in Credential Manager and in memory, and not used, until a sign-in replaces
it or Sign Out deletes it, so that Sign Out can always be chosen. The tokens of the other methods
are in memory alone, and a change of the vault drops them, since the credential may have changed.

Test Connection of a signed-in OIDC vault checks that token and lists the keys with it, at the
address and namespace as typed: the user who typed them chose the server, as the question on
saving them does.

The sign-in window is opened from Sign In only, never because a code was needed, so a
window opening in the background cannot start a login nobody expects. The other methods sign in
by themselves, since they need no user.

The redirect URI is `http://localhost:<port>/oidc/callback`, 8250 by default, which the role's
`allowed_redirect_uris` must hold, as for `vault login -method=oidc`. The state of the
authorisation URL is compared with the state of the redirect before the code is passed to Vault.

## OIDC signs in in an embedded WebView2 the app controls

The identity provider's pages open in a window of the app, a WebView2 control, and not in the
user's browser: a login page in another app, with no visible tie to the Authenticator, confuses
the user, and a browser that is sent to `http://localhost` needs a listener that browsers' own
connections in advance can hold up. The app takes the redirect itself: `NavigationStarting`
cancels the navigation to the redirect URI and reads the state and the code from its address, so
nothing listens on a port, nothing loads from localhost, and two OIDC vaults can use one redirect
port, which only builds the URI.

The decision is the library type `OidcSignInPolicy`, so it is tested without WebView2: the
redirect ends the sign-in, a page over HTTPS loads, and plain HTTP, `data:`, `file:`,
`javascript:` and custom schemes are refused with the reason shown in the window. The navigations
of frames, `FrameNavigationStarting`, are decided the same way; WebView2 cannot cancel a frame's
navigation to `about:srcdoc`, which the policy refuses but the frame loads. A page that opens a
window loads in the same view. The header names the host of the page at all times, which is the
user's only check of where a password goes. Certificate trust is the Windows store's; a
certificate it refuses cancels the load instead of showing WebView2's warning page, and the
error line says what is wrong, as it does for any other failed load.

The provider's cookies live in the app's own WebView2 user data folder under
`%LOCALAPPDATA%\pl.waw.koszewscy\WindowsAuthenticator`, apart from Edge's profile, so a provider's
session survives and a sign-in after a start is often one click; the cost is that the session is
kept on disk in the user's profile. The WebView2 Runtime is part of Windows 11; where it is
missing, the sign-in fails with a problem that says so, and the other methods are unaffected.

The `Microsoft.Web.WebView2` package references its Windows Forms, WPF and core assemblies in
every .NET project and has no setting to leave one out. The WPF assembly needs the WPF
`WindowsBase`, which a Windows Forms app does not have, so the build reports a version conflict
(MSB3277) for an assembly the app never loads. A target in the app's project removes that
reference before references are resolved, which keeps the build free of warnings and the WPF
assembly out of the published folder.

An embedded view has costs that the choice accepts: RFC 8252 recommends an external user agent
for native apps, and Microsoft's WebView2 documentation advises against showing OAuth login
pages in WebView2 and reading the redirect; the view has no Edge session and no Windows single
sign-on, some providers refuse embedded views, and the app can in principle see what is typed in
it. A provider for which this matters needs the browser.

## Vault Setup writes policies for each engine, replaces nothing unasked, and assigns nothing

Setup enables the TOTP engine and writes `totp_creator` and `totp_user`, and, when asked, enables a
KV v2 engine and writes `kv_creator` and `kv_user`, and a KV v1 engine with `kv1_creator` and
`kv1_user`, with the identity the vault's page describes, and stops at the first call that fails:
Vault's own answer, such as a path already in use or a refused write, says what is wrong, and a
half-done setup that went on would hide it. The identity is the page as typed, like Test
Connection, so an administrator's token need not be saved as the vault's credential. The sign-in of
the page's method is `VaultClient.SignInAsync`, which Test Connection and the setup share.

The TOTP creator policy holds `read` as well as `create` and `update`, because the app reads a key
to check that the name is free and to make the account. The user policy holds `read` on keys and
`list`, beside `read` on codes: reading a key returns its issuer, account name, algorithm, digits
and period but never the secret, and adding an account from a vault needs them. Neither holds
`delete` or `sudo`. A user who adds accounts and shows codes needs both policies.

The KV setup is for either version, each its own part with its own mount and policy names, and the
engine is mounted with the option `version` stated, since the default of an engine is Vault's to
change. A version 2 policy has to name the `data/` and `metadata/` paths; a version 1 policy names
the mount's paths alone, `<mount>/*` with `list` and the rest, and has no `patch`, which version 1
has no call for. The version 2 creator policy holds `create`, `update`, `patch` and `read` on
`<mount>/data/*`, since writing a field of a secret that exists is a patch and of one that does
not, a create, and `list` on `<mount>/metadata`; the user policy holds `read` and `list`. Neither
holds `delete`, `destroy` or `sudo`, so a secret cannot be deleted through them. The parts are
chosen separately, may not share a mount or a policy name, and run in the order TOTP, KV v2, KV
v1. The engine bodies and secret fields are sent as JSON nodes, not through the client's snake-case
naming, since their names are Vault's and the user's.

A policy of the same name is not replaced unless the dialog is told to, since a write replaces
the whole policy of a vault that may use it for more than this. Policies are assigned by the
vault's administrator, not by the setup, so the setup grants nobody access.

## A secret account is a kind of account, in the same list

An account is an OTP account or a secret account (`AccountKind`, OTP by default). A secret account
has no algorithm, digits or period that anything reads, but it shares the id, the name, the
unique-name rule, the menu order and the removal of the other accounts, so the menu, the Accounts
tab and the stored order need no second list. Everything that computes or shows a code works on
OTP accounts alone: a secret account is not a shown account, so the store never reads its secret for
a code window, and a secret is never drawn on the screen unasked. It is copied, revealed in the
Settings window, or shown in a window of its own that the user clicks to unmask (see the entry on
the secret window).

## A secret account in Credential Manager has a target prefix of its own

The credentials of OTP accounts are matched by the filter `pl.waw.koszewscy.WindowsAuthenticator:*`,
and one whose parameters attribute is missing is dropped. A secret kept under the same prefix would
be listed by a build that knows no secret accounts the moment it carried a parameters attribute,
and shown as codes computed from a password. The prefix
`pl.waw.koszewscy.WindowsAuthenticator.secret:`, which that filter does not match, keeps them apart.
The blob is the secret as UTF-8, at most `CRED_MAX_CREDENTIAL_BLOB_SIZE`, 2560 bytes, and a longer
one is refused when it is added.

## A secret is shown or copied after Windows Hello, when its setting asks for it

Reveal and Copy Secret run `UserConsentVerifierInterop.RequestVerificationForWindowAsync`, the
desktop form of `UserConsentVerifier`, which takes a face, a fingerprint or the Windows Hello PIN,
so a person at an unlocked computer cannot read a secret that the app holds in Credential Manager
or fetches from Vault. It needs Windows build 22000 and the target framework
`net10.0-windows10.0.22000.0`, which makes Windows 11 the app's requirement. The call needs a
shown and active window of the app as the owner of the prompt: the Settings window or the secret
window. Copy Secret in the tray menu, which has no window, copies at once when no prompt is needed,
and otherwise in the secret window, where Mac Authenticator copies from the menu; an invisible
window of the app's own did not work as an owner, since the copy failed after the prompt, and the
secret window gives the prompt an owner the user sees. Without
Windows Hello set up, or with it disabled by policy, the secret is refused with a message that says
so, and is not shown without asking: the setting is the user's statement that the secret needs a
check, and a fallback without one would void it.

Whether a secret asks is the account's own setting, since a password that guards little is a
nuisance to verify for on every copy and a key that guards much is not, and so is the number of
seconds after a verification during which it does not ask again, 0 asking every time. The time of
the last verification is one for the app, not one for each secret, since a verification proves the
user is there, and each secret decides how long that proof is good for. It is forgotten when the
computer resumes (`SystemEvents.PowerModeChanged` with `PowerModes.Resume`) and on every
`SystemEvents.SessionSwitch`, which Windows raises for a lock and an unlock of the screen, a sign-in
and sign-out and a remote or console connection, so a lock forgets it, as macOS, which documents no
lock notification, cannot. Both are static events, attached by the store and detached when the app
is disposed, as their documentation asks. A cancelled prompt does nothing and shows no error. A
revealed secret is hidden when the Settings window loses the keyboard or is hidden, since the window
is kept and its page would show the secret again, and the clipboard copy of a secret is emptied when
the app quits as well as after 30 seconds.

The three settings of a secret, whether it asks, the seconds it stays verified and the seconds it
stays shown, are one value, `SecretSettings`, stored as one text,
`authenticate=1&seconds=60&hide=30`, in the attribute `Koszewscy_Authenticate` of a secret's
credential, and as three DWORD values of the registry key of a Vault secret, `Authenticate`,
`AuthenticateSeconds` and `HideSeconds`. A missing key or value takes its default, and the values
`1` and `0` that earlier builds wrote in the attribute are read as `authenticate=1` and
`authenticate=0`, so the earlier forms still read.

## A secret window masks the secret and a countdown hides it again

A secret account has a window over the others like a code window, for a secret that is read many
times in a sitting. The secret is masked until the user clicks, since a window over other apps would
otherwise show it to anyone looking; the click reads it, after the verification the secret's
settings ask for, and a countdown masks it again after the secret's own number of seconds, or never
for 0, which is for development and lab use where hiding is a nuisance. A click on the shown secret
masks it at once. The secret is held by the window alone, not by the store, while it is shown, and
masking it or closing the window drops it. Reveal in the Settings window follows the same hide
time. The window keeps a shown secret when it loses the keyboard, as on macOS; only the Settings
window, which is kept hidden, hides it then.

A shown secret stays on one line, since a secret that wraps is hard to read and compare: the font
shrinks to fit the width, down to 12 points, and the window cannot be made narrower than that needs;
the width it opens with is the secret's on one line, up to 520 pixels at 96 DPI, and the user's own
resizing is then left alone until the window is closed. Only showing a secret fits the window to it;
masking it leaves the window as it is. A secret of more than 64 characters is not shown in the
window, since even the smallest font would not keep it on one line in a window of a sensible width,
and a secret that long is a key or a token that is copied, not read; the window offers Copy for it,
and discards the text it read. Reveal in the Settings window has no such limit.

## A Vault secret is a reference to one field, and the KV version is the user's choice

The reference is the KV version, the mount, the secret's name and the field: a secret is a single
level of fields, and the account is one of them. The user names the KV version, since the call
that tells it, `sys/internal/ui/mounts/<mount>`, has no stability guarantee in Vault's
documentation, and a wrong guess reads or writes the wrong paths. The registry key of a Vault
account gains a kind and the four parts of the reference, which keys written before secret
accounts lack, so they stay OTP accounts. A key of the secret kind that lacks a part of the
reference is listed with a problem, and is never read from Credential Manager by mistake. Each
record is a key of its own, so a record that cannot be read is never saved over by a change of
the others.

Writing sets one field and keeps the rest of the secret. KV v2 patches the secret
(`application/merge-patch+json`) and, when it does not exist, creates it with `cas` 0, so a
concurrent creation is not overwritten. KV v1 has no merge or compare-and-set, so the secret is
read, the field set and the secret written back from the JSON the vault returned, which keeps
fields of other types; the secret is read again, and the write is repeated up to three times if the
field is gone, which another writer's replacement of the secret causes. It does not catch a writer
whose write lands between the read and the write and drops no field of ours, which no check can.

The checks that need no write are made first: the account name is free, and the field is told to
hold a value or not, which the user is asked about, so that a refusal does not leave a secret
changed in Vault and no account for it. Generate in Vault and Import to Vault check the name before
they change the vault for the same reason. A mount and a secret's name are names separated by
single slashes, each escaped for the URL, with no empty name and no name of dots, which would reach
another path.

## A call to a vault is tracked in the session, shown in three places, and cancellable

Every call to a vault passes through `VaultSession.AuthorizedAsync`, which records it with a label
that says what it does, and runs it with a cancellation token of its own. The tray icon, the status
bar of the Settings window and the Accounts list read that record, so no dialog keeps a spinner of
its own, and a call started from anywhere shows everywhere. A call is shown 300 ms after it starts,
since a quick call that flashes a badge looks like a fault, and the background fetch of codes is
never shown, since it runs every period and a code window has its dot. A cancelled call throws
`OperationCanceledException`, sets no state and reports no problem; the callers say nothing for it.
The cancellation token is a parameter of every call of the library, the .NET convention, and is
passed to `HttpClient`, whose timeout of 30 seconds is kept: the wait and a Cancel button are shown
instead of a shorter timeout, which would fail slow but working vaults. A timeout stays a transport
problem, told apart from a cancellation by the token.

## A copied secret is kept out of the clipboard history and cleared

A copied secret goes to the clipboard with the registered formats Windows documents for this,
`ExcludeClipboardContentFromMonitorProcessing`, and `CanIncludeInClipboardHistory` and
`CanUploadToCloudClipboard` as a DWORD 0, so it stays out of the clipboard history and the cloud
clipboard. The copy is made with the Win32 clipboard calls and a message-only window as the owner,
since the .NET 10 `DataObject` documents no raw data of a custom format, and a clipboard emptied
without an owner takes no data. The clipboard is emptied after 30 seconds if
`GetClipboardSequenceNumber` is still that of the copy, so a later copy of the user's is not lost.
A TOTP code expires on its own and is copied as plain text.

## About names the commit through Source Link

The .NET SDK includes Source Link, which sets `SourceRevisionId` to the commit the app is built
from and appends it to `InformationalVersion` after a `+`. About shows the version and that id cut
to seven characters, the length `git log --oneline` shows in this repository, as the build number,
so a build can be told from another of the same version. A build outside a git repository has no
id, and About shows the version alone.

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
