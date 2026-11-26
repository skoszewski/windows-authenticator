# Development

Building, testing and releasing Windows Authenticator. Using the app is described in
[Usage.md](Usage.md) and [Vault.md](Vault.md).

## Requirements

- To build: the .NET 10 SDK, on Windows, macOS or Linux. The app targets
  `net10.0-windows10.0.22000.0`, for the Windows Hello prompt of Windows 11, and builds elsewhere
  with `EnableWindowsTargeting`.
- To test: the `vault` binary on `PATH`, or named by `VAULT_BINARY`. The Vault tests start an
  in-memory `vault server -dev` on 127.0.0.1, port 18200 or `VAULT_TEST_PORT`, and stop it
  afterwards.

## Building

```sh
dotnet build -c Release           # build the libraries, the app and the tests
dotnet publish src/WindowsAuthenticator -c Release -r win-x64 --self-contained false -o dist/win-x64
dotnet publish src/WindowsAuthenticator -c Release -r win-arm64 --self-contained false -o dist/win-arm64
```

The projects are:

- `src/Totp`: the TOTP code, base32 decoding and otpauth URI reading;
- `src/Vault`: the client of the Vault HTTP API, with the TOTP and KV engines, the paths a user
  types, the rules of the OIDC sign-in window, the connection test, Vault Setup and the problems in
  words;
- `src/WindowsAuthenticator`: the Windows Forms app;
- `tests/Totp.Tests` and `tests/Vault.Tests`: the tests of the libraries.

## Testing

```sh
dotnet test                       # run the tests of the TOTP and Vault libraries
```

`dotnet test` runs the tests of the two libraries; they run on any OS. The tests in
`tests/Totp.Tests` compare the codes with the test vectors of RFC 6238 Appendix B and with codes
printed by `otp.py` of linux-cloud-router, and check the reading of secrets and otpauth URIs. The
tests in `tests/Vault.Tests` run the Vault client against a dev server they start:

- the authentication with a token, a password and an AppRole, renewing, and a revoked token;
- listing, reading, generating and importing keys, the policy that denies listing, and codes that
  agree with the ones `Totp` computes for the same secret;
- reading, writing and listing the fields of KV v1 and v2 secrets, whether a field exists, a
  deleted KV v2 secret, and a cancelled call;
- the paths a user types, which are refused when they hold an empty name, a name of dots or a
  control character, and escaped in the request;
- Test Connection, Vault Setup of the TOTP and KV engines, and the words a problem is said in;
- the rules that decide which pages of the OIDC sign-in window load and which address ends the
  sign-in.

The app itself runs on Windows alone, so its windows are checked there by hand.

## The app icon

The app icon, `src/WindowsAuthenticator/Resources/AppIcon.ico`, is part of the repository. It is
drawn by `tools/make-windows-icon.swift` of the Mac Authenticator repository, run there:

```sh
swift tools/make-windows-icon.swift <windows-authenticator>/src/WindowsAuthenticator/Resources/AppIcon.ico
```

The script needs macOS. It draws with CoreGraphics and ImageIO, which
[Swift for Windows](https://www.swift.org/install/windows/) does not include, so it does not
build on Windows.

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
when the entry is written. About shows it with the commit the app was built from, which Source
Link adds to the informational version.
