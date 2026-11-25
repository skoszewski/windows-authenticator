using System.Net;
using System.Net.Sockets;

namespace Vault;

/// <summary>The outcome of one step of a connection test.</summary>
public enum VaultCheckOutcome
{
    Passed,
    Warning,
    Failed,
    Skipped,
}

/// <summary>The result of one step of a connection test.</summary>
/// <param name="Problem">Why the step failed or warns, with what to do.</param>
public sealed record VaultCheck(string Step, VaultCheckOutcome Outcome, string Message, VaultProblem? Problem);

/// <summary>
/// Tests the connection to a Vault step by step: the address, the server, the sign-in and the TOTP engine. It
/// keeps no token and touches no session.
/// </summary>
public static class VaultDiagnostics
{
    /// <summary>
    /// Runs the steps in order, stopping after a step that fails; the credential is the token, the password or
    /// the SecretID of the configured method.
    /// </summary>
    public static async Task<IReadOnlyList<VaultCheck>> RunAsync(VaultConfiguration configuration, string? credential)
    {
        var checks = new List<VaultCheck>();
        var client = new VaultClient(configuration);

        // Address
        try
        {
            using var request = client.MakeRequest(HttpMethod.Get, "sys/health");
            var uri = request.RequestUri!;
            var plain = uri.Scheme == "http";
            if (plain && !await ResolvesToLoopbackAsync(uri.Host).ConfigureAwait(false))
            {
                checks.Add(new VaultCheck("Address", VaultCheckOutcome.Warning,
                                          "The address uses plain HTTP; the credential and the codes cross the network unencrypted.",
                                          null));
            }
            else
            {
                checks.Add(new VaultCheck("Address", VaultCheckOutcome.Passed, uri.AbsoluteUri, null));
            }
        }
        catch (VaultException error)
        {
            checks.Add(new VaultCheck("Address", VaultCheckOutcome.Failed, "The address cannot be used.",
                                      VaultProblem.From(error)));
            return checks;
        }

        // Server
        try
        {
            var status = await client.HealthStatusAsync().ConfigureAwait(false);
            switch (status)
            {
                case 200:
                    checks.Add(new VaultCheck("Server", VaultCheckOutcome.Passed, "Vault is active and unsealed.", null));
                    break;
                case 429 or 472 or 473:
                    checks.Add(new VaultCheck("Server", VaultCheckOutcome.Warning, "Vault answers as a standby node.", null));
                    break;
                case 501:
                    checks.Add(new VaultCheck("Server", VaultCheckOutcome.Failed, "Vault is not initialized.",
                                              VaultProblem.From(VaultException.Http(status, []))));
                    return checks;
                case 503:
                    checks.Add(new VaultCheck("Server", VaultCheckOutcome.Failed, "Vault is sealed.",
                                              VaultProblem.From(VaultException.Http(status, []))));
                    return checks;
                default:
                    checks.Add(new VaultCheck("Server", VaultCheckOutcome.Warning,
                                              $"Vault's health check answered {status}.", null));
                    break;
            }
        }
        catch (VaultException error)
        {
            checks.Add(new VaultCheck("Server", VaultCheckOutcome.Failed, "The server could not be reached.",
                                      VaultProblem.From(error)));
            return checks;
        }

        // Sign-in
        VaultToken? token;
        try
        {
            token = await VaultClient.SignInAsync(configuration, credential).ConfigureAwait(false);
            checks.Add(token is null
                ? new VaultCheck("Sign-in", VaultCheckOutcome.Skipped, "OIDC signs in in the browser, from the vault's page.", null)
                : new VaultCheck("Sign-in", VaultCheckOutcome.Passed,
                                 $"Signed in with the {configuration.AuthMethod.Name()} method.", null));
        }
        catch (Exception error) when (error is VaultException or EmptyValueException)
        {
            checks.Add(new VaultCheck("Sign-in", VaultCheckOutcome.Failed, "The sign-in failed.", VaultProblem.From(error)));
            return checks;
        }

        // TOTP engine
        if (token is null)
        {
            checks.Add(new VaultCheck("TOTP engine", VaultCheckOutcome.Skipped, "Needs a sign-in.", null));
            return checks;
        }
        try
        {
            var keys = await new VaultClient(configuration, token.Token).ListKeysAsync().ConfigureAwait(false);
            checks.Add(keys.Count == 0
                ? new VaultCheck("TOTP engine", VaultCheckOutcome.Warning,
                                 $"The engine lists no keys; the mount {configuration.TotpMount} may be wrong.", null)
                : new VaultCheck("TOTP engine", VaultCheckOutcome.Passed, $"{keys.Count} keys are listed.", null));
        }
        catch (VaultException error) when (error.IsDenied)
        {
            checks.Add(new VaultCheck("TOTP engine", VaultCheckOutcome.Warning,
                                      "The policy does not allow listing the keys; their names can be typed.",
                                      VaultProblem.From(error)));
        }
        catch (VaultException error)
        {
            checks.Add(new VaultCheck("TOTP engine", VaultCheckOutcome.Failed, "The keys could not be listed.",
                                      VaultProblem.From(error)));
        }
        return checks;
    }

    /// <summary>Whether the host name resolves to loopback addresses alone; false when it does not resolve.</summary>
    internal static async Task<bool> ResolvesToLoopbackAsync(string host)
    {
        IPAddress[] addresses;
        if (IPAddress.TryParse(host.Trim('[', ']'), out var literal))
        {
            addresses = [literal];
        }
        else
        {
            try
            {
                addresses = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
            }
            catch (SocketException)
            {
                return false;
            }
        }
        return addresses.Length > 0 && addresses.All(IPAddress.IsLoopback);
    }
}
