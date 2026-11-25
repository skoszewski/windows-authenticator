namespace Vault;

/// <summary>What the setup of a vault is asked to do.</summary>
/// <param name="OverwritePolicies">Replace policies of these names that exist; otherwise the setup stops at one.</param>
/// <param name="EngineExists">The engine is enabled already, so only the policies are written.</param>
public sealed record VaultSetupOptions(string Mount = "totp", string Description = "TOTP secrets engine",
                                       string CreatorPolicy = "totp_creator", string UserPolicy = "totp_user",
                                       bool OverwritePolicies = false, bool EngineExists = false);

/// <summary>
/// Prepares a vault for the app: enables the TOTP secrets engine and writes the policies that let users create
/// keys and read codes. It assigns no policy to anyone.
/// </summary>
public static class VaultSetup
{
    private static string Trimmed(string mount) => mount.Trim().Trim('/');

    /// <summary>The policy that lets a user list, create, import and read keys of the engine.</summary>
    public static string CreatorPolicy(string mount)
    {
        var path = Trimmed(mount);
        return $$"""
            path "{{path}}/keys" {
              capabilities = ["list"]
            }

            path "{{path}}/keys/*" {
              capabilities = ["create", "update", "read"]
            }

            """.ReplaceLineEndings("\n");
    }

    /// <summary>The policy that lets a user list and read keys, which never return their secrets, and read codes.</summary>
    public static string UserPolicy(string mount)
    {
        var path = Trimmed(mount);
        return $$"""
            path "{{path}}/keys" {
              capabilities = ["list"]
            }

            path "{{path}}/keys/*" {
              capabilities = ["read"]
            }

            path "{{path}}/code/*" {
              capabilities = ["read"]
            }

            """.ReplaceLineEndings("\n");
    }

    /// <summary>Why the options cannot be used, or null.</summary>
    public static VaultProblem? Problem(VaultSetupOptions options)
    {
        static VaultProblem Invalid(string detail) =>
            new(VaultProblemKind.Other, "A setup setting is not valid", detail, "Correct it and run the setup again.");

        static bool IsName(string value) =>
            value.Length > 0 && !value.Any(char.IsWhiteSpace) && value.IndexOfAny(['?', '#', '"']) < 0;

        if (!IsName(Trimmed(options.Mount)))
        {
            return Invalid("The mount is empty or holds spaces or other characters a path cannot hold.");
        }
        if (!IsName(options.CreatorPolicy) || !IsName(options.UserPolicy))
        {
            return Invalid("A policy name is empty or holds spaces or other characters a name cannot hold.");
        }
        if (options.CreatorPolicy == options.UserPolicy)
        {
            return Invalid("The two policies need different names.");
        }
        return null;
    }

    /// <summary>
    /// Runs the calls in order with the client's identity, which is assumed to hold the rights for them, and stops
    /// after the first that fails. Returns the steps that ran.
    /// </summary>
    public static async Task<IReadOnlyList<VaultCheck>> RunAsync(VaultClient client, VaultSetupOptions options)
    {
        if (Problem(options) is { } problem)
        {
            return [new VaultCheck("Settings", VaultCheckOutcome.Failed, "The setup was not started.", problem)];
        }
        var checks = new List<VaultCheck>();
        var mount = Trimmed(options.Mount);

        // Enable the engine
        if (options.EngineExists)
        {
            checks.Add(new VaultCheck("Engine", VaultCheckOutcome.Skipped, $"The engine is taken as enabled at {mount}.", null));
        }
        else
        {
            try
            {
                await client.SendAsync(HttpMethod.Post, $"sys/mounts/{mount}",
                                       body: new Dictionary<string, string> { ["type"] = "totp", ["description"] = options.Description })
                    .ConfigureAwait(false);
                checks.Add(new VaultCheck("Engine", VaultCheckOutcome.Passed, $"The TOTP engine is enabled at {mount}.", null));
            }
            catch (VaultException error)
            {
                checks.Add(new VaultCheck("Engine", VaultCheckOutcome.Failed, "The engine was not enabled.",
                                          VaultProblem.From(error)));
                return checks;
            }
        }

        foreach (var (step, name, text) in new[]
                 {
                     ("Creator policy", options.CreatorPolicy, CreatorPolicy(mount)),
                     ("User policy", options.UserPolicy, UserPolicy(mount)),
                 })
        {
            var check = await WritePolicyAsync(step, name, text, client, options.OverwritePolicies).ConfigureAwait(false);
            checks.Add(check);
            if (check.Outcome == VaultCheckOutcome.Failed)
            {
                break;
            }
        }
        return checks;
    }

    /// <summary>Writes one policy, first refusing a name that exists unless overwriting is allowed.</summary>
    private static async Task<VaultCheck> WritePolicyAsync(string step, string name, string text, VaultClient client,
                                                           bool overwrite)
    {
        if (!overwrite)
        {
            try
            {
                await client.SendAsync(HttpMethod.Get, $"sys/policies/acl/{name}").ConfigureAwait(false);
                return new VaultCheck(step, VaultCheckOutcome.Failed, $"A policy named {name} exists already.",
                                      new VaultProblem(VaultProblemKind.Other, "The policy exists",
                                                       $"The vault holds a policy named {name}, and writing it would replace it.",
                                                       "Allow the setup to replace existing policies, or choose another name."));
            }
            catch (VaultException error) when (error is { Kind: VaultErrorKind.Http, Status: 404 })
            {
                // The name is free.
            }
            catch (VaultException error)
            {
                return new VaultCheck(step, VaultCheckOutcome.Failed, $"The policy {name} could not be looked up.",
                                      VaultProblem.From(error));
            }
        }
        try
        {
            await client.SendAsync(HttpMethod.Put, $"sys/policies/acl/{name}",
                                   body: new Dictionary<string, string> { ["policy"] = text }).ConfigureAwait(false);
            return new VaultCheck(step, VaultCheckOutcome.Passed, $"The policy {name} is written.", null);
        }
        catch (VaultException error)
        {
            return new VaultCheck(step, VaultCheckOutcome.Failed, $"The policy {name} was not written.",
                                  VaultProblem.From(error));
        }
    }
}
