using System.Globalization;
using System.Text.Json.Nodes;

namespace Vault;

/// <summary>What the setup of a KV engine for secrets is asked to do.</summary>
/// <param name="EngineExists">The engine is enabled already, so only the policies are written.</param>
public sealed record KvSetupOptions(KvVersion Version, string Mount, string Description, string CreatorPolicy,
                                    string UserPolicy, bool EngineExists = false)
{
    /// <summary>The engine of the version at its usual mount, <c>secret</c> for KV v2 and <c>kv</c> for KV v1.</summary>
    public static KvSetupOptions Default(KvVersion version) => version == KvVersion.V2
        ? new(version, "secret", "KV v2 secrets engine", "kv_creator", "kv_user")
        : new(version, "kv", "KV v1 secrets engine", "kv1_creator", "kv1_user");
}

/// <summary>
/// What the setup of a vault is asked to do: the TOTP engine and its policies, a KV v2 engine and a KV v1 engine,
/// each with its policies, any of them or all.
/// </summary>
/// <param name="OverwritePolicies">Replace policies of these names that exist; otherwise the setup stops at one.</param>
/// <param name="EngineExists">The TOTP engine is enabled already, so only its policies are written.</param>
/// <param name="Totp">Set up the TOTP engine.</param>
/// <param name="Kv">The KV v2 engine to set up, or null for none.</param>
/// <param name="Kv1">The KV v1 engine to set up, or null for none.</param>
public sealed record VaultSetupOptions(string Mount = "totp", string Description = "TOTP secrets engine",
                                       string CreatorPolicy = "totp_creator", string UserPolicy = "totp_user",
                                       bool OverwritePolicies = false, bool EngineExists = false, bool Totp = true,
                                       KvSetupOptions? Kv = null, KvSetupOptions? Kv1 = null);

/// <summary>
/// Prepares a vault for the app: enables the TOTP secrets engine and writes the policies that let users create
/// keys and read codes, and enables KV secrets engines and writes the policies that let users write and read
/// secrets. It assigns no policy to anyone.
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

    /// <summary>The policy that lets a user list, create, update and read the secrets of a KV engine.</summary>
    public static string KvCreatorPolicy(string mount, KvVersion version = KvVersion.V2)
    {
        var path = Trimmed(mount);
        var text = version == KvVersion.V1
            ? $$"""
                path "{{path}}/*" {
                  capabilities = ["list", "create", "update", "read"]
                }

                """
            : $$"""
                path "{{path}}/metadata" {
                  capabilities = ["list"]
                }

                path "{{path}}/data/*" {
                  capabilities = ["create", "update", "patch", "read"]
                }

                """;
        return text.ReplaceLineEndings("\n");
    }

    /// <summary>The policy that lets a user list and read the secrets of a KV engine.</summary>
    public static string KvUserPolicy(string mount, KvVersion version = KvVersion.V2)
    {
        var path = Trimmed(mount);
        var text = version == KvVersion.V1
            ? $$"""
                path "{{path}}/*" {
                  capabilities = ["list", "read"]
                }

                """
            : $$"""
                path "{{path}}/metadata" {
                  capabilities = ["list"]
                }

                path "{{path}}/data/*" {
                  capabilities = ["read"]
                }

                """;
        return text.ReplaceLineEndings("\n");
    }

    /// <summary>Why the options cannot be used, or null.</summary>
    public static VaultProblem? Problem(VaultSetupOptions options)
    {
        static VaultProblem Invalid(string detail) =>
            new(VaultProblemKind.Other, "A setup setting is not valid", detail, "Correct it and run the setup again.");

        static bool IsName(string value) =>
            value.Length > 0 && !value.Any(char.IsWhiteSpace) && value.IndexOfAny(['?', '#', '"']) < 0;

        if (!options.Totp && options.Kv is null && options.Kv1 is null)
        {
            return Invalid("Nothing is chosen to set up.");
        }
        var mounts = new List<string>();
        var policies = new List<string>();
        if (options.Totp)
        {
            mounts.Add(Trimmed(options.Mount));
            policies.AddRange([options.CreatorPolicy, options.UserPolicy]);
        }
        foreach (var kv in new[] { options.Kv, options.Kv1 }.OfType<KvSetupOptions>())
        {
            mounts.Add(Trimmed(kv.Mount));
            policies.AddRange([kv.CreatorPolicy, kv.UserPolicy]);
        }
        if (!mounts.All(IsName))
        {
            return Invalid("A mount is empty or holds spaces or other characters a path cannot hold.");
        }
        if (!policies.All(IsName))
        {
            return Invalid("A policy name is empty or holds spaces or other characters a name cannot hold.");
        }
        if (mounts.Distinct().Count() != mounts.Count)
        {
            return Invalid("The engines need different mounts.");
        }
        if (policies.Distinct().Count() != policies.Count)
        {
            return Invalid("The policies need different names.");
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
        // The parts in order: the TOTP engine, then KV v2, then KV v1, each an engine and its two policies.
        var parts = new List<(string Step, string Label, string Mount, JsonObject Body, bool Exists,
                              (string Step, string Name, string Text)[] Policies)>();
        if (options.Totp)
        {
            var mount = Trimmed(options.Mount);
            parts.Add(("Engine", "TOTP", mount, new JsonObject { ["type"] = "totp", ["description"] = options.Description },
                       options.EngineExists,
                       [("Creator policy", options.CreatorPolicy, CreatorPolicy(mount)),
                        ("User policy", options.UserPolicy, UserPolicy(mount))]));
        }
        foreach (var kv in new[] { options.Kv, options.Kv1 }.OfType<KvSetupOptions>())
        {
            var mount = Trimmed(kv.Mount);
            var label = $"KV v{(int)kv.Version}";
            parts.Add(($"{label} engine", label, mount,
                       new JsonObject
                       {
                           ["type"] = "kv",
                           ["description"] = kv.Description,
                           ["options"] = new JsonObject { ["version"] = ((int)kv.Version).ToString(CultureInfo.InvariantCulture) },
                       },
                       kv.EngineExists,
                       [($"{label} creator policy", kv.CreatorPolicy, KvCreatorPolicy(mount, kv.Version)),
                        ($"{label} user policy", kv.UserPolicy, KvUserPolicy(mount, kv.Version))]));
        }

        var checks = new List<VaultCheck>();
        foreach (var part in parts)
        {
            // Enable the engine
            if (part.Exists)
            {
                checks.Add(new VaultCheck(part.Step, VaultCheckOutcome.Skipped,
                                          $"The {part.Label} engine is taken as enabled at {part.Mount}.", null));
            }
            else
            {
                try
                {
                    await client.SendAsync(HttpMethod.Post, $"sys/mounts/{part.Mount}", json: part.Body).ConfigureAwait(false);
                    checks.Add(new VaultCheck(part.Step, VaultCheckOutcome.Passed,
                                              $"The {part.Label} engine is enabled at {part.Mount}.", null));
                }
                catch (VaultException error)
                {
                    checks.Add(new VaultCheck(part.Step, VaultCheckOutcome.Failed, "The engine was not enabled.",
                                              VaultProblem.From(error)));
                    return checks;
                }
            }

            foreach (var (step, name, text) in part.Policies)
            {
                var check = await WritePolicyAsync(step, name, text, client, options.OverwritePolicies).ConfigureAwait(false);
                checks.Add(check);
                if (check.Outcome == VaultCheckOutcome.Failed)
                {
                    return checks;
                }
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
