using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace Vault.Tests;

/// <summary>
/// A running <c>vault server -dev</c> with in-memory storage, started once for the test assembly and prepared
/// with the engines, policies and identities the tests use.
/// </summary>
[TestClass]
public static class VaultDevServer
{
    public const int DefaultPort = 18200;

    /// <summary>The base32 secret of the keys the tests create.</summary>
    public const string Secret = "JBSWY3DPEHPK3PXP";
    public const string Password = "correct horse";

    private static readonly HttpClient Http = new();
    private static Process? process;

    public static int Port { get; private set; }
    public static string RootToken { get; private set; } = "";
    public static string Address => $"http://127.0.0.1:{Port}";
    public static string RoleId { get; private set; } = "";
    public static string SecretId { get; private set; } = "";

    /// <summary>Starts the server named by VAULT_BINARY, or vault on the PATH, and prepares it.</summary>
    [AssemblyInitialize]
    public static async Task StartAsync(TestContext context)
    {
        Port = int.TryParse(Environment.GetEnvironmentVariable("VAULT_TEST_PORT"), out var port) ? port : DefaultPort;
        RootToken = "root-" + Guid.NewGuid().ToString("D");
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("VAULT_BINARY") ?? "vault")
        {
            ArgumentList =
            {
                "server", "-dev", $"-dev-root-token-id={RootToken}", $"-dev-listen-address=127.0.0.1:{Port}",
                "-dev-no-store-token",
            },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var name in start.Environment.Keys.Where(k => k.StartsWith("VAULT_ADDR", StringComparison.Ordinal) || k == "VAULT_TOKEN").ToList())
        {
            start.Environment.Remove(name);
        }
        try
        {
            process = Process.Start(start) ?? throw new InvalidOperationException("The vault binary did not start.");
        }
        catch (System.ComponentModel.Win32Exception error)
        {
            throw new InvalidOperationException($"The vault binary could not be run: {error.Message}. Install Vault or set VAULT_BINARY.", error);
        }
        process.OutputDataReceived += (_, _) => { };
        process.ErrorDataReceived += (_, _) => { };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (true)
        {
            if (process.HasExited)
            {
                throw new InvalidOperationException($"The vault dev server exited with status {process.ExitCode}; is port {Port} free?");
            }
            if (DateTime.UtcNow > deadline)
            {
                throw new InvalidOperationException("The vault dev server was not healthy within 10 seconds.");
            }
            try
            {
                using var health = await Http.GetAsync($"{Address}/v1/sys/health");
                if ((int)health.StatusCode == 200)
                {
                    break;
                }
            }
            catch (HttpRequestException)
            {
            }
            await Task.Delay(100);
        }
        await PrepareAsync();
    }

    [AssemblyCleanup]
    public static void Stop()
    {
        if (process is { HasExited: false })
        {
            process.Kill();
            process.WaitForExit();
        }
        process?.Dispose();
    }

    /// <summary>Calls Vault's API with the root token, or the given one, without the client under test.</summary>
    public static async Task<JsonElement> AdminAsync(string method, string path, object? body = null, string? token = null)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), $"{Address}/v1/{path}");
        request.Headers.Add("X-Vault-Token", token ?? RootToken);
        if (body is not null)
        {
            request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        }
        using var response = await Http.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"{method} {path} answered {(int)response.StatusCode}: {text}");
        }
        return text.Length == 0 ? default : JsonDocument.Parse(text).RootElement.Clone();
    }

    /// <summary>A new renewable token with the policy, lasting an hour.</summary>
    public static async Task<string> TokenAsync(string policy)
    {
        var reply = await AdminAsync("POST", "auth/token/create",
                                     new { policies = new[] { policy }, ttl = "1h", renewable = true });
        return reply.GetProperty("auth").GetProperty("client_token").GetString()!;
    }

    private static string Policy(bool listing) => string.Join("\n", new[] { "totp", "team/totp" }.Select(mount =>
        $$"""
        {{(listing ? $"path \"{mount}/keys\" {{ capabilities = [\"list\"] }}" : "")}}
        path "{{mount}}/keys/*" { capabilities = ["read"] }
        path "{{mount}}/code/*" { capabilities = ["read"] }
        """));

    /// <summary>Enables the engines and methods and creates the keys, policies and identities.</summary>
    private static async Task PrepareAsync()
    {
        await AdminAsync("POST", "sys/mounts/totp", new { type = "totp" });
        await AdminAsync("POST", "sys/mounts/team/totp", new { type = "totp" });
        await AdminAsync("POST", "sys/mounts/scratch/totp", new { type = "totp" });
        await AdminAsync("POST", "totp/keys/default", new { key = Secret, issuer = "Acme", account_name = "alice@example.com" });
        await AdminAsync("POST", "totp/keys/strong", new
        {
            key = Secret, issuer = "Acme", account_name = "bob@example.com", algorithm = "SHA256", digits = 8, period = 60,
        });
        await AdminAsync("POST", "team/totp/keys/shared", new { key = Secret, account_name = "team" });

        await AdminAsync("POST", "sys/mounts/kv1", new { type = "kv", options = new { version = "1" } });
        await AdminAsync("POST", "sys/mounts/kv2", new { type = "kv", options = new { version = "2" } });
        await AdminAsync("POST", "kv1/app", new { password = "p1", other = "keep1" });
        await AdminAsync("POST", "kv1/dir/inner", new { password = "x" });
        await AdminAsync("POST", "kv2/data/app", new { data = new { password = "p2", other = "keep2" } });
        await AdminAsync("POST", "kv2/data/dir/inner", new { data = new { password = "x" } });

        await AdminAsync("PUT", "sys/policies/acl/full", new { policy = Policy(true) });
        await AdminAsync("PUT", "sys/policies/acl/nolist", new { policy = Policy(false) });

        await AdminAsync("POST", "sys/auth/userpass", new { type = "userpass" });
        await AdminAsync("POST", "auth/userpass/users/alice", new { password = Password, token_policies = new[] { "full" } });

        await AdminAsync("POST", "sys/auth/approle", new { type = "approle" });
        await AdminAsync("POST", "auth/approle/role/app", new { token_policies = new[] { "full" }, token_ttl = "1h" });
        RoleId = (await AdminAsync("GET", "auth/approle/role/app/role-id")).GetProperty("data").GetProperty("role_id").GetString()!;
        SecretId = (await AdminAsync("POST", "auth/approle/role/app/secret-id")).GetProperty("data").GetProperty("secret_id").GetString()!;
    }
}
