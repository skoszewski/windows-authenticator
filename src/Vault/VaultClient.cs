using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Totp;

namespace Vault;

/// <summary>The calls of the Vault HTTP API that the app makes.</summary>
public sealed class VaultClient(VaultConfiguration configuration, string? token = null)
{
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);
    private static readonly HttpMethod ListMethod = new("LIST");
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    /// <summary>The connections, one per scheme, host and port, so a refused certificate is told apart by vault.</summary>
    private static readonly ConcurrentDictionary<string, Connection> Connections = new();

    public VaultConfiguration Configuration { get; } = configuration;

    public string? Token { get; } = token;

    /// <summary>
    /// An HTTP client checking certificates against the system trust store, which keeps the errors of the
    /// last certificate it refused.
    /// </summary>
    private sealed class Connection
    {
        private volatile CertificateErrors? lastRefusal;

        public Connection()
        {
            var handler = new SocketsHttpHandler
            {
                SslOptions = { RemoteCertificateValidationCallback = Validate },
            };
            Http = new HttpClient(handler) { Timeout = RequestTimeout };
        }

        public HttpClient Http { get; }

        public CertificateErrors? LastRefusal
        {
            get => lastRefusal;
            set => lastRefusal = value;
        }

        private bool Validate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
        {
            if (errors == SslPolicyErrors.None)
            {
                return true;
            }
            var status = X509ChainStatusFlags.NoError;
            foreach (var element in chain?.ChainStatus ?? [])
            {
                status |= element.Status;
            }
            lastRefusal = new CertificateErrors(errors, status);
            return false;
        }
    }

    /// <summary>The request for <paramref name="path"/> below <c>/v1/</c>, with the token and namespace headers.</summary>
    internal HttpRequestMessage MakeRequest(HttpMethod method, string path,
                                            IReadOnlyList<KeyValuePair<string, string>>? query = null,
                                            IReadOnlyDictionary<string, string>? body = null)
    {
        if (!Uri.TryCreate(Configuration.Address.Trim(), UriKind.Absolute, out var address)
            || address.Scheme is not ("http" or "https")
            || address.Host.Length == 0)
        {
            throw VaultException.BadAddress(Configuration.Address);
        }
        var text = new StringBuilder(address.GetLeftPart(UriPartial.Authority)).Append("/v1/").Append(path);
        if (query is { Count: > 0 })
        {
            text.Append('?').AppendJoin('&', query.Select(item =>
                $"{Uri.EscapeDataString(item.Key)}={Uri.EscapeDataString(item.Value)}"));
        }
        var request = new HttpRequestMessage(method, new Uri(text.ToString()));
        if (Token is not null)
        {
            request.Headers.TryAddWithoutValidation("X-Vault-Token", Token);
        }
        if (!string.IsNullOrEmpty(Configuration.Namespace))
        {
            request.Headers.TryAddWithoutValidation("X-Vault-Namespace", Configuration.Namespace);
        }
        if (body is not null)
        {
            request.Content = new StringContent(JsonSerializer.Serialize(body, Json), Encoding.UTF8,
                                                new MediaTypeHeaderValue("application/json"));
        }
        return request;
    }

    /// <summary>
    /// Sends the request; a request that gets no HTTP answer fails as <see cref="VaultErrorKind.Transport"/>,
    /// with the errors of a refused certificate.
    /// </summary>
    private static async Task<HttpResponseMessage> TransmitAsync(HttpRequestMessage request)
    {
        var uri = request.RequestUri!;
        var connection = Connections.GetOrAdd(uri.GetLeftPart(UriPartial.Authority), _ => new Connection());
        try
        {
            var response = await connection.Http.SendAsync(request).ConfigureAwait(false);
            connection.LastRefusal = null;
            return response;
        }
        catch (HttpRequestException error)
        {
            var certificate = error.HttpRequestError == HttpRequestError.SecureConnectionError
                ? connection.LastRefusal
                : null;
            throw VaultException.Transport(uri.Host, error, certificate);
        }
        catch (TaskCanceledException error) when (error.InnerException is TimeoutException)
        {
            throw VaultException.Transport(uri.Host, error);
        }
    }

    /// <summary>
    /// Sends the request and returns the body of a successful answer; other answers are errors carrying
    /// Vault's messages.
    /// </summary>
    internal async Task<byte[]> SendAsync(HttpMethod method, string path,
                                         IReadOnlyList<KeyValuePair<string, string>>? query = null,
                                         IReadOnlyDictionary<string, string>? body = null)
    {
        using var request = MakeRequest(method, path, query, body);
        using var response = await TransmitAsync(request).ConfigureAwait(false);
        var data = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            List<string> messages;
            try
            {
                messages = JsonSerializer.Deserialize<ErrorsReply>(data, Json)?.Errors ?? [];
            }
            catch (JsonException)
            {
                messages = [];
            }
            throw VaultException.Http((int)response.StatusCode, messages);
        }
        return data;
    }

    private static T Decode<T>(byte[] data, string what)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(data, Json) ?? throw VaultException.BadResponse(what);
        }
        catch (JsonException)
        {
            throw VaultException.BadResponse(what);
        }
    }

    private sealed class ErrorsReply
    {
        public List<string>? Errors { get; init; }
    }

    private sealed class DataReply<T>
    {
        public required T Data { get; init; }
    }

    private sealed class AuthReply
    {
        public AuthBlock? Auth { get; init; }
    }

    private sealed class AuthBlock
    {
        public required string ClientToken { get; init; }
        public required int LeaseDuration { get; init; }
        public required bool Renewable { get; init; }
    }

    private sealed class AuthUrlData
    {
        public required string AuthUrl { get; init; }
    }

    private sealed class TokenData
    {
        public required int Ttl { get; init; }
        public bool? Renewable { get; init; }
    }

    private sealed class KeysData
    {
        public required List<string> Keys { get; init; }
    }

    private sealed class KeyData
    {
        public string? AccountName { get; init; }
        public string? Issuer { get; init; }
        public required string Algorithm { get; init; }
        public required int Digits { get; init; }
        public required int Period { get; init; }
    }

    private sealed class GeneratedData
    {
        public string? Barcode { get; init; }
        public required string Url { get; init; }
    }

    private sealed class CodeData
    {
        public required string Code { get; init; }
    }

    private static VaultToken TokenFrom(byte[] data, DateTimeOffset now)
    {
        var auth = Decode<AuthReply>(data, "a sign-in answer").Auth ?? throw VaultException.BadResponse("a sign-in answer");
        var lease = TimeSpan.FromSeconds(auth.LeaseDuration);
        return new VaultToken(auth.ClientToken, auth.LeaseDuration > 0 ? now + lease : null, auth.Renewable,
                              auth.LeaseDuration > 0 ? lease : null);
    }

    /// <summary>The name with each part between slashes percent-encoded, for a path.</summary>
    private static string Escaped(string name) => string.Join('/', name.Split('/').Select(Uri.EscapeDataString));

    private string AuthPath(string suffix) => $"auth/{Configuration.AuthMount.Trim('/')}/{suffix}";

    private string EnginePath(string suffix) => $"{Configuration.TotpMount.Trim('/')}/{suffix}";

    public async Task<VaultToken> LoginUserpassAsync(string username, string password)
    {
        var data = await SendAsync(HttpMethod.Post, AuthPath($"login/{Escaped(username)}"),
                                   body: new Dictionary<string, string> { ["password"] = password }).ConfigureAwait(false);
        return TokenFrom(data, DateTimeOffset.Now);
    }

    public async Task<VaultToken> LoginAppRoleAsync(string roleId, string secretId)
    {
        var data = await SendAsync(HttpMethod.Post, AuthPath("login"),
                                   body: new Dictionary<string, string> { ["role_id"] = roleId, ["secret_id"] = secretId })
            .ConfigureAwait(false);
        return TokenFrom(data, DateTimeOffset.Now);
    }

    /// <summary>The identity provider's authorisation URL for an OIDC login.</summary>
    public async Task<Uri> OidcAuthUrlAsync(string? role, string redirectUri, string clientNonce)
    {
        var body = new Dictionary<string, string> { ["redirect_uri"] = redirectUri, ["client_nonce"] = clientNonce };
        if (!string.IsNullOrEmpty(role))
        {
            body["role"] = role;
        }
        var data = await SendAsync(HttpMethod.Post, AuthPath("oidc/auth_url"), body: body).ConfigureAwait(false);
        var text = Decode<DataReply<AuthUrlData>>(data, "an authorisation URL").Data.AuthUrl;
        if (!Uri.TryCreate(text, UriKind.Absolute, out var url))
        {
            throw VaultException.BadResponse("an authorisation URL");
        }
        return url;
    }

    /// <summary>Completes an OIDC login with the values the identity provider returned to the redirect URI.</summary>
    public async Task<VaultToken> OidcCallbackAsync(string state, string nonce, string code, string clientNonce)
    {
        KeyValuePair<string, string>[] query =
        [
            new("state", state), new("nonce", nonce), new("code", code), new("client_nonce", clientNonce),
        ];
        var data = await SendAsync(HttpMethod.Get, AuthPath("oidc/callback"), query).ConfigureAwait(false);
        return TokenFrom(data, DateTimeOffset.Now);
    }

    /// <summary>The status of Vault's health check, which also answers while Vault is sealed or in standby.</summary>
    internal async Task<int> HealthStatusAsync()
    {
        using var request = MakeRequest(HttpMethod.Get, "sys/health");
        using var response = await TransmitAsync(request).ConfigureAwait(false);
        return (int)response.StatusCode;
    }

    /// <summary>The client's own token as Vault knows it, so its end is known.</summary>
    public async Task<VaultToken> LookupSelfAsync()
    {
        if (Token is null)
        {
            throw VaultException.NotSignedIn();
        }
        var now = DateTimeOffset.Now;
        var data = await SendAsync(HttpMethod.Get, "auth/token/lookup-self").ConfigureAwait(false);
        var payload = Decode<DataReply<TokenData>>(data, "a token").Data;
        var lease = TimeSpan.FromSeconds(payload.Ttl);
        return new VaultToken(Token, payload.Ttl > 0 ? now + lease : null, payload.Renewable ?? false,
                              payload.Ttl > 0 ? lease : null);
    }

    public async Task<VaultToken> RenewSelfAsync()
    {
        var now = DateTimeOffset.Now;
        var data = await SendAsync(HttpMethod.Post, "auth/token/renew-self", body: new Dictionary<string, string>())
            .ConfigureAwait(false);
        return TokenFrom(data, now);
    }

    /// <summary>The names of the TOTP engine's keys; none when the engine holds no key.</summary>
    public async Task<IReadOnlyList<string>> ListKeysAsync()
    {
        try
        {
            var data = await SendAsync(ListMethod, EnginePath("keys")).ConfigureAwait(false);
            return Decode<DataReply<KeysData>>(data, "a list of keys").Data.Keys;
        }
        catch (VaultException error) when (error is { Kind: VaultErrorKind.Http, Status: 404 })
        {
            return [];
        }
    }

    public async Task<VaultKeyInfo> ReadKeyAsync(string name)
    {
        var data = await SendAsync(HttpMethod.Get, EnginePath($"keys/{Escaped(name)}")).ConfigureAwait(false);
        var payload = Decode<DataReply<KeyData>>(data, "a key").Data;
        return new VaultKeyInfo(name, payload.AccountName ?? "", payload.Issuer ?? "", payload.Algorithm,
                                payload.Digits, payload.Period);
    }

    /// <summary>Refuses a name that a key has already.</summary>
    private async Task RequireNewKeyAsync(string name)
    {
        try
        {
            await ReadKeyAsync(name).ConfigureAwait(false);
        }
        catch (VaultException error) when (error is { Kind: VaultErrorKind.Http, Status: 400 or 404 })
        {
            return;
        }
        throw VaultException.KeyExists(name);
    }

    /// <summary>Has Vault generate a key under a new name.</summary>
    public async Task<GeneratedKey> GenerateKeyAsync(string name, string issuer, string accountName)
    {
        await RequireNewKeyAsync(name).ConfigureAwait(false);
        var body = new Dictionary<string, string>
        {
            ["generate"] = "true",
            ["issuer"] = issuer,
            ["account_name"] = accountName,
        };
        var data = await SendAsync(HttpMethod.Post, EnginePath($"keys/{Escaped(name)}"), body: body).ConfigureAwait(false);
        var payload = Decode<DataReply<GeneratedData>>(data, "a generated key").Data;
        byte[]? png = null;
        if (payload.Barcode is not null)
        {
            try
            {
                png = Convert.FromBase64String(payload.Barcode);
            }
            catch (FormatException)
            {
                png = null;
            }
        }
        return new GeneratedKey(png, payload.Url);
    }

    /// <summary>
    /// Stores an existing key under a new name, given as a base32 secret or an otpauth URI, if Vault supports its
    /// parameters: 6 or 8 digits.
    /// </summary>
    public async Task ImportKeyAsync(string name, string input)
    {
        var created = OtpAuth.Parse(name, input);
        if (created.Account.Digits is not (6 or 8))
        {
            throw VaultException.UnsupportedKey($"it has {created.Account.Digits} digits; Vault supports 6 or 8.");
        }
        await RequireNewKeyAsync(name).ConfigureAwait(false);
        var text = input.Trim();
        var body = text.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase)
            ? new Dictionary<string, string> { ["url"] = text }
            : new Dictionary<string, string> { ["key"] = created.Secret };
        await SendAsync(HttpMethod.Post, EnginePath($"keys/{Escaped(name)}"), body: body).ConfigureAwait(false);
    }

    /// <summary>The key's code for the present time.</summary>
    public async Task<string> CodeAsync(string key)
    {
        var data = await SendAsync(HttpMethod.Get, EnginePath($"code/{Escaped(key)}")).ConfigureAwait(false);
        return Decode<DataReply<CodeData>>(data, "a code").Data.Code;
    }

    /// <summary>
    /// The token of a sign-in with the configured method and credential, the token, the password or the SecretID;
    /// null for OIDC, which needs the browser. An empty setting or credential the method needs fails as
    /// <see cref="EmptyValueException"/>.
    /// </summary>
    public static async Task<VaultToken?> SignInAsync(VaultConfiguration configuration, string? credential)
    {
        static string Required(string? value, string what) =>
            string.IsNullOrEmpty(value) ? throw new EmptyValueException(what) : value;

        var client = new VaultClient(configuration);
        return configuration.AuthMethod switch
        {
            AuthMethod.Token => await new VaultClient(configuration, Required(credential, "The token"))
                .LookupSelfAsync().ConfigureAwait(false),
            AuthMethod.Userpass => await client.LoginUserpassAsync(Required(configuration.Username, "The user name"),
                                                                   Required(credential, "The password")).ConfigureAwait(false),
            AuthMethod.Approle => await client.LoginAppRoleAsync(Required(configuration.RoleId, "The RoleID"),
                                                                 Required(credential, "The SecretID")).ConfigureAwait(false),
            _ => null,
        };
    }
}

/// <summary>A setting or credential the authentication method needs and the form leaves empty.</summary>
public sealed class EmptyValueException(string what) : Exception($"{what} is empty."), IVaultProblemSource
{
    public VaultProblem Problem => new(VaultProblemKind.Credential, $"{what} is empty",
                                       $"The authentication needs {what.ToLowerInvariant()}.", "Provide it for the vault.");
}
