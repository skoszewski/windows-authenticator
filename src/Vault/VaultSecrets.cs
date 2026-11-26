using System.Text.Json;
using System.Text.Json.Nodes;

namespace Vault;

/// <summary>The version of a KV secrets engine.</summary>
public enum KvVersion
{
    V1 = 1,
    V2 = 2,
}

/// <summary>
/// One field of a secret of a KV engine: the version of the engine, its mount, the secret's name and the field.
/// A secret is a single level of fields.
/// </summary>
public sealed record SecretReference(KvVersion Version, string Mount, string Name, string Field)
{
    /// <summary>
    /// The reference with its mount and name trimmed of blanks and of slashes at their ends, and its field of
    /// blanks; an empty part fails as <see cref="EmptyValueException"/>, and a mount or name that is not a path of
    /// names as <see cref="InvalidValueException"/>.
    /// </summary>
    public SecretReference Validated()
    {
        static string Part(string value, string what)
        {
            var trimmed = value.Trim().Trim('/');
            if (trimmed.Length == 0)
            {
                throw new EmptyValueException(what);
            }
            return VaultPath.Problem(trimmed) is { } reason ? throw new InvalidValueException(what, reason) : trimmed;
        }

        var field = Field.Trim();
        if (field.Length == 0)
        {
            throw new EmptyValueException("The field");
        }
        return new SecretReference(Version, Part(Mount, "The mount"), Part(Name, "The secret name"), field);
    }
}

/// <summary>The calls of the KV secrets engines.</summary>
public sealed partial class VaultClient
{
    private static readonly HttpMethod PatchMethod = new("PATCH");

    /// <summary>The path of a secret's data: the KV v2 engine keeps it below <c>data/</c>.</summary>
    private static string DataPath(SecretReference reference)
    {
        var mount = VaultPath.Escaped(reference.Mount);
        var name = VaultPath.Escaped(reference.Name);
        return reference.Version == KvVersion.V2 ? $"{mount}/data/{name}" : $"{mount}/{name}";
    }

    /// <summary>
    /// The fields of the secret as Vault holds them; null when the secret does not exist. A KV v2 secret whose
    /// latest version is deleted or destroyed fails as <see cref="VaultErrorKind.SecretDeleted"/>.
    /// </summary>
    private async Task<JsonObject?> SecretFieldsAsync(SecretReference reference, CancellationToken cancellationToken)
    {
        var (data, status) = await ExchangeAsync(HttpMethod.Get, DataPath(reference), allowing: [404],
                                                 cancellationToken: cancellationToken).ConfigureAwait(false);
        JsonNode? reply;
        try
        {
            reply = data.Length == 0 ? null : JsonNode.Parse(data);
        }
        catch (JsonException)
        {
            reply = null;
            if (status != 404)
            {
                throw VaultException.BadResponse("secret");
            }
        }
        if (status == 404)
        {
            var metadata = reply?["data"]?["metadata"] as JsonObject;
            var destroyed = metadata?["destroyed"] is JsonValue flag && flag.GetValueKind() == JsonValueKind.True;
            var deleted = metadata?["deletion_time"] is JsonValue time && time.GetValueKind() == JsonValueKind.String
                          && time.GetValue<string>().Length > 0;
            if (reference.Version == KvVersion.V2 && (destroyed || deleted))
            {
                throw VaultException.SecretDeleted(reference.Name);
            }
            return null;
        }
        if (reply?["data"] is not JsonObject fields)
        {
            throw VaultException.BadResponse("secret");
        }
        return reference.Version == KvVersion.V1 ? fields : fields["data"] as JsonObject;
    }

    /// <summary>The text of the secret's field.</summary>
    public async Task<string> ReadSecretAsync(SecretReference reference, CancellationToken cancellationToken = default)
    {
        var fields = await SecretFieldsAsync(reference, cancellationToken).ConfigureAwait(false)
                     ?? throw VaultException.NoSecret(reference.Name);
        if (!fields.TryGetPropertyValue(reference.Field, out var value) || value is null)
        {
            throw VaultException.MissingField(reference.Field, reference.Name);
        }
        if (value.GetValueKind() != JsonValueKind.String)
        {
            throw VaultException.BadResponse($"the field {reference.Field} is not text");
        }
        return value.GetValue<string>();
    }

    /// <summary>Whether the secret holds the field; a secret that does not exist does not.</summary>
    public async Task<bool> SecretFieldExistsAsync(SecretReference reference, CancellationToken cancellationToken = default)
    {
        try
        {
            await ReadSecretAsync(reference, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (VaultException error) when (error.Kind is VaultErrorKind.NoSecret or VaultErrorKind.MissingField)
        {
            return false;
        }
    }

    /// <summary>
    /// Sets the field of the secret, creating the secret when it does not exist, and keeps its other fields. A KV
    /// v1 write is read back, and repeated up to three times when another writer's write dropped the field.
    /// </summary>
    public async Task WriteSecretAsync(SecretReference reference, string value, CancellationToken cancellationToken = default)
    {
        var path = DataPath(reference);
        if (reference.Version == KvVersion.V2)
        {
            try
            {
                await SendAsync(PatchMethod, path, json: new JsonObject { ["data"] = new JsonObject { [reference.Field] = value } },
                                contentType: "application/merge-patch+json", cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (VaultException error) when (error is { Kind: VaultErrorKind.Http, Status: 404 })
            {
                // The secret does not exist; cas 0 creates it only if nobody created it meanwhile.
                await SendAsync(HttpMethod.Post, path, json: new JsonObject
                {
                    ["options"] = new JsonObject { ["cas"] = 0 },
                    ["data"] = new JsonObject { [reference.Field] = value },
                }, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            return;
        }
        // KV v1 has no merge: the fields are written back as Vault returned them, with the field set.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var fields = await SecretFieldsAsync(reference, cancellationToken).ConfigureAwait(false) ?? [];
            fields[reference.Field] = value;
            await SendAsync(HttpMethod.Post, path, json: fields, cancellationToken: cancellationToken).ConfigureAwait(false);
            var written = await SecretFieldsAsync(reference, cancellationToken).ConfigureAwait(false);
            if (written?[reference.Field] is JsonValue kept && kept.GetValueKind() == JsonValueKind.String
                && kept.GetValue<string>() == value)
            {
                return;
            }
        }
        throw VaultException.WriteLost(reference.Name);
    }

    /// <summary>The names of the secrets directly below the mount; folders are left out.</summary>
    public async Task<IReadOnlyList<string>> ListSecretsAsync(string mount, KvVersion version,
                                                              CancellationToken cancellationToken = default)
    {
        var escaped = VaultPath.Escaped(mount);
        try
        {
            var data = await SendAsync(ListMethod, version == KvVersion.V2 ? $"{escaped}/metadata" : escaped,
                                       cancellationToken: cancellationToken).ConfigureAwait(false);
            return [.. Decode<DataReply<KeysData>>(data, "a list of secrets").Data.Keys.Where(name => !name.EndsWith('/'))];
        }
        catch (VaultException error) when (error is { Kind: VaultErrorKind.Http, Status: 404 })
        {
            return [];
        }
    }
}
