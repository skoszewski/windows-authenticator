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
    /// blanks; an empty part fails as <see cref="EmptyValueException"/>.
    /// </summary>
    public SecretReference Validated()
    {
        static string Part(string value, string what)
        {
            var trimmed = value.Trim().Trim('/');
            return trimmed.Length == 0 ? throw new EmptyValueException(what) : trimmed;
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
        var mount = reference.Mount.Trim('/');
        var name = Escaped(reference.Name.Trim('/'));
        return reference.Version == KvVersion.V2 ? $"{mount}/data/{name}" : $"{mount}/{name}";
    }

    /// <summary>The fields of the secret as Vault holds them; null when the secret does not exist.</summary>
    private async Task<JsonObject?> SecretFieldsAsync(SecretReference reference)
    {
        byte[] data;
        try
        {
            data = await SendAsync(HttpMethod.Get, DataPath(reference)).ConfigureAwait(false);
        }
        catch (VaultException error) when (error is { Kind: VaultErrorKind.Http, Status: 404 })
        {
            return null;
        }
        JsonNode? reply;
        try
        {
            reply = JsonNode.Parse(data);
        }
        catch (JsonException)
        {
            throw VaultException.BadResponse("secret");
        }
        if (reply?["data"] is not JsonObject fields)
        {
            throw VaultException.BadResponse("secret");
        }
        if (reference.Version == KvVersion.V1)
        {
            return fields;
        }
        // A deleted version of a KV v2 secret has no data.
        return fields["data"] as JsonObject;
    }

    /// <summary>The text of the secret's field.</summary>
    public async Task<string> ReadSecretAsync(SecretReference reference)
    {
        var fields = await SecretFieldsAsync(reference).ConfigureAwait(false) ?? throw VaultException.NoSecret(reference.Name);
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

    /// <summary>Sets the field of the secret, creating the secret when it does not exist, and keeps its other fields.</summary>
    public async Task WriteSecretAsync(SecretReference reference, string value)
    {
        var path = DataPath(reference);
        if (reference.Version == KvVersion.V2)
        {
            try
            {
                await SendAsync(PatchMethod, path, json: new JsonObject { ["data"] = new JsonObject { [reference.Field] = value } },
                                contentType: "application/merge-patch+json").ConfigureAwait(false);
            }
            catch (VaultException error) when (error is { Kind: VaultErrorKind.Http, Status: 404 })
            {
                // The secret does not exist; cas 0 creates it only if nobody created it meanwhile.
                await SendAsync(HttpMethod.Post, path, json: new JsonObject
                {
                    ["options"] = new JsonObject { ["cas"] = 0 },
                    ["data"] = new JsonObject { [reference.Field] = value },
                }).ConfigureAwait(false);
            }
            return;
        }
        // KV v1 has no merge: the fields are written back as Vault returned them, with the field set.
        var fields = await SecretFieldsAsync(reference).ConfigureAwait(false) ?? [];
        fields[reference.Field] = value;
        await SendAsync(HttpMethod.Post, path, json: fields).ConfigureAwait(false);
    }

    /// <summary>The names of the secrets directly below the mount; folders are left out.</summary>
    public async Task<IReadOnlyList<string>> ListSecretsAsync(string mount, KvVersion version)
    {
        var trimmed = mount.Trim().Trim('/');
        try
        {
            var data = await SendAsync(ListMethod, version == KvVersion.V2 ? $"{trimmed}/metadata" : trimmed)
                .ConfigureAwait(false);
            return [.. Decode<DataReply<KeysData>>(data, "a list of secrets").Data.Keys.Where(name => !name.EndsWith('/'))];
        }
        catch (VaultException error) when (error is { Kind: VaultErrorKind.Http, Status: 404 })
        {
            return [];
        }
    }
}
