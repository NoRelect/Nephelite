namespace Nephelite.Services;

public class KubernetesService(Kubernetes kubernetes)
{
    private const string NamespaceEnvVarName = "NEPHELITE_NAMESPACE";
    private const string CrdGroupName = "nephelite.norelect.ch";
    private const string CrdVersion = "v1";
    private const string CrdClientPlural = "clients";
    private const string CrdUserPlural = "users";
    private const string KeySecretName = "nephelite-keys";

    private readonly string _namespace = Environment.GetEnvironmentVariable(NamespaceEnvVarName) ??
                     throw new Exception($"No {NamespaceEnvVarName} environment variable set.");

    public async Task<List<V1ClientSpec>> GetClients(CancellationToken cancellationToken)
    {
        var clientList = await kubernetes.ListNamespacedCustomObjectAsync<CustomResourceList<V1Client>>(
            CrdGroupName,
            CrdVersion,
            _namespace,
            CrdClientPlural,
            cancellationToken: cancellationToken);
        return clientList.Items
            .Select(c => c.Spec)
            .ToList();
    }

    public async Task<List<V1User>> GetUsers(CancellationToken cancellationToken)
    {
        var clientList = await kubernetes.ListNamespacedCustomObjectAsync<CustomResourceList<V1User>>(
            CrdGroupName,
            CrdVersion,
            _namespace,
            CrdUserPlural,
            cancellationToken: cancellationToken);
        return clientList.Items
            .ToList();
    }

    public async Task ReplaceUserStatus(V1User user, CancellationToken cancellationToken)
    {
        await kubernetes.ReplaceNamespacedCustomObjectStatusAsync<V1UserStatus>(
            user,
            CrdGroupName,
            CrdVersion,
            _namespace,
            CrdUserPlural,
            user.Name(),
            cancellationToken: cancellationToken);
    }

    public async Task<IDictionary<string, byte[]>?> GetSecret(CancellationToken cancellationToken)
    {
        var secret = await kubernetes.ReadNamespacedSecretAsync(
            KeySecretName,
            _namespace,
            cancellationToken: cancellationToken);
        return secret.Data;
    }

    public async Task CreateImmutableSecret(IDictionary<string, byte[]> data, CancellationToken cancellationToken)
    {
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = KeySecretName,
                NamespaceProperty = _namespace
            },
            Immutable = true,
            Type = "Opaque",
            Data = data
        };
        await kubernetes.CreateNamespacedSecretAsync(secret, _namespace, cancellationToken: cancellationToken);
    }
}