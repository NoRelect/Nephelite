namespace Nephelite.Services;

public class KubernetesService
{
    private const string NamespaceEnvVarName = "NEPHELITE_NAMESPACE";
    private const string CrdGroupName = "nephelite.norelect.ch";
    private const string CrdVersion = "v1";
    private const string CrdClientPlural = "clients";
    private const string CrdUserPlural = "users";
    
    private readonly Kubernetes _kubernetes;
    private readonly string _namespace;
    
    public KubernetesService(Kubernetes kubernetes)
    {
        _kubernetes = kubernetes;
        _namespace = Environment.GetEnvironmentVariable(NamespaceEnvVarName) ??
                     throw new Exception($"No {NamespaceEnvVarName} environment variable set.");
    }

    public async Task<List<V1ClientSpec>> GetClients(CancellationToken cancellationToken)
    {
        var clientList = await _kubernetes.ListNamespacedCustomObjectAsync<CustomResourceList<V1Client>>(
            CrdGroupName, 
            CrdVersion,
            _namespace,
            CrdClientPlural,
            cancellationToken: cancellationToken);
        return clientList.Items
            .Select(c => c.Spec)
            .ToList();
    }
    
    public async Task<List<V1UserSpec>> GetUsers(CancellationToken cancellationToken)
    {
        var clientList = await _kubernetes.ListNamespacedCustomObjectAsync<CustomResourceList<V1User>>(
            CrdGroupName,
            CrdVersion,
            _namespace,
            CrdUserPlural,
            cancellationToken: cancellationToken);
        return clientList.Items
            .Select(c => c.Spec)
            .ToList();
    }
}