namespace Nephelite.CustomResources;

public abstract class CustomResource : KubernetesObject, IMetadata<V1ObjectMeta>
{
    [JsonPropertyName("metadata")]
    public V1ObjectMeta Metadata { get; set; } = default!;
}

public abstract class CustomResource<TSpec> : CustomResource
{
    [JsonPropertyName("spec")]
    public TSpec Spec { get; set; } = default!;
}

public abstract class CustomResource<TSpec, TStatus> : CustomResource<TSpec>
{
    [JsonPropertyName("status")]
    public TStatus Status { get; set; } = default!;
}

public class CustomResourceList<T> : KubernetesObject
    where T : CustomResource
{
    [JsonPropertyName("metadata")]
    public V1ListMeta Metadata { get; set; } = default!;
    
    [JsonPropertyName("items")]
    public List<T> Items { get; set; } = default!;
}