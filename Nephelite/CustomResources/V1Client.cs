namespace Nephelite.CustomResources;

public class V1Client : CustomResource<V1ClientSpec>
{
}

public class V1ClientSpec
{
    [JsonPropertyName("clientId")]
    public string ClientId { get; set; } = default!;

    [JsonPropertyName("clientSecret")]
    public string? ClientSecret { get; set; }

    [JsonPropertyName("redirectUris")]
    public string[] RedirectUris { get; set; } = default!;

    [JsonPropertyName("confidential")]
    public bool IsConfidentialClient { get; set; } = true;

    [JsonPropertyName("tokenLifetime")]
    public TimeSpan? TokenLifetime { get; set; } = null;
}