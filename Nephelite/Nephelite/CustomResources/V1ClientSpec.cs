namespace Nephelite.CustomResources;

public class V1ClientSpec
{
    public string ClientId { get; set; } = default!;
    public string? ClientSecret { get; set; }
    public string[] RedirectUrls { get; set; } = default!;
    public bool IsConfidentialClient { get; set; } = true;
}