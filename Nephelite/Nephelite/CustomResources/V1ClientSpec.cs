namespace Nephelite.CustomResources;

public class V1ClientSpec
{
    public string ClientId { get; set; } = default!;
    public string ClientSecret { get; set; } = default!;
    public string[] RedirectUrls { get; set; } = default!;
}