namespace Nephelite.Controllers;

[ApiController]
[Route("/.well-known/openid-configuration")]
public class DiscoveryController : ControllerBase
{
    private readonly NepheliteConfiguration _nepheliteConfiguration;

    public DiscoveryController(IOptions<NepheliteConfiguration> nepheliteConfiguration)
    {
        _nepheliteConfiguration = nepheliteConfiguration.Value;
    }

    [HttpGet]
    public IActionResult Get()
    {
        return new JsonResult(new OpenIdProviderMetadata
        {
            Issuer = $"https://{_nepheliteConfiguration.Host}",
            AuthorizationEndpoint = $"https://{_nepheliteConfiguration.Host}/authorize",
            TokenEndpoint = $"https://{_nepheliteConfiguration.Host}/token",
            JwksUri = $"https://{_nepheliteConfiguration.Host}/keys",
            UserInfoEndpoint = $"https://{_nepheliteConfiguration.Host}/user_info",
            SupportedScopes = new List<string>{ "openid" },
            SupportedResponseTypes = new List<string> { "code", "id_token", "id_token token" },
            SupportedSubjectTypes = new List<string> { "public" },
            SupportedIdTokenSigningAlgorithmValues= new List<string> { "RS256" }
        });
    }
}