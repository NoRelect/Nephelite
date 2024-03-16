namespace Nephelite.Controllers;

[ApiController]
[Route("/.well-known/openid-configuration")]
public class DiscoveryController : ControllerBase
{
    public DiscoveryController()
    {
    }

    [HttpGet]
    public IActionResult Get()
    {
        var domain = "localhost:7096";
        return new JsonResult(new OpenIdProviderMetadata
        {
            Issuer = $"https://{domain}",
            AuthorizationEndpoint = $"https://{domain}/authorize",
            TokenEndpoint = $"https://{domain}/token",
            JwksUri = $"https://{domain}/jwks",
            UserInfoEndpoint = $"https://{domain}/user_info",
            SupportedScopes = new List<string>{ "openid" },
            SupportedResponseTypes = new List<string> { "code", "id_token", "id_token token" },
            SupportedSubjectTypes = new List<string> { "public" },
            SupportedIdTokenSigningAlgorithmValues= new List<string> { "RS256" }
        });
    }
}