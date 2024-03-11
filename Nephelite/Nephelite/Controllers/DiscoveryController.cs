namespace Nephelite.Controllers;

[ApiController]
[Route("/.well-known/openid-configuration")]
public class DiscoveryController : ControllerBase
{
    private readonly KeyService _keyService;
    private readonly ILogger<DiscoveryController> _logger;

    public DiscoveryController(KeyService keyService, ILogger<DiscoveryController> logger)
    {
        _keyService = keyService;
        _logger = logger;
    }

    [HttpGet]
    public OpenIdProviderMetadata Get()
    {
        var domain = "example.com";
        return new OpenIdProviderMetadata
        {
            Issuer = $"https://{domain}",
            AuthorizationEndpoint = $"https://{domain}/authorize",
            TokenEndpoint = $"https://{domain}/token",
            JwksUri = $"https://{domain}/jwks",
            UserInfoEndpoint = $"https://{domain}/user_info",
            SupportedScopes = new List<string>{ "openid" },
            SupportedResponseTypes = new List<string> { "code", "code id_token", "id_token", "id_token token" },
            SupportedSubjectTypes = new List<string> { "public" },
            SupportedIdTokenSigningAlgorithmValues= _keyService.GetPublicJsonWebKeySet().Keys
                .Select(k => k.Alg).ToList()
        };
    }
}