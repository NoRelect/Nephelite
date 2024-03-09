namespace Nephelite.Controllers;

[ApiController]
[Route("/jwks")]
public class JwksController : ControllerBase
{
    private readonly KeyService _keyService;
    private readonly ILogger<DiscoveryController> _logger;

    public JwksController(KeyService keyService, ILogger<DiscoveryController> logger)
    {
        _keyService = keyService;
        _logger = logger;
    }

    [HttpGet]
    public JsonWebKeySet Get()
    {
        return _keyService.GetPublicJsonWebKeySet();
    }
}