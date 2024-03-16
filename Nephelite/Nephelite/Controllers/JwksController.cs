namespace Nephelite.Controllers;

[ApiController]
[Route("/jwks")]
public class JwksController : ControllerBase
{
    private readonly KeyService _keyService;

    public JwksController(KeyService keyService)
    {
        _keyService = keyService;
    }

    [HttpGet]
    public IActionResult Get()
    {
        return new JsonResult(_keyService.GetPublicJsonWebKeySet());
    }
}