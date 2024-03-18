namespace Nephelite.Controllers;

[ApiController]
[Route("/keys")]
public class KeysController : ControllerBase
{
    private readonly KeyService _keyService;

    public KeysController(KeyService keyService)
    {
        _keyService = keyService;
    }

    [HttpGet]
    public IActionResult Get()
    {
        return new JsonResult(_keyService.GetPublicJsonWebKeySet());
    }
}