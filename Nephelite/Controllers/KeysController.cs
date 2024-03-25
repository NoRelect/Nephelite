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
    public async Task<IActionResult> Get(CancellationToken cancellationToken)
    {
        var keyMaterial = await _keyService.GetKeyMaterial(cancellationToken);
        var keys = new JsonWebKeySet();
        keys.Keys.Add(keyMaterial.SigningPublicKey);
        return new JsonResult(keys);
    }
}