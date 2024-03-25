namespace Nephelite.Controllers;

[ApiController]
[Route("/userinfo")]
public class UserInfoController : ControllerBase
{
    private readonly KeyService _keyService;
    private readonly NepheliteConfiguration _nepheliteConfiguration;
    private readonly ILogger<UserInfoController> _logger;

    public UserInfoController(
        KeyService keyService,
        NepheliteConfiguration nepheliteConfiguration,
        ILogger<UserInfoController> logger)
    {
        _keyService = keyService;
        _nepheliteConfiguration = nepheliteConfiguration;
        _logger = logger;
    }

    [HttpPost]
    [HttpGet]
    public async Task<IActionResult> UserInfo(CancellationToken cancellationToken)
    {
        HttpContext.Response.Headers.CacheControl = "no-store";
        HttpContext.Response.Headers.Pragma = "no-cache";

        var authorization = HttpContext.Request.Headers.Authorization.FirstOrDefault();
        if (string.IsNullOrEmpty(authorization))
        {
            HttpContext.Response.StatusCode = 401;
            HttpContext.Response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";
            _logger.LogWarning("Invalid access token used for user information endpoint");
            return new EmptyResult();
        }

        var parts = authorization.Split(" ");
        var authType = parts.FirstOrDefault();
        var accessToken = parts.LastOrDefault();
        if (string.IsNullOrEmpty(authType) || string.IsNullOrEmpty(accessToken) ||
            !authType.Equals("bearer", StringComparison.OrdinalIgnoreCase))
        {
            HttpContext.Response.StatusCode = 401;
            HttpContext.Response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";
            _logger.LogWarning("Invalid access token used for user information endpoint");
            return new EmptyResult();
        }

        var keyMaterial = await _keyService.GetKeyMaterial(cancellationToken);
        var jwtHandler = new JsonWebTokenHandler();
        var idpUrl = $"https://{_nepheliteConfiguration.Host}";
        var validationResult = await jwtHandler.ValidateTokenAsync(accessToken, new TokenValidationParameters
        {
            ValidIssuer = idpUrl,
            ValidAudience = idpUrl,
            IssuerSigningKey = keyMaterial.SigningKey.Key,
            TokenDecryptionKey = keyMaterial.AccessTokenEncryptionKey.Key,
            RequireAudience = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.Zero
        });
        
        if (!validationResult.IsValid)
        {
            HttpContext.Response.StatusCode = 401;
            HttpContext.Response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";
            _logger.LogWarning("Invalid access token used for user information endpoint");
            return new EmptyResult();
        }
        return new JsonResult(validationResult.Claims);
    }
}