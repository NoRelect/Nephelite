namespace Nephelite.Controllers;

[ApiController]
[Route("/user_info")]
public class UserInfoController : ControllerBase
{
    private readonly KeyService _keyService;
    private readonly ILogger<UserInfoController> _logger;

    public UserInfoController(
        KeyService keyService,
        ILogger<UserInfoController> logger)
    {
        _keyService = keyService;
        _logger = logger;
    }

    [HttpPost]
    [HttpGet]
    public async Task<IActionResult> UserInfo()
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

        var jwtHandler = new JsonWebTokenHandler();
        var validationResult = await jwtHandler.ValidateTokenAsync(accessToken, new TokenValidationParameters
        {
            ValidIssuer = "https://localhost:7096",
            ValidAudience = "https://localhost:7096",
            IssuerSigningKey = _keyService.GetSigningCredentials().Key,
            TokenDecryptionKey = _keyService.GetAccessTokenEncryptingCredentials().Key,
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