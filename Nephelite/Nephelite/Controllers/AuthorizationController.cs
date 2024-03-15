using System.Text.Encodings.Web;

namespace Nephelite.Controllers;

[ApiController]
[Route("/authorize")]
public class AuthorizationController : ControllerBase
{
    private readonly IFido2 _fido2;
    private readonly IOptionsSnapshot<PublicKeyCredentialsConfiguration> _publicKeyCredentials;
    private readonly IOptionsSnapshot<ClientConfiguration> _clients;
    private readonly KeyService _keyService;
    private readonly ILogger<AuthorizationController> _logger;

    public AuthorizationController(
        IFido2 fido2,
        IOptionsSnapshot<PublicKeyCredentialsConfiguration> publicKeyCredentials,
        IOptionsSnapshot<ClientConfiguration> clients,
        KeyService keyService,
        ILogger<AuthorizationController> logger)
    {
        _fido2 = fido2;
        _publicKeyCredentials = publicKeyCredentials;
        _clients = clients;
        _keyService = keyService;
        _logger = logger;
    }
    
    // Testing done with the following url:
    // https://localhost:7096/authorize?scope=openid&client_id=test&redirect_uri=https://localhost:5000&response_type=id_token%20token&nonce=once
    [HttpGet]
    public IActionResult PromptAuthentication([FromQuery] AuthorizationRequest request)
    {
        var client = _clients.Value.Clients.FirstOrDefault(c => c.ClientId == request.ClientId);
        if (client == null)
        {
            _logger.LogWarning("Request used an invalid client id: '{ClientId}'", request.ClientId);
            HttpContext.Response.StatusCode = 400;
            return new JsonResult(new {Error = "Invalid client id"});
        }
        
        if (string.IsNullOrEmpty(request.RedirectUri) || !request.RedirectUri.StartsWith("https://") ||
            !client.RedirectUrls.Contains(request.RedirectUri))
        {
            _logger.LogWarning("Request used an invalid redirect uri: '{RedirectUri}'", request.RedirectUri);
            HttpContext.Response.StatusCode = 400;
            return new JsonResult(new {Error = "Invalid redirect uri"});
        }

        var scopes = request.Scope?.Split(" ") ?? Array.Empty<string>();
        if (!scopes.Contains("openid"))
        {
            _logger.LogWarning("Request is missing the openid scope: '{Scope}'", request.Scope);
            return RedirectWithError(request, "invalid_scope");
        }
        
        var validResponseTypes = new [] { "code", "id_token token", "id_token" };
        if (string.IsNullOrEmpty(request.ResponseType) || !validResponseTypes.Contains(request.ResponseType))
        {
            _logger.LogWarning("Request used an invalid response type: '{ResponseType}'", request.ResponseType);
            return RedirectWithError(request, "unsupported_response_type");
        }

        switch (request.ResponseType)
        {
            case "code" when !client.IsConfidentialClient:
                _logger.LogWarning("Request tried to use invalid response type for public client: {ResponseType}",
                    request.ResponseType);
                return RedirectWithError(request, "unauthorized_client");
            case "id_token token" or "id_token" when request.Nonce == null:
                _logger.LogWarning("Request tried to use implicit flow without nonce");
                return RedirectWithError(request, "invalid_request");
        }

        if (request.Prompt == "none")
        {
            // We do not keep track of who is logged in or not, so we always return the "not logged in" state
            return RedirectWithError(request, "login_required");
        }
        
        var existingCredentials = _publicKeyCredentials.Value.Credentials
            .Select(c => new PublicKeyCredentialDescriptor
            {
                Id = c.CredentialId,
                Type = PublicKeyCredentialType.PublicKey,
            }).ToList();
        var assertionOptions = _fido2.GetAssertionOptions(
            existingCredentials,
            UserVerificationRequirement.Preferred,
            new AuthenticationExtensionsClientInputs
            {
                Extensions = true,
                UserVerificationMethod = true
            }
        );

        var session = _keyService.EncryptSession(JsonSerializer.Serialize(new SessionInformation
        {
            AuthorizationRequest = request,
            AssertionOptions = assertionOptions,
            RequestStart = DateTime.UtcNow
        }));
        var content = $"""
                       <!DOCTYPE html>
                       <html>
                           <head>
                               <title>Nephelite</title>
                               <link rel="stylesheet" href="css/style.css" />
                           </head>
                           <body>
                               <img src="img/logo.png" alt="Nephelite Logo"> 
                               <script type="text/javascript" src="js/script.js"></script>
                               <script type="text/javascript">
                                   let session = "{session}";
                                   let options = {JsonSerializer.Serialize(assertionOptions)};
                                   authenticate(session, options);
                               </script>
                           </body>
                       </html>
                       """;
        return new FileContentResult(Encoding.UTF8.GetBytes(content), "text/html");
    }
    
    [HttpPost]
    public async Task<IActionResult> Authenticate(
        [FromForm] string session,
        [FromForm] string response,
        CancellationToken cancellationToken)
    {
        var clientResponse = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(response);
        if (clientResponse == null)
        {
            HttpContext.Response.StatusCode = 400;
            return new JsonResult(new {Error = "Invalid client response"});
        }
        
        var sessionInformation = JsonSerializer.Deserialize<SessionInformation>(_keyService.DecryptSession(session));
        if (sessionInformation == null)
        {
            HttpContext.Response.StatusCode = 400;
            return new JsonResult(new {Error = "Invalid session"});
        }

        var request = sessionInformation.AuthorizationRequest;

        var elapsedTime = DateTime.UtcNow.Subtract(sessionInformation.RequestStart);
        if (elapsedTime.TotalMinutes is < 0 or > 5)
        {
            _logger.LogWarning("Received request that has expired");
            HttpContext.Response.StatusCode = 400;
            return new JsonResult(new {Error = "Request expired"});
        }
        
        var cred = _publicKeyCredentials.Value.Credentials
                .First(c => c.CredentialId.SequenceEqual(clientResponse.Id));

        try
        {
            await _fido2.MakeAssertionAsync(
                clientResponse, sessionInformation.AssertionOptions, cred.PublicKey, 0, Callback,
                cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Authentication failed: {Exception}", ex);
            return RedirectWithError(request, "access_denied");
        }
        
        // Create OpenID spec compliant response with either
        // an authorization code, an id_token or an access token or a combination
        var expiryDate = sessionInformation.RequestStart
            .Add(TimeSpan.FromMinutes(5));
        var expiresIn = (int)expiryDate.Subtract(DateTime.UtcNow).TotalSeconds;
        var jwtHandler = new JsonWebTokenHandler();
        var nonce = sessionInformation.AuthorizationRequest.Nonce;
        var accessTokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = "https://localhost:7096/",
            Audience = "https://localhost:7096/",
            IssuedAt = sessionInformation.RequestStart,
            Expires = expiryDate,
            Claims = new Dictionary<string, object?>
            {
                { "sub", "test" }
            },
            SigningCredentials = _keyService.GetSigningCredentials(),
            EncryptingCredentials = _keyService.GetEncryptingCredentials()
        };
        if(!string.IsNullOrEmpty(nonce))
            accessTokenDescriptor.Claims.Add("nonce", nonce);
        var accessToken = jwtHandler.CreateToken(accessTokenDescriptor);
        var idTokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = "https://localhost:7096/",
            Audience = sessionInformation.AuthorizationRequest.ClientId,
            IssuedAt = sessionInformation.RequestStart,
            Expires = expiryDate,
            Claims = new Dictionary<string, object?>
            {
                { "sub", "test" }
            },
            SigningCredentials = _keyService.GetSigningCredentials(),
            EncryptingCredentials = null
        };
        if (request.ResponseType == "id_token token")
            idTokenDescriptor.Claims.Add("at_hash",
                WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken))));
        if(!string.IsNullOrEmpty(nonce))
            idTokenDescriptor.Claims.Add("nonce", nonce);
        var idToken = jwtHandler.CreateToken(idTokenDescriptor);
        
        HttpContext.Response.Headers.CacheControl = "no-store";
        var uriBuilder = new UriBuilder(new Uri(request.RedirectUri!));
        switch (request.ResponseType)
        {
            case "code":
                uriBuilder.Query = $"code=TODO&state={UrlEncoder.Default.Encode(request.State)}";
                return Redirect(uriBuilder.Uri.ToString());
            case "id_token token":
                uriBuilder.Fragment = $"access_token={accessToken}&token_type=Bearer&id_token={idToken}" +
                                      $"&state={UrlEncoder.Default.Encode(request.State)}&expires_in={expiresIn}&nonce={UrlEncoder.Default.Encode(request.Nonce)}";
                return Redirect(uriBuilder.Uri.ToString());
            case "id_token":
                uriBuilder.Fragment = $"id_token={idToken}&state={UrlEncoder.Default.Encode(request.State)}&expires_in={expiresIn}";
                return Redirect(uriBuilder.Uri.ToString());
            default:
                _logger.LogWarning("Invalid response type used: {ResponseType}", request.ResponseType);
                HttpContext.Response.StatusCode = 400;
                return new JsonResult(new { Error = "Invalid response type"});
        }
        async Task<bool> Callback(IsUserHandleOwnerOfCredentialIdParams args, CancellationToken cancellation)
        {
            return await Task.FromResult(true);
        }
    }

    private RedirectResult RedirectWithError(AuthorizationRequest request, string error)
    {
        var uriBuilder = new UriBuilder(new Uri(request.RedirectUri!))
        {
            Query = $"error={error}&state={UrlEncoder.Default.Encode(request.State)}",
        };
        return Redirect(uriBuilder.Uri.ToString());
    }
}