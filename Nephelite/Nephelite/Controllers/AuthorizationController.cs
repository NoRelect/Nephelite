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
    // https://localhost:7096/authorize?scope=openid&client_id=test&redirect_uri=https://localhost:5000
    [HttpGet]
    public IActionResult PromptAuthentication([FromQuery] AuthorizationRequest request)
    {
        var scopes = request.Scope?.Split(" ") ?? Array.Empty<string>();
        if (!scopes.Contains("openid"))
        {
            _logger.LogWarning("Request is missing the openid scope: '{Scope}'", request.Scope);
            HttpContext.Response.StatusCode = 400;
            return new JsonResult(new {Error = "Invalid scope"});
        }
        
        var client = _clients.Value.Clients.FirstOrDefault(c => c.ClientId == request.ClientId);
        if (client == null)
        {
            // Do not redirect in case the client id is wrong since we can't validate the redirect uri.
            // Instead, show an error message directly to the user.
            _logger.LogWarning("Request used an invalid client id: '{ClientId}'", request.ClientId);
            HttpContext.Response.StatusCode = 400;
            return new JsonResult(new {Error = "Invalid client id"});
        }
        
        if (string.IsNullOrEmpty(request.RedirectUri) || !request.RedirectUri.StartsWith("https://") ||
            !client.RedirectUrls.Contains(request.RedirectUri))
        {
            // Do not redirect in case the redirect uri is wrong.
            // Instead, show an error message to the user.
            _logger.LogWarning("Request used an invalid redirect uri: '{RedirectUri}'", request.RedirectUri);
            HttpContext.Response.StatusCode = 400;
            return new JsonResult(new {Error = "Invalid redirect uri"});
        }
        
        if (request.Prompt == "none")
        {
            // We do not keep track of who is logged in or not, so we always return the "not logged in" state
            var uriBuilder = new UriBuilder(new Uri(request.RedirectUri))
            {
                Query = $"error=login_required&state={request.State}",
                Fragment = null,
            };
            return Redirect(uriBuilder.Uri.ToString());
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

        var session = _keyService.Encrypt(JsonSerializer.Serialize(new SessionInformation
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
        
        var sessionInformation = JsonSerializer.Deserialize<SessionInformation>(_keyService.Decrypt(session));
        if (sessionInformation == null)
        {
            HttpContext.Response.StatusCode = 400;
            return new JsonResult(new {Error = "Invalid session"});
        }

        var elapsedTime = DateTime.UtcNow.Subtract(sessionInformation.RequestStart);
        if (elapsedTime.TotalMinutes is < 0 or > 5)
        {
            _logger.LogWarning("Received request that has expired");
            HttpContext.Response.StatusCode = 400;
            return new JsonResult(new {Error = "Request expired"});
        }
        
        var cred = _publicKeyCredentials.Value.Credentials
                .First(c => c.CredentialId.SequenceEqual(clientResponse.Id));

        var result = await _fido2.MakeAssertionAsync(
            clientResponse, sessionInformation.AssertionOptions, cred.PublicKey, 0, Callback, cancellationToken: cancellationToken);

        // Create OpenID spec compliant response with either
        // an authorization code, an id_token or an access token or a combination
        
        return new JsonResult(result);

        async Task<bool> Callback(IsUserHandleOwnerOfCredentialIdParams args, CancellationToken cancellation)
        {
            return await Task.FromResult(true);
        }
    }
}