namespace Nephelite.Controllers;

[ApiController]
[Route("/authorize")]
public class AuthorizationController : ControllerBase
{
    private readonly IFido2 _fido2;
    private readonly IOptionsSnapshot<PublicKeyCredentialsConfiguration> _publicKeyCredentials;
    private readonly KeyService _keyService;
    private readonly ILogger<AuthorizationController> _logger;

    public AuthorizationController(
        IFido2 fido2,
        IOptionsSnapshot<PublicKeyCredentialsConfiguration> publicKeyCredentials,
        KeyService keyService,
        ILogger<AuthorizationController> logger)
    {
        _fido2 = fido2;
        _publicKeyCredentials = publicKeyCredentials;
        _keyService = keyService;
        _logger = logger;
    }
    
    [HttpGet]
    public async Task Get()
    {
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

        var state = _keyService.Encrypt(assertionOptions.ToJson());
        Response.Headers.ContentType = "text/html";
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
                                   let state = "{state}";
                                   let options = {JsonSerializer.Serialize(assertionOptions)};
                                   authenticate(state, options);
                               </script>
                           </body>
                       </html>
                       """;
        await Response.Body.WriteAsync(Encoding.UTF8.GetBytes(content));
    }
    
    [HttpPost]
    public async Task<JsonResult> Authenticate(
        [FromForm] string state,
        [FromForm] string response,
        CancellationToken cancellationToken)
    {
        var clientResponse = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(response);
        if (clientResponse == null)
            return new JsonResult(null);
        var options = AssertionOptions.FromJson(_keyService.Decrypt(state));
        var cred = _publicKeyCredentials.Value.Credentials
                .First(c => c.CredentialId.SequenceEqual(clientResponse.Id));

        var result = await _fido2.MakeAssertionAsync(
            clientResponse, options, cred.PublicKey, 0, Callback, cancellationToken: cancellationToken);

        return new JsonResult(result);

        async Task<bool> Callback(IsUserHandleOwnerOfCredentialIdParams args, CancellationToken cancellation)
        {
            return await Task.FromResult(true);
        }
    }
}