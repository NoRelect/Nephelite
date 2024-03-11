namespace Nephelite.Controllers;

[ApiController]
[Route("/authorize")]
public class AuthorizationController : ControllerBase
{
    private readonly IFido2 _fido2;
    private readonly IOptionsSnapshot<PublicKeyCredentialsConfiguration> _publicKeyCredentials;
    private readonly ILogger<AuthorizationController> _logger;

    public AuthorizationController(
        IFido2 fido2,
        IOptionsSnapshot<PublicKeyCredentialsConfiguration> publicKeyCredentials,
        ILogger<AuthorizationController> logger)
    {
        _fido2 = fido2;
        _publicKeyCredentials = publicKeyCredentials;
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

        HttpContext.Session.SetString("fido2.assertionOptions", assertionOptions.ToJson());
        
        Response.Headers.ContentType = "text/html";
        var content = $"""
                               <!DOCTYPE html>
                               <html>
                                   <head>
                                   </head>
                                   <body>
                                       <script type="text/javascript">
                                           let assertionOptions = {JsonSerializer.Serialize(assertionOptions)};
                                       </script>
                                       <button onclick="createCredential()">Create credential</button>
                                       <button onclick="authenticate()">Authenticate</button>
                                       <script type="text/javascript" src="helpers.js"></script>
                                       <script type="text/javascript" src="webauthn.js"></script>
                                   </body>
                               </html>
                               """;
        await Response.Body.WriteAsync(Encoding.UTF8.GetBytes(content));
    }
    
    [HttpPost]
    public async Task<JsonResult> Authenticate(AuthenticatorAssertionRawResponse clientResponse, CancellationToken cancellationToken)
    {
        var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
        var options = AssertionOptions.FromJson(jsonOptions);
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